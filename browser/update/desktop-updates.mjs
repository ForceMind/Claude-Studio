import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { copyFile, lstat, mkdir, mkdtemp, open, readdir, rename, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { checkReleaseManifest, isNewerVersion } from './release-manifest.mjs';

export class ReleaseDataError extends Error {}

async function* boundedResponse(response, limit, signal) {
  if (response.status !== 200 || !response.body || response.redirected) {
    void response.body?.cancel().catch(() => {});
    throw new Error('更新源响应不可用。');
  }
  const reader = response.body.getReader();
  const abort = () => { void reader.cancel(signal.reason).catch(() => {}); };
  signal.addEventListener('abort', abort, { once: true });
  let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new ReleaseDataError('更新响应超过允许的大小。');
      yield value;
    }
  } finally {
    signal.removeEventListener('abort', abort);
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

async function fileDigest(file, limit) {
  const handle = await open(file, 'r');
  const stream = handle.createReadStream({ autoClose: false });
  const hash = createHash('sha256');
  let size = 0;
  try {
    for await (const bytes of stream) {
      size += bytes.length;
      if (size > limit) throw new ReleaseDataError('更新包超过签名允许的大小。');
      hash.update(bytes);
    }
    return { size, sha256: hash.digest('hex') };
  } finally {
    stream.destroy();
    await handle.close();
  }
}

async function readState(file) {
  const handle = await open(file, 'r').catch(error => {
    if (error.code !== 'ENOENT') throw error;
  });
  if (!handle) return undefined;
  try {
    if ((await handle.stat()).size > 4096) throw new Error();
    const data = JSON.parse(await handle.readFile({ encoding: 'utf8' }));
    if (!Number.isSafeInteger(data.sequence) || data.sequence < 1 ||
        typeof data.digest !== 'string' || !/^[a-f0-9]{64}$/.test(data.digest)) throw new Error();
    isNewerVersion(data.version, data.version);
    return { sequence: data.sequence, digest: data.digest, version: data.version };
  } catch {
    throw new ReleaseDataError('更新记录损坏，已暂停接受更新。');
  } finally {
    await handle.close();
  }
}

async function writeState(file, state) {
  const temporary = file + '.' + randomUUID() + '.tmp';
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(JSON.stringify(state), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, file);
  } finally {
    await rm(temporary, { force: true });
  }
}

function validate(envelope, target, previous, now) {
  try {
    return checkReleaseManifest(envelope, { ...target, previous, now });
  } catch {
    throw new ReleaseDataError('更新清单的签名、版本或发布目标无效。');
  }
}

export class DesktopUpdates {
  #target;
  #request;
  #verifyPlatform;
  #stateDirectory;
  #stateFile;
  #stagingDirectory;
  #recovery;
  #onReady;
  #candidate;
  #ready;
  #operations = Promise.resolve();
  #lifetime = new AbortController();
  #download;
  #now;

  constructor({ target, request, root, verifyPlatform, onReady = () => {}, now = Date.now }) {
    this.#target = target;
    this.#request = request;
    this.#verifyPlatform = verifyPlatform;
    this.#onReady = onReady;
    this.#now = now;
    this.#stateDirectory = path.join(root, 'update-state');
    const id = target.platform + '-' + target.arch + '-' + target.channel + (target.edition ? '-' + target.edition : '');
    this.#stateFile = path.join(this.#stateDirectory, id + '.json');
    this.#stagingDirectory = path.join(root, 'update-staging', id);
  }

  get offer() {
    return this.#candidate && this.#verifyPlatform ?
      { token: this.#candidate.asset.state.digest, version: this.#candidate.asset.version } : undefined;
  }

  get ready() {
    return this.#ready && { token: this.#ready.token, version: this.#ready.version };
  }

  async check(signal) {
    const control = AbortSignal.any([signal, this.#lifetime.signal, AbortSignal.timeout(15_000)]);
    this.#recovery ??= this.#recoverStaging();
    await this.#recovery;
    control.throwIfAborted();
    const response = await this.#request(this.#target.feed, control);
    const chunks = [];
    for await (const bytes of boundedResponse(response, 16_384, control)) chunks.push(bytes);
    const envelope = Buffer.concat(chunks).toString('utf8');
    return this.#serialize(async () => {
      control.throwIfAborted();
      const previous = await readState(this.#stateFile);
      const asset = validate(envelope, this.#target, previous, this.#now());
      control.throwIfAborted();
      if (asset.state.digest !== previous?.digest) {
        await mkdir(this.#stateDirectory, { recursive: true });
        await writeState(this.#stateFile, asset.state);
      }
      control.throwIfAborted();
      if (this.#ready?.token !== asset.state.digest) await this.#removeReady();
      this.#candidate = asset.available ? { asset, envelope } : undefined;
      return asset.available ? asset.version : undefined;
    });
  }

  async download(token) {
    if (!this.#verifyPlatform || this.#download) throw new Error('当前无法下载更新。');
    this.#download = this.#downloadCandidate(token);
    try { return await this.#download; }
    finally { this.#download = undefined; }
  }

  async #downloadCandidate(token) {
    if (this.#ready?.token === token) {
      await this.verifyReady(token);
      return this.ready;
    }
    const candidate = await this.#serialize(() => this.#validateCandidate(token));
    const control = AbortSignal.any([this.#lifetime.signal, AbortSignal.timeout(10 * 60_000)]);
    await mkdir(this.#stagingDirectory, { recursive: true, mode: 0o700 });
    const directory = await mkdtemp(path.join(this.#stagingDirectory, 'package-'));
    const file = path.join(directory, 'ClaudeBrowser-' + candidate.version + this.#target.extension);
    let retained = false;
    try {
      const response = await this.#request(candidate.url, control, {
        githubRelease: this.#target.isGitHubReleaseAsset?.(candidate) === true
      });
      const staged = await open(file, 'wx', 0o600);
      const hash = createHash('sha256');
      let size = 0;
      try {
        for await (const bytes of boundedResponse(response, candidate.size, control)) {
          size += bytes.byteLength;
          hash.update(bytes);
          await staged.writeFile(bytes);
        }
        if (size !== candidate.size || hash.digest('hex') !== candidate.sha256) {
          throw new ReleaseDataError('更新包的大小或哈希与签名清单不符。');
        }
        await staged.sync();
      } finally {
        await staged.close();
      }
      await this.#verifyPlatform(file, candidate, control);
      return await this.#serialize(async () => {
        control.throwIfAborted();
        await this.#validateCandidate(token);
        await this.#removeReady();
        this.#ready = { file, directory, token, version: candidate.version };
        retained = true;
        this.#onReady(this.ready);
        return this.ready;
      });
    } finally {
      if (!retained) await this.#removePackage({ file, directory });
    }
  }

  async verifyReady(token) {
    return this.#serialize(() => this.#verifyReady(token));
  }

  async saveVerified(token, destination) {
    return this.#serialize(async () => {
      const { file, candidate } = await this.#verifyReady(token);
      if (!destination.toLowerCase().endsWith(this.#target.extension)) throw new Error('保存路径的扩展名不匹配。');
      await copyFile(file, destination, constants.COPYFILE_EXCL);
      try { await this.#verifyBytes(destination, candidate); }
      catch (error) {
        await rm(destination, { force: true });
        throw error;
      }
    });
  }

  async installVerified(token, installer) {
    return this.#serialize(async () => {
      const verified = await this.#verifyReady(token);
      return installer(verified, () => this.#validateCandidate(token), this.#lifetime.signal);
    });
  }

  async #verifyReady(token) {
    const ready = this.#ready;
    if (!ready || token !== ready.token) throw new Error('更新包已改变，请重新检查。');
    try {
      const candidate = await this.#validateCandidate(token);
      await this.#verifyBytes(ready.file, candidate);
      const control = AbortSignal.any([this.#lifetime.signal, AbortSignal.timeout(30_000)]);
      await this.#verifyPlatform(ready.file, candidate, control);
      await this.#verifyBytes(ready.file, candidate);
      control.throwIfAborted();
      await this.#validateCandidate(token);
      return { file: ready.file, candidate };
    } catch (error) {
      await this.#removeReady();
      throw error;
    }
  }

  async #verifyBytes(file, candidate) {
    const actual = await fileDigest(file, candidate.size);
    if (actual.sha256 !== candidate.sha256 || actual.size !== candidate.size) {
      throw new ReleaseDataError('已下载的更新包已改变。');
    }
  }

  async close() {
    this.#lifetime.abort();
    await this.#download?.catch(() => {});
    await this.#serialize(async () => {
      this.#candidate = undefined;
      await this.#removeReady();
    });
  }

  /** @template T @param {() => Promise<T>} work @returns {Promise<T>} */
  #serialize(work) {
    const run = this.#operations.then(work);
    this.#operations = run.then(() => {}, () => {});
    return run;
  }

  async #validateCandidate(token) {
    this.#lifetime.signal.throwIfAborted();
    const current = this.#candidate;
    if (!current || current.asset.state.digest !== token) throw new Error('更新清单已改变，请重新确认。');
    const previous = await readState(this.#stateFile);
    if (previous?.digest !== token) throw new ReleaseDataError('更新记录已改变，请重新检查。');
    return validate(current.envelope, this.#target, previous, this.#now());
  }

  async #removeReady() {
    const ready = this.#ready;
    if (!ready) return;
    this.#ready = undefined;
    this.#onReady(undefined);
    await this.#removePackage(ready);
  }

  async #removePackage({ file, directory }) {
    await rm(file, { force: true });
    await rmdir(directory);
  }

  async #recoverStaging() {
    // The application acquires its per-profile single instance lock before recovery.
    const folder = await lstat(this.#stagingDirectory).catch(error => {
      if (error.code !== 'ENOENT') throw error;
    });
    if (!folder) return;
    if (!folder.isDirectory() || folder.isSymbolicLink()) throw new Error('更新暂存目录无效。');
    for (const entry of await readdir(this.#stagingDirectory, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.isSymbolicLink() || !/^package-[a-z0-9]{6}$/i.test(entry.name)) continue;
      const directory = path.join(this.#stagingDirectory, entry.name);
      const contents = await readdir(directory, { withFileTypes: true });
      const [file] = contents;
      if (!file) {
        await rmdir(directory);
        continue;
      }
      if (contents.length === 1 && file.isFile() && /^ClaudeBrowser-\d+\.\d+\.\d+\.(exe|zip)$/.test(file.name) &&
          file.name.endsWith(this.#target.extension)) {
        await this.#removePackage({ file: path.join(directory, file.name), directory });
      }
    }
  }
}
