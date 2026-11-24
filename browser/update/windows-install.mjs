import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { copyFile, lstat, mkdir, open, readFile, readdir, realpath, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { sha256 } from './release-manifest.mjs';

const launcherName = 'ClaudeBrowser.exe';
const helperName = 'windows-authenticode.exe';
const candidateName = 'candidate.exe';
const localDrive = /^[a-z]:\\/i;
const digestPattern = /^[a-f0-9]{64}$/;
const jobPattern = /^job-[a-f0-9]{16,64}$/;

function equalPath(first, second) {
  return path.win32.normalize(first).toLowerCase() === path.win32.normalize(second).toLowerCase();
}

// NSIS sets these paths but the native helper must independently bind them to the actual processes.
export function portableInstallContext({ launcher, appImage, root, appPid, launcherPid, currentVersion }) {
  if (process.platform !== 'win32' || process.arch !== 'x64' ||
      ![launcher, appImage, root].every(value => typeof value === 'string' && localDrive.test(value)) ||
      path.win32.basename(launcher).toLowerCase() !== launcherName.toLowerCase() ||
      path.win32.basename(appImage).toLowerCase() !== launcherName.toLowerCase() ||
      equalPath(launcher, appImage) ||
      !equalPath(root, path.win32.join(path.win32.dirname(launcher), '.browser-local')) ||
      !Number.isInteger(appPid) || appPid <= 0 || !Number.isInteger(launcherPid) ||
      launcherPid <= 0 || appPid === launcherPid) return undefined;
  return { launcher, appImage, root, appPid, launcherPid, currentVersion };
}

export function setupInstallContext({ appImage, root, appPid, currentVersion }) {
  if (process.platform !== 'win32' || process.arch !== 'x64' ||
      ![appImage, root].every(value => typeof value === 'string' && localDrive.test(value)) ||
      path.win32.basename(appImage).toLowerCase() !== launcherName.toLowerCase() ||
      !Number.isInteger(appPid) || appPid <= 0) return undefined;
  return { edition: 'setup', appImage, root, appPid, currentVersion };
}

function jobRoot(context) {
  return path.join(context.root, context.edition === 'setup' ? 'update-install-setup' : 'update-install');
}

async function localDirectory(directory) {
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || !equalPath(await realpath(directory), directory)) {
    throw new Error('安装暂存目录发生变化。');
  }
}

async function durableWrite(file, bytes) {
  const handle = await open(file, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function receiveLine(child, lines, prefix, signal) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      lines.off('line', arrived);
      lines.off('close', failed);
      child.off('exit', failed);
      child.off('error', failed);
      signal.removeEventListener('abort', canceled);
    };
    function arrived(line) {
      cleanup();
      const response = /^(READY|COMMITTED) ([a-f0-9]{64})$/.exec(line);
      if (response?.[1] === prefix) resolve(response[2]);
      else reject(new Error('安装助手未接受交接。'));
    }
    function failed() {
      cleanup();
      reject(new Error('安装助手在交接完成前退出。'));
    }
    function canceled() {
      cleanup();
      reject(signal.reason);
    }
    if (signal.aborted) return canceled();
    lines.once('line', arrived);
    lines.once('close', failed);
    child.once('exit', failed);
    child.once('error', failed);
    signal.addEventListener('abort', canceled, { once: true });
  });
}

async function withDeadline(operation, signal) {
  signal.throwIfAborted();
  let abort;
  const deadline = new Promise((_, reject) => {
    abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
  });
  try { return await Promise.race([operation(), deadline]); }
  finally { signal.removeEventListener('abort', abort); }
}

async function waitForExit(child) {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) return true;
  let finish;
  const exited = new Promise(resolve => {
    finish = () => resolve(true);
    child.once('exit', finish);
  });
  try { return await Promise.race([exited, delay(1000, false, { ref: false })]); }
  finally { child.off('exit', finish); }
}

export async function lastWindowsInstall(context) {
  const base = jobRoot(context);
  try {
    await localDirectory(base);
    let latest;
    for (const entry of await readdir(base, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.isSymbolicLink() || !jobPattern.test(entry.name)) continue;
      const file = path.join(base, entry.name, 'result.json');
      try {
        const info = await lstat(file);
        if (!info.isFile() || info.isSymbolicLink() || info.size > 4096 || (latest && latest.time >= info.mtimeMs)) continue;
        const result = JSON.parse(await readFile(file, 'utf8'));
        if (result.schema !== 1 || !/^\d+\.\d+\.\d+$/.test(result.candidateVersion) ||
            !['installed', 'failed', 'recovery-required'].includes(result.status)) continue;
        latest = { time: info.mtimeMs, version: result.candidateVersion, status: result.status };
      } catch { /* Incomplete receipts can be left by interrupted transactions. */ }
    }
    return latest;
  } catch { return undefined; }
}

export async function handoffWindowsInstall(context, {
  file, candidate, verifierPath, verifierHash, prepare, revalidate, signal
}) {
  if (!digestPattern.test(candidate.sha256) || !digestPattern.test(verifierHash) ||
      !Number.isSafeInteger(candidate.expiresAt) || candidate.expiresAt <= Date.now()) {
    throw new Error('安装包或授权已过期。');
  }
  signal.throwIfAborted();
  await localDirectory(context.root);
  const base = jobRoot(context);
  await mkdir(base, { recursive: true, mode: 0o700 });
  await localDirectory(base);
  const directory = path.join(base, 'job-' + randomBytes(16).toString('hex'));
  await mkdir(directory, { mode: 0o700 });
  const helper = path.join(directory, helperName);
  const staged = path.join(directory, candidateName);
  let child;
  let lines;
  let committed = false;
  let submitted = false;
  try {
    const verifier = await readFile(verifierPath);
    if (sha256(verifier) !== verifierHash) throw new Error('随包安装助手完整性检查失败。');
    await durableWrite(helper, verifier);
    await copyFile(file, staged, constants.COPYFILE_EXCL);
    const handle = await open(staged, 'r+');
    try { await handle.sync(); }
    finally { await handle.close(); }
    await revalidate();
    signal.throwIfAborted();
    const expiry = Math.min(candidate.expiresAt, Date.now() + 120_000);
    const control = AbortSignal.any([signal, AbortSignal.timeout(45_000)]);
    const versionArgs = [context.currentVersion, candidate.version, candidate.sha256, String(expiry)];
    const args = context.edition === 'setup' ?
      ['--install-setup', directory, context.appImage, String(context.appPid), ...versionArgs] :
      ['--install', directory, context.launcher, context.appImage, String(context.appPid), String(context.launcherPid), ...versionArgs];
    child = spawn(helper, args, { cwd: directory, detached: true, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
    child.on('error', () => {});
    child.stdin.on('error', () => {});
    lines = createInterface({ input: child.stdout, crlfDelay: Infinity, terminal: false });
    const nonce = await receiveLine(child, lines, 'READY', control);
    await withDeadline(prepare, control);
    await withDeadline(revalidate, control);
    control.throwIfAborted();
    const acknowledgment = receiveLine(child, lines, 'COMMITTED', control);
    submitted = true;
    child.stdin.end('COMMIT ' + nonce + '\n');
    if (await acknowledgment !== nonce) throw new Error('安装确认与交易不匹配。');
    committed = true;
    child.unref();
  } finally {
    try {
      if (!committed) {
        if (child) {
          // Before submission, EOF lets an authenticated helper record the cancellation.
          // An ambiguous acknowledgment after submission must not wait for a later app exit.
          if (submitted) child.kill();
          else child.stdin.end();
          const exited = await waitForExit(child);
          if (!exited) child.kill();
          if (exited || await waitForExit(child)) {
            await rm(staged, { force: true });
            await rm(helper, { force: true });
          }
        } else {
          await rm(staged, { force: true });
          await rm(helper, { force: true });
          await rmdir(directory);
        }
      }
    } finally {
      lines?.close();
      child?.stdout.destroy();
      child?.stdin.destroy();
    }
  }
}
