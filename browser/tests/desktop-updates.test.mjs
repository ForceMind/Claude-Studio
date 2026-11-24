import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout } from 'node:timers/promises';
import { DesktopUpdates, ReleaseDataError } from '../update/desktop-updates.mjs';
import { desktopTarget, normalizeDesktopPolicy } from '../update/desktop-policy.mjs';
import { sha256, signReleaseManifest } from '../update/release-manifest.mjs';
import { createUpdateTransport } from '../update/proxy-transport.mjs';

const now = Date.parse('2026-11-23T04:00:00Z');
const fileBytes = Buffer.from('synthetic signed application');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const feed = 'https://manifest.example.test/win32-x64.json';
const base = 'https://downloads.example.test/windows/';
const location = base + 'ClaudeBrowser.exe';
const raw = {
  schema: 1, product: 'com.claudestudio.browser', channel: 'stable',
  publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  targets: { 'win32-x64': { feed, assets: [base], minSequence: 7, signerPins: ['b'.repeat(64)] } }
};
const target = desktopTarget(raw, 'win32', 'x64', '0.5.0');
const signal = AbortSignal.timeout(30_000);

function manifest(overrides = {}) {
  return signReleaseManifest({
    schema: 1, product: target.product, channel: target.channel, platform: 'win32', arch: 'x64',
    size: fileBytes.byteLength, sha256: sha256(fileBytes), url: location,
    version: '0.5.1', sequence: 7, expiresAt: now + 10_000, ...overrides
  }, privateKey);
}

async function sandbox(t, options = {}) {
  const parent = path.resolve(tmpdir());
  const root = await mkdtemp(path.join(parent, 'claude-desktop-update-'));
  const requests = [];
  const instances = [];
  let source = manifest();
  let content = fileBytes;
  const request = async (url, control) => {
    requests.push(url);
    if (options.request) return options.request(url, control);
    return new Response(url === feed ? source : content);
  };
  const create = overrides => {
    const updater = new DesktopUpdates({ root, target, request, now: () => now, ...options, ...overrides });
    instances.push(updater);
    return updater;
  };
  const updater = create();
  t.after(async () => {
    await Promise.all(instances.map(instance => instance.close()));
    assert.equal(path.dirname(root), parent);
    assert.match(path.basename(root), /^claude-desktop-update-/);
    await rm(root, { recursive: true, force: true });
  });
  return { root, updater, create, requests, manifest(value) { source = value; }, replace(bytes) { content = bytes; } };
}

test('生产策略固定 Ed25519、最低序号、HTTPS 路径前缀和平台身份', () => {
  assert.equal(normalizeDesktopPolicy(raw).targets['win32-x64'].minSequence, 7);
  assert.equal(target.allowAssetURL(new URL(location)), true);
  for (const url of [base + 'file.zip', base + '../file.exe', base + 'folder%2fescape.exe', base + 'file.exe?x=1',
    'https://downloads.example.test/windowsextra/file.exe', 'http://downloads.example.test/windows/file.exe']) {
    assert.equal(target.allowAssetURL(new URL(url)), false, url);
  }
  assert.throws(() => normalizeDesktopPolicy({ ...raw, publicKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
  assert.throws(() => desktopTarget(raw, 'win32', 'x64', '0.5.0-preview.1'));
  assert.throws(() => desktopTarget(raw, 'darwin', 'arm64', '0.5.0'));
  assert.throws(() => normalizeDesktopPolicy({ ...raw, targets: { 'win32-x64': {
    ...raw.targets['win32-x64'], feed: 'https://127.0.0.1/feed.json'
  } } }));
});

test('检查同版本表示最新，生产最低序号和版本互相独立，默认只读取清单', async t => {
  const demo = await sandbox(t);
  demo.manifest(manifest({ version: '0.5.0' }));
  assert.equal(await demo.updater.check(signal), undefined);
  assert.deepEqual(demo.requests, [feed]);
  assert.equal(demo.updater.offer, undefined);
  demo.manifest(manifest({ version: '0.5.1', sequence: 6 }));
  await assert.rejects(demo.updater.check(signal), ReleaseDataError);
  demo.manifest(manifest({ version: '0.4.9', sequence: 20 }));
  await assert.rejects(demo.updater.check(signal), ReleaseDataError);
});

test('先接受较新响应，再到达的旧响应和同序异内容均被拒绝，重启也保持序号', async t => {
  const responses = [];
  const demo = await sandbox(t, { request: () => new Promise(resolve => responses.push(resolve)) });
  const waitForRequest = async index => {
    for (let attempt = 0; !responses[index] && attempt < 100; attempt++) await setTimeout(5);
    assert.ok(responses[index]);
  };
  const older = demo.updater.check(signal);
  const newer = demo.updater.check(signal);
  await waitForRequest(1);
  responses[1](new Response(manifest({ version: '0.6.0', sequence: 11 })));
  assert.equal(await newer, '0.6.0');
  responses[0](new Response(manifest({ version: '0.5.1', sequence: 9 })));
  await assert.rejects(older, ReleaseDataError);
  const next = demo.create();
  const incompatible = next.check(signal);
  await waitForRequest(2);
  responses[2](new Response(manifest({ version: '0.6.1', sequence: 11 })));
  await assert.rejects(incompatible, ReleaseDataError);
  const downgraded = next.check(signal);
  await waitForRequest(3);
  responses[3](new Response(manifest({ version: '0.5.9', sequence: 12 })));
  await assert.rejects(downgraded, ReleaseDataError);
  assert.equal(JSON.parse(await readFile(path.join(demo.root, 'update-state', 'win32-x64-stable.json'), 'utf8')).sequence, 11);
});

test('序号文件损坏或无法写入时不提供下载', async t => {
  const demo = await sandbox(t, { verifyPlatform: async () => {} });
  const root = path.join(demo.root, 'update-state');
  await writeFile(root, 'block state directory');
  await assert.rejects(demo.updater.check(signal));
  assert.equal(demo.updater.offer, undefined);
  await rm(root);
  await mkdir(root);
  await writeFile(path.join(root, 'win32-x64-stable.json'), '{"sequence":7}');
  await assert.rejects(demo.updater.check(signal), ReleaseDataError);
  assert.equal(demo.updater.offer, undefined);
});

test('显式下载两次校验，可重新验证并保存，保存不会覆盖现有文件', async t => {
  let checks = 0;
  const demo = await sandbox(t, { verifyPlatform: async (file, asset) => {
    assert.equal(sha256(await readFile(file)), asset.sha256);
    checks += 1;
  } });
  assert.equal(await demo.updater.check(signal), '0.5.1');
  assert.deepEqual(demo.requests, [feed]);
  const { token } = demo.updater.offer;
  assert.deepEqual(await demo.updater.download(token), { version: '0.5.1', token });
  assert.deepEqual(demo.requests, [feed, location]);
  const exported = path.join(demo.root, 'verified.exe');
  await demo.updater.saveVerified(token, exported);
  assert.equal(checks, 2);
  assert.deepEqual(await readFile(exported), fileBytes);
  await assert.rejects(demo.updater.saveVerified(token, exported), { code: 'EEXIST' });
  assert.deepEqual(await readFile(exported), fileBytes);
});

test('拒绝超限、截断、损坏和平台验签失败，清理暂存内容', async t => {
  let checks = 0;
  const demo = await sandbox(t, { verifyPlatform: async () => {
    checks += 1;
    throw new Error('untrusted release signer');
  } });
  await demo.updater.check(signal);
  const { token } = demo.updater.offer;
  for (const bad of [Buffer.concat([fileBytes, Buffer.from('extra')]), fileBytes.subarray(1), Buffer.alloc(fileBytes.byteLength)]) {
    demo.replace(bad);
    await assert.rejects(demo.updater.download(token), ReleaseDataError);
  }
  assert.equal(checks, 0);
  demo.replace(fileBytes);
  await assert.rejects(demo.updater.download(token), /untrusted release signer/);
  assert.equal(checks, 1);
  assert.equal(demo.updater.ready, undefined);
  assert.deepEqual(await readdir(path.join(demo.root, 'update-state')), ['win32-x64-stable.json']);
  assert.deepEqual(await readdir(path.join(demo.root, 'update-staging', 'win32-x64-stable')), []);
});

test('旧确认令牌与过期清单无法保存或下载', async t => {
  let time = now;
  const demo = await sandbox(t, { verifyPlatform: async () => {}, now: () => time });
  await demo.updater.check(signal);
  const first = demo.updater.offer.token;
  await demo.updater.download(first);
  demo.manifest(manifest({ version: '0.6.0', sequence: 10 }));
  await demo.updater.check(signal);
  await assert.rejects(demo.updater.saveVerified(first, path.join(demo.root, 'old.exe')));
  await assert.rejects(demo.updater.download(first));
  const second = demo.updater.offer.token;
  time = now + 10_000;
  await assert.rejects(demo.updater.download(second), ReleaseDataError);
  assert.equal(demo.updater.ready, undefined);
});

test('安装交接绑定已验证的原包，准备时清单到期则禁止提交', async t => {
  let time = now;
  const demo = await sandbox(t, { verifyPlatform: async () => {}, now: () => time });
  await demo.updater.check(signal);
  const token = demo.updater.offer.token;
  await demo.updater.download(token);
  let reached = false;
  await assert.rejects(demo.updater.installVerified(token, async ({ file, candidate }, revalidate) => {
    assert.deepEqual(await readFile(file), fileBytes);
    assert.equal(candidate.state.digest, token);
    assert.equal(candidate.expiresAt, now + 10_000);
    reached = true;
    time = candidate.expiresAt;
    await revalidate();
    assert.fail('expired update reached commit');
  }), ReleaseDataError);
  assert.equal(reached, true);
});

test('退出时取消停滞的下载流并移除自有临时文件', async t => {
  let started;
  const received = new Promise(resolve => { started = resolve; });
  let canceled = false;
  const demo = await sandbox(t, {
    verifyPlatform: async () => {},
    async request(url) {
      if (url === feed) return new Response(manifest());
      return new Response(new ReadableStream({
        pull() { started(); }, cancel() { canceled = true; }
      }));
    }
  });
  await demo.updater.check(signal);
  const pending = assert.rejects(demo.updater.download(demo.updater.offer.token));
  await received;
  await demo.updater.close();
  await pending;
  assert.equal(canceled, true);
  assert.deepEqual(await readdir(path.join(demo.root, 'update-state')), ['win32-x64-stable.json']);
  assert.deepEqual(await readdir(path.join(demo.root, 'update-staging', 'win32-x64-stable')), []);
});

test('下一次启动只清理由中断留下的应用自有暂存目录和文件', async t => {
  const demo = await sandbox(t);
  const staging = path.join(demo.root, 'update-staging', 'win32-x64-stable');
  await mkdir(path.join(staging, 'package-Ab123c'), { recursive: true });
  await mkdir(path.join(staging, 'package-5896Ac'), { recursive: true });
  await writeFile(path.join(staging, 'package-Ab123c', 'ClaudeBrowser-0.5.1.exe'), 'partial');
  await writeFile(path.join(staging, 'package-5896Ac', 'user-file.txt'), 'preserve');
  await demo.updater.check(signal);
  assert.deepEqual(await readdir(staging), ['package-5896Ac']);
});

test('专用更新会话在代理设置完成前不发请求，拒绝 DIRECT，代理切换取消旧请求', async () => {
  let port = null;
  let route = 'DIRECT';
  let beforeSend;
  const calls = [];
  let lastSignal;
  const transport = createUpdateTransport({
    readPort: () => port,
    session: {
      webRequest: { onBeforeSendHeaders(_filter, handler) { beforeSend = handler; } },
      async setProxy(config) { calls.push(config); },
      async closeAllConnections() { calls.push('closeAllConnections'); },
      async resolveProxy() { calls.push('resolve'); return route; },
      async fetch(url, options) { calls.push(url); lastSignal = options.signal; return options; }
    },
    async connect(upstream) { calls.push(['connect', upstream]); return { port: 43123, online: true, close() { calls.push('close'); } }; }
  });
  await assert.rejects(transport.request(feed, signal));
  assert.deepEqual(calls, []);
  port = 32109;
  await assert.rejects(transport.request(feed, signal));
  assert.deepEqual(calls, [['connect', port], { mode: 'fixed_servers', proxyRules: 'http://127.0.0.1:43123',
    proxyBypassRules: '<-loopback>' }, 'closeAllConnections', 'resolve']);
  route = 'PROXY 127.0.0.1:43123';
  const request = await transport.request(feed, signal);
  assert.equal(request.redirect, 'error');
  assert.equal(request.credentials, 'omit');
  assert.equal(request.referrerPolicy, 'no-referrer');
  beforeSend({ requestHeaders: { Cookie: 'secret', authorization: 'secret', Referer: 'secret', Accept: 'application/json' } },
    result => assert.deepEqual(result.requestHeaders, { Accept: 'application/json' }));
  transport.invalidate();
  assert.equal(lastSignal.aborted, true);
  assert.ok(calls.includes('close'));
  transport.close();
});


test('安装版和便携版各自接受签名清单和独立序号，拒绝交叉工件', async t => {
  const setupFeed = 'https://manifest.example.test/windows-setup.json';
  const setupBase = 'https://downloads.example.test/setup/';
  const setupURL = setupBase + 'ClaudeBrowser-Setup.exe';
  const config = { ...raw, targets: { ...raw.targets,
    'win32-x64-setup': { ...raw.targets['win32-x64'], feed: setupFeed, assets: [setupBase] }
  } };
  const setup = desktopTarget(config, 'win32', 'x64', '0.5.0', 'setup');
  const portable = desktopTarget(config, 'win32', 'x64', '0.5.0');
  assert.throws(() => normalizeDesktopPolicy({ ...config, targets: { ...config.targets,
    'win32-x64-setup': { ...config.targets['win32-x64-setup'], feed }
  } }), /各自/);
  const demo = await sandbox(t);
  const installed = demo.create({ target: setup, request: async () => new Response(manifest({
    edition: 'setup', sequence: 8, version: '0.5.6', url: setupURL
  })) });
  assert.equal(await installed.check(signal), '0.5.6');
  assert.equal(await demo.updater.check(signal), '0.5.1');
  assert.equal(portable.allowAssetURL(new URL(base + 'ClaudeBrowser-Setup.exe')), false);
  assert.equal(setup.allowAssetURL(new URL(setupBase + 'ClaudeBrowser.exe')), false);
  for (const wrong of [manifest({ url: setupURL }), manifest({ edition: 'setup', url: location })]) {
    const reject = demo.create({ target: setup, request: async () => new Response(wrong) });
    await assert.rejects(reject.check(signal), ReleaseDataError);
  }
  demo.manifest(manifest({ edition: 'setup', url: location }));
  await assert.rejects(demo.updater.check(signal), ReleaseDataError);
  assert.deepEqual((await readdir(path.join(demo.root, 'update-state'))).sort(),
    ['win32-x64-stable-setup.json', 'win32-x64-stable.json']);
});

test('签名的 GitHub Setup 经同一代理跳转到 CDN，下载后仍执行包校验', async t => {
  const setupFeed = 'https://raw.githubusercontent.com/example/project/windows-updates/win32-x64-setup.json';
  const setupBase = 'https://github.com/example/project/releases/download/';
  const setupURL = setupBase + 'windows-setup-v0.5.1/ClaudeBrowser-Setup.exe';
  const cdnURL = 'https://release-assets.githubusercontent.com/github-production-release-asset/123/abcd-1234?sig=fixture';
  const config = { ...raw, targets: {
    'win32-x64-setup': { ...raw.targets['win32-x64'], feed: setupFeed, assets: [setupBase] }
  } };
  const setup = desktopTarget(config, 'win32', 'x64', '0.5.0', 'setup');
  assert.equal(setup.isGitHubReleaseAsset({ url: setupURL, version: '0.5.1' }), true);
  assert.equal(setup.isGitHubReleaseAsset({ url: setupURL, version: '0.5.2' }), false);
  assert.equal(setup.isGitHubReleaseAsset({ url: setupURL.replace('/example/', '/other/'), version: '0.5.1' }), false);
  assert.equal(setup.allowAssetURL(new URL(cdnURL)), false);

  const calls = [];
  let aborted = false;
  let verified = false;
  const transport = createUpdateTransport({
    readPort: () => 10810,
    session: {
      webRequest: { onBeforeSendHeaders() {} },
      async setProxy() {},
      async closeAllConnections() {},
      async resolveProxy(url) { calls.push(['route', url]); return 'PROXY 127.0.0.1:43123'; },
      async fetch(url, options) {
        calls.push(['fetch', url, options.redirect, options.credentials, options.referrerPolicy]);
        return new Response(url === setupFeed ? manifest({ edition: 'setup', url: setupURL }) : fileBytes);
      }
    },
    openRequest(options) {
      calls.push(['open', options.url, options.redirect, options.credentials, options.referrerPolicy]);
      const request = new EventEmitter();
      request.end = () => request.emit('redirect', 302, 'GET', cdnURL);
      request.abort = () => { aborted = true; };
      return request;
    },
    async connect() { return { port: 43123, online: true, close() {} }; }
  });
  t.after(() => transport.close());
  const demo = await sandbox(t);
  const updater = demo.create({ target: setup, request: transport.request, async verifyPlatform(file, candidate) {
    assert.equal(candidate.sha256, sha256(await readFile(file)));
    verified = true;
  } });
  assert.equal(await updater.check(signal), '0.5.1');
  assert.equal((await updater.download(updater.offer.token)).version, '0.5.1');
  assert.equal(aborted, true);
  assert.equal(verified, true);
  assert.deepEqual(calls, [
    ['route', setupFeed], ['fetch', setupFeed, 'error', 'omit', 'no-referrer'],
    ['route', setupURL], ['open', setupURL, 'manual', 'omit', 'no-referrer'],
    ['route', cdnURL], ['fetch', cdnURL, 'error', 'omit', 'no-referrer']
  ]);
});

test('GitHub 安装包拒绝意外跳转和直连，切换代理时中止在途请求', async t => {
  const asset = 'https://github.com/example/project/releases/download/windows-setup-v0.5.1/ClaudeBrowser-Setup.exe';
  const cdn = 'https://release-assets.githubusercontent.com/github-production-release-asset/123/abcd-1234?sig=fixture';
  let status = 302;
  let redirect = cdn;
  let allowCdnProxy = false;
  let directResponse = false;
  let pause = false;
  let aborts = 0;
  let started;
  const transport = createUpdateTransport({
    readPort: () => 10810,
    session: {
      webRequest: { onBeforeSendHeaders() {} },
      async setProxy() {},
      async closeAllConnections() {},
      async resolveProxy(url) { return url === asset || allowCdnProxy ? 'PROXY 127.0.0.1:43123' : 'DIRECT'; },
      async fetch(_url, options) {
        assert.equal(options.redirect, 'error');
        throw new Error('进一步跳转被拒绝');
      }
    },
    openRequest() {
      const request = new EventEmitter();
      request.end = () => {
        if (pause) return started();
        if (!directResponse) return request.emit('redirect', status, 'GET', redirect);
        const response = Readable.from([fileBytes]);
        response.statusCode = 200;
        request.emit('response', response);
      };
      request.abort = () => { aborts++; };
      return request;
    },
    async connect() { return { port: 43123, online: true, close() {} }; }
  });
  t.after(() => transport.close());
  const options = { githubRelease: true };
  for (const bad of [cdn.replace('https:', 'http:'), cdn.replace('.com/', '.com.evil.test/'),
    cdn.replace('.com/', '.com:8443/'), cdn.replace('://', '://user@'),
    cdn.replace('github-production-release-asset', 'elsewhere'), cdn + '#fragment']) {
    redirect = bad;
    await assert.rejects(transport.request(asset, signal, options), /重定向不符合/);
  }
  redirect = cdn;
  status = 301;
  await assert.rejects(transport.request(asset, signal, options), /重定向不符合/);
  status = 302;
  await assert.rejects(transport.request(asset, signal, options), /代理不可用/);
  allowCdnProxy = true;
  await assert.rejects(transport.request(asset, signal, options), /进一步跳转被拒绝/);
  directResponse = true;
  const response = await transport.request(asset, signal, options);
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), fileBytes);

  pause = true;
  const began = new Promise(resolve => { started = resolve; });
  const inFlight = transport.request(asset, signal, options);
  await began;
  transport.invalidate();
  await assert.rejects(inFlight, { name: 'AbortError' });
  assert.equal(aborts, 10);
});