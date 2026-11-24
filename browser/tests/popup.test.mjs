import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { build } from 'esbuild';

const require = createRequire(import.meta.url);
const { outputFiles } = await build({
  bundle: true, platform: 'node', format: 'cjs', write: false,
  entryPoints: [fileURLToPath(new URL('../shell/network.ts', import.meta.url))],
  external: ['electron', '../relay.mjs']
});
const loadNetwork = new Function('require', 'module', outputFiles[0].text);
const profile = { language: 'en-US', zone: 'America/Los_Angeles', mail: '' };

function makeNetwork() {
  const sessions = new Map();
  const electron = {
    app: { getPreferredSystemLanguages: () => ['en-US'] },
    session: {
      fromPartition(partition) {
        const state = {
          webRequest: {
            onBeforeSendHeaders(_filter, callback) { state.headers = callback; },
            onBeforeRequest(_filter, callback) { state.request = callback; }
          },
          getUserAgent() { return 'Chromium test'; },
          setUserAgent() {},
          flushStorageData() { state.storageFlushed = true; },
          cookies: { async flushStore() { state.cookiesFlushed = true; } },
          setPermissionCheckHandler() {},
          setPermissionRequestHandler() {},
          setDisplayMediaRequestHandler() {},
          setDevicePermissionHandler() {},
          on() {},
          async setProxy(proxy) { state.proxy = proxy; },
          async closeAllConnections() {}
        };
        assert.ok(!sessions.has(partition));
        sessions.set(partition, state);
        return state;
      }
    }
  };
  const module = { exports: {} };
  loadNetwork(id => {
    if (id === 'electron') return electron;
    if (id === '../relay.mjs') return {
      startRelay: async port => ({ port, online: true, close() { this.online = false; } })
    };
    return require(id);
  }, module);
  return { network: new module.exports.AccountNetwork(() => {}), sessions };
}

function makeContents(id, session, sendCommand) {
  const events = new EventEmitter();
  return Object.assign(events, {
    id, session,
    setWebRTCIPHandlingPolicy(policy) { this.webRTC = policy; },
    stop() { this.stopped = true; },
    isDestroyed() { return false; },
    getUserAgent() { return 'Chromium test'; },
    debugger: { attach() {}, sendCommand }
  });
}

function navigation(session, details) {
  return new Promise(resolve => session.request({resourceType: 'mainFrame', ...details}, resolve));
}

test('安装退出前刷新已配置账号的存储和 Cookie，失败时向调用方报错', async () => {
  const { network, sessions } = makeNetwork();
  await network.connect('A', 42873, profile);
  await network.connect('B', 42873, profile);
  await network.flushStorage();
  assert.equal(sessions.size, 2);
  for (const account of sessions.values()) {
    assert.equal(account.storageFlushed, true);
    assert.equal(account.cookiesFlushed, true);
  }
  sessions.get('persist:account-B').cookies.flushStore = async () => { throw new Error('profile write failed'); };
  await assert.rejects(network.flushStorage(), /profile write failed/);
});

test('原生弹窗首请求先走发起账号代理，网页初始化可等导航开始后完成', async () => {
  const { network, sessions } = makeNetwork();
  const space = await network.connect('A', 42873, profile);
  const session = sessions.get('persist:account-A');
  assert.equal(session.proxy.proxyRules, 'http://127.0.0.1:42873');
  const calls = [];
  let beginNavigation;
  const requestStarted = new Promise(resolve => { beginNavigation = resolve; });
  const popup = makeContents(10, session, async (command, options) => {
    calls.push([command, options]);
    await requestStarted;
  });
  const preferences = network.preparePopup(popup, space);
  assert.equal(popup.webRTC, 'disable_non_proxied_udp');
  let reply;
  session.request({ resourceType: 'mainFrame', webContents: popup }, result => { reply = result; });
  assert.deepEqual(reply, {}, '弹窗首请求必须立即放行，网页环境可以等导航开始');
  const headers = await new Promise(resolve => session.headers({ requestHeaders: {} }, resolve));
  assert.equal(headers.requestHeaders['Accept-Language'], 'en-US,en;q=0.9');
  beginNavigation();
  assert.equal(await preferences, undefined);
  assert.equal(calls[0][1].acceptLanguage, 'en-US,en');
  assert.deepEqual(calls[1], ['Emulation.setTimezoneOverride', { timezoneId: profile.zone }]);
  popup.emit('destroyed');
  assert.deepEqual(await navigation(session, { webContentsId: popup.id }), { cancel: true });
});

test('账号不匹配、代理失效及重新连接后的旧弹窗都保持拦截', async () => {
  const { network, sessions } = makeNetwork();
  const a = await network.connect('A', 42873, profile);
  const b = await network.connect('B', 42874, profile);
  const popup = makeContents(11, a.session, async () => {});
  const wrong = makeContents(12, b.session, () => assert.fail('Wrong session should remain unconfigured'));
  assert.equal(await network.preparePopup(wrong, a), '账号会话不匹配');
  assert.equal(wrong.stopped, true);
  assert.deepEqual(await navigation(b.session, { webContentsId: wrong.id }), { cancel: true });
  assert.equal(await network.preparePopup(popup, a), undefined);
  assert.deepEqual(await navigation(b.session, { webContentsId: popup.id }), { cancel: true });
  a.relay.online = false;
  assert.deepEqual(await navigation(a.session, { webContentsId: popup.id }), { cancel: true });
  await network.disconnect('A');
  const next = await network.connect('A', 42875, profile);
  assert.equal(next.session, a.session);
  assert.equal(sessions.get('persist:account-A').proxy.proxyRules, 'http://127.0.0.1:42875');
  assert.deepEqual(await navigation(next.session, { webContentsId: popup.id }), { cancel: true });
});

test('弹窗给出脱敏失败阶段，普通标签仍等待本地引导和时区设置', async () => {
  const { network } = makeNetwork();
  const space = await network.connect('A', 42873, profile);
  const popup = makeContents(13, space.session, async command => {
    if (command === 'Emulation.setTimezoneOverride') throw new Error('private login value');
  });
  assert.equal(await network.preparePopup(popup, space), '应用网页时区失败');

  let finishBootstrap;
  const tab = makeContents(14, space.session, async () => {});
  tab.loadFile = () => new Promise(resolve => { finishBootstrap = resolve; });
  tab.executeJavaScript = async () => undefined;
  const preferences = network.prepare(tab, space, 'synthetic-empty.html');
  let replied = false;
  const request = navigation(space.session, { webContentsId: tab.id }).then(result => {
    replied = true;
    return result;
  });
  await Promise.resolve();
  assert.equal(replied, false);
  finishBootstrap();
  assert.equal(await preferences, true);
  assert.deepEqual(await request, { cancel: false });
});

test('邮箱分区拦截 Claude 请求，只向已登记的顶层 GET 发起选择，邮箱 OAuth 保留原会话', async () => {
  const { network, sessions } = makeNetwork();
  const mailbox = await network.connect('mailbox:synthetic-1', 42873, profile);
  const sameMailbox = await network.connect('mailbox:synthetic-1', 42873, profile);
  const otherMailbox = await network.connect('mailbox:synthetic-2', 42873, profile);
  const accountA = await network.connect('A', 42873, profile);
  assert.equal(mailbox, sameMailbox);
  assert.notEqual(mailbox.session, otherMailbox.session);
  assert.notEqual(mailbox.session, accountA.session);
  assert.equal(sessions.get('persist:mailbox-synthetic-1'), mailbox.session);
  const source = makeContents(22, mailbox.session, async () => {});
  const a = makeContents(23, accountA.session, async () => {});
  const offered = [];
  await network.preparePopup(source, mailbox, url => offered.push(url));
  await network.preparePopup(a, accountA);
  const url = 'https://claude.ai/login?code=synthetic';
  const request = { method: 'GET', webContentsId: source.id, url };
  for (const extra of [
    { method: 'POST' }, { resourceType: 'subFrame' }, { resourceType: 'xhr' },
    { webContentsId: a.id }, { url: 'http://claude.ai/login' },
    { url: 'https://claude.ai:449/login' }, { url: 'https://claude.ai./login' },
    { url: 'https://fake.claude.ai/login' }, { url: 'https://name:pass@claude.ai/login' },
    { uploadData: [{}] }
  ]) assert.deepEqual(await navigation(mailbox.session, { ...request, ...extra }), { cancel: true });
  assert.deepEqual(offered, []);
  assert.deepEqual(await navigation(mailbox.session, request), { cancel: true });
  assert.deepEqual(offered, [url]);
  assert.deepEqual(await navigation(mailbox.session, { ...request, url: 'https://claude.ai.example.test/login' }), {});
  assert.deepEqual(offered, [url]);
  assert.deepEqual(await navigation(mailbox.session, { ...request, method: 'POST', url: 'https://accounts.google.com/signin' }), {});
  assert.deepEqual(await navigation(accountA.session, { ...request, webContentsId: a.id }), {});
  await network.flushStorage();
  assert.ok(mailbox.session.storageFlushed && mailbox.session.cookiesFlushed);
  source.emit('destroyed');
  assert.deepEqual(await navigation(mailbox.session, request), { cancel: true });
  assert.deepEqual(offered, [url]);
});
