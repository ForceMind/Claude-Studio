import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import { build } from 'esbuild';
import { defaults, loadSettings } from '../settings.mjs';
import { loadState } from '../shell/state.ts';
import { installedMarker, readInstalledChoice, saveInstalledChoice, windowsAppId } from '../shell/windows-edition.ts';
import { signReleaseManifest, sha256 } from '../update/release-manifest.mjs';

const feed = 'https://manifest.example.test/win32-x64.json';
const base = 'https://downloads.example.test/claude/';
const product = 'com.claudestudio.browser';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const policy = {
  schema: 1, product, channel: 'stable', publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  targets: { 'win32-x64': { feed, assets: [base], minSequence: 10, signerPins: ['1'.repeat(64)] } }
};
const envelope = signReleaseManifest({
  schema: 1, product, channel: 'stable', platform: 'win32', arch: 'x64',
  version: '0.5.1', sequence: 10, expiresAt: Date.now() + 600_000,
  size: 1, sha256: sha256(Buffer.from([1])), url: base + 'ClaudeBrowser.exe'
}, privateKey);

const setupFeed = 'https://manifest.example.test/win32-x64-setup.json';
const setupBase = 'https://downloads.example.test/claude-setup/';
const setupPolicy = { ...policy, targets: {
  'win32-x64-setup': { feed: setupFeed, assets: [setupBase], minSequence: 10, signerPins: ['1'.repeat(64)] }
} };
const setupEnvelope = signReleaseManifest({
  schema: 1, product, channel: 'stable', platform: 'win32', arch: 'x64', edition: 'setup',
  version: '0.5.2', sequence: 10, expiresAt: Date.now() + 600_000,
  size: 1, sha256: sha256(Buffer.from([1])), url: setupBase + 'ClaudeBrowser-Setup.exe'
}, privateKey);

async function until(condition) {
  for (let pass = 0; pass < 100; pass++) {
    if (condition()) return;
    await setTimeout(10);
  }
  assert.fail('main process did not publish the expected state');
}

async function start(t, release, { port = 30202, decisions = [], failClear, fakePages = false, installed, savedSettings = defaults } = {}) {
  const parent = path.resolve(tmpdir());
  const root = await mkdtemp(path.join(parent, 'claude-production-shell-'));
  let dispose = async () => {};
  t.after(async () => {
    await dispose();
    assert.equal(path.dirname(root), parent);
    assert.match(path.basename(root), /^claude-production-shell-/);
    await rm(root, { recursive: true, force: true });
  });
  const user = path.join(root, '.browser-local');
  await mkdir(path.join(user, 'electron'), { recursive: true });
  await writeFile(path.join(user, 'settings.json'), JSON.stringify({ ...savedSettings, port }));
  const resources = path.join(root, 'resources');
  const installedRoot = path.join(root, 'Claude Browser');
  if (installed) {
    await mkdir(resources);
    await writeFile(path.join(resources, installedMarker), 'installed\n');
    if (installed === 'reuse') saveInstalledChoice(installedRoot, { kind: 'portable', root: user });
  }
  let currentWindow;
  let quit = false;
  let menu;
  let proxy;
  const checks = [];
  const requests = [];
  const handlers = new Map();
  const dataPaths = new Map();
  const clear = [];
  const prompts = [];
  const pages = [];
  const attached = new Set();
  const app = Object.assign(new EventEmitter(), {
    isPackaged: true, commandLine: { appendSwitch() {} }, enableSandbox() {}, requestSingleInstanceLock: () => true,
    getVersion: () => '0.5.0', whenReady: async () => {}, setPath: (key, value) => dataPaths.set(key, value),
    getPath: () => root, getPreferredSystemLanguages: () => ['en-US'],
    setAppUserModelId(id) { this.appId = id; },
    relaunch() { this.relaunched = true; },
    quit() { quit = true; }
  });
  const session = {
    defaultSession: { webRequest: { onBeforeRequest() {} } },
    fromPartition(name, options) {
      if (name.startsWith('persist:account-')) return {
        async closeAllConnections() {},
        async clearData() {
          clear.push(name);
          if (failClear === name) throw new Error('synthetic partition failure');
        },
        async clearAuthCache() {}
      };
      checks.push({ name, options });
      return {
        webRequest: { onBeforeSendHeaders() {} }, async setProxy(config) { proxy = config; },
        async closeAllConnections() {}, async resolveProxy() { return 'PROXY 127.0.0.1:43210'; },
        async fetch(url) { requests.push(url); return new Response(url === setupFeed ? setupEnvelope : envelope); }
      };
    }
  };
  class Window extends EventEmitter {
    constructor() {
      super();
      currentWindow = this;
      this.webContents = Object.assign(new EventEmitter(), { setWindowOpenHandler() {}, send() {}, focus() {} });
      this.contentView = { addChildView: view => attached.add(view), removeChildView: view => attached.delete(view) };
    }
    getContentSize() { return [900, 650]; }
    isFullScreen() { return false; }
    setTitle() {}
    setAppDetails(details) { this.details = details; }
    setMenuBarVisibility() {}
    isDestroyed() { return false; }
    isMinimized() { return false; }
    show() {}
    focus() { this.emit('focus'); }
    async loadFile(file) { this.webContents.mainFrame = { url: pathToFileURL(file).href }; }
  }
  class View {
    constructor({ webPreferences }) {
      const contents = Object.assign(new EventEmitter(), {
        id: pages.length + 1, session: webPreferences.session, url: '',
        destroyed: false, loads: 0, muted: false,
        navigationHistory: { canGoBack: () => false, canGoForward: () => false },
        setWindowOpenHandler(handler) { this.open = handler; },
        isDestroyed() { return this.destroyed; },
        isLoadingMainFrame: () => false, getURL() { return this.url; },
        isAudioMuted() { return this.muted; }, setAudioMuted(value) { this.muted = value; },
        focus() {},
        async loadURL(url) { this.url = url; this.loads++; this.emit('did-navigate', {}, url); this.emit('did-stop-loading'); },
        close() { this.destroyed = true; this.emit('destroyed'); }
      });
      this.webContents = contents;
      pages.push(this);
    }
    setBackgroundColor() {}
    setVisible() {}
    setBounds() {}
  }
  const electron = {
    app, session, powerMonitor: new EventEmitter(), BrowserWindow: Window, WebContentsView: View,
    screen: { getAllDisplays: () => [] },
    ipcMain: { handle: (name, fn) => handlers.set(name, fn) },
    Menu: { buildFromTemplate: entries => entries, setApplicationMenu: entries => { menu = entries; } },
    dialog: {
      showErrorBox: (_, message) => assert.fail(message),
      async showMessageBox(parent, options) {
        prompts.push(options ?? parent);
        return { response: decisions.shift() ?? 0 };
      },
      async showOpenDialog() { return { canceled: false, filePaths: [root] }; }
    }
  };
  const source = fileURLToPath(new URL('../shell/main.ts', import.meta.url));
  const { outputFiles } = await build({
    entryPoints: [source], bundle: true, platform: 'node', format: 'cjs', write: false, logLevel: 'silent',
    external: ['electron'], define: { __DESKTOP_RELEASE__: JSON.stringify(release), __WINDOWS_UPDATE_PREVIEW__: 'false' },
    plugins: [{ name: 'loopback-relay-fixture', setup(builder) {
      builder.onResolve({ filter: /^\.\.\/relay\.mjs$/ }, () => ({ path: 'relay', namespace: 'fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'fixture' }, () => ({
        contents: 'export async function startRelay() { return { port: 43210, online: true, close() {} }; }'
      }));
      if (fakePages) {
        builder.onResolve({ filter: /^\.\/network$/ }, () => ({ path: 'page-network', namespace: 'page-fixture' }));
        builder.onLoad({ filter: /.*/, namespace: 'page-fixture' }, () => ({ contents: [
          'export const securePreferences = {};',
          'export class AccountNetwork {',
          ' constructor(){this.spaces = new Map();}',
          ' status(){return "online";}',
          ' async connect(id){if (!this.spaces.has(id)) this.spaces.set(id, {session:{id}}); return this.spaces.get(id);}',
          ' canReuse(id,space){return this.spaces.get(id) === space;}',
          ' webPreferences(space){return {session:space.session};}',
          ' async prepare(contents, _space, _bootstrap, requestLink){contents.requestLink = requestLink; return true;}',
          ' async clearAccountData(id){this.spaces.delete(id);}',
          ' async disconnect(id){this.spaces.delete(id);}',
          ' close(){this.spaces.clear();}',
          '}'
        ].join('\n') }));
      }
    } }]
  });
  const previousResources = process.resourcesPath;
  if (installed) process.resourcesPath = resources;
  const previous = process.env.PORTABLE_EXECUTABLE_DIR;
  const previousOverride = process.env.CLAUDE_BROWSER_DATA_DIR;
  process.env.PORTABLE_EXECUTABLE_DIR = root;
  if (release) process.env.CLAUDE_BROWSER_DATA_DIR = path.join(root, 'should-not-be-used');
  else delete process.env.CLAUDE_BROWSER_DATA_DIR;
  dispose = async () => {
    if (app.listenerCount('will-quit')) {
      app.emit('will-quit', { preventDefault() {} });
      await until(() => quit);
    }
    if (installed) {
      if (previousResources === undefined) delete process.resourcesPath;
      else process.resourcesPath = previousResources;
    }
    if (previous === undefined) delete process.env.PORTABLE_EXECUTABLE_DIR;
    else process.env.PORTABLE_EXECUTABLE_DIR = previous;
    if (previousOverride === undefined) delete process.env.CLAUDE_BROWSER_DATA_DIR;
    else process.env.CLAUDE_BROWSER_DATA_DIR = previousOverride;
  };
  const nativeRequire = createRequire(import.meta.url);
  const module = { exports: {} };
  new Function('require', 'module', 'exports', '__dirname', outputFiles[0].text)(
    id => id === 'electron' ? electron : nativeRequire(id), module, module.exports, path.dirname(source)
  );
  await until(() => installed === 'choose' ? quit : currentWindow?.webContents.mainFrame);
  const trusted = () => ({ sender: currentWindow.webContents, senderFrame: currentWindow.webContents.mainFrame });
  return {
    app, power: electron.powerMonitor, checks, requests, dataPaths, user, handlers,
    installedRoot, window: currentWindow, menu: () => menu.find(item => item.label === '更新').submenu, proxy: () => proxy,
    send: command => handlers.get('shell:command')(trusted(), command),
    state: () => handlers.get('shell:read')(trusted()),
    clear, prompts, pages, attached
  };
}

const windows = { skip: process.platform !== 'win32' || process.arch !== 'x64' };

test('真实主入口在无内置信任策略时不创建更新会话', windows, async t => {
  const shell = await start(t, null);
  assert.deepEqual(shell.checks, []);
  assert.deepEqual(shell.requests, []);
  assert.equal(shell.menu()[0].label, '未配置生产更新源');
});

test('真实主入口在启动和显式再打开时检查，普通恢复不重复；拒绝不可信 renderer', windows, async t => {
  const shell = await start(t, { config: policy });
  await until(() => shell.menu()[0].label === '发现更新 0.5.1');
  assert.equal(shell.dataPaths.get('userData'), path.join(shell.user, 'electron'));
  assert.deepEqual(shell.checks, [{ name: 'claude-release-updates', options: { cache: false } }]);
  assert.deepEqual(shell.requests, [feed]);
  assert.equal(shell.proxy().proxyRules, 'http://127.0.0.1:43210');
  assert.ok(!shell.menu().some(item => /下载|安装/.test(item.label)));
  assert.throws(() => shell.handlers.get('shell:command')({
    sender: shell.window.webContents, senderFrame: { url: 'https://web.example.test/' }
  }, { type: 'menu', menu: 'app', x: 0, y: 0 }), /未知/);
  shell.power.emit('resume');
  assert.deepEqual(shell.requests, [feed]);
  shell.app.emit('second-instance');
  await until(() => shell.requests.length === 2);
  await until(() => shell.menu()[0].label === '发现更新 0.5.1');
  assert.deepEqual(shell.requests, [feed, feed]);
});

test('主进程确认后只清理指定账号，设置和其他账号保留', windows, async t => {
  const shell = await start(t, null, { port: null, decisions: [0, 1] });
  const legacy = path.join(shell.user, 'profiles', 'A');
  await mkdir(legacy, { recursive: true });
  await writeFile(path.join(legacy, 'edge.txt'), 'legacy');
  assert.equal(await shell.send({ type: 'account-order', id: 'B', direction: -1 }), undefined);
  assert.deepEqual(Object.keys(shell.state().settings.profiles), ['B', 'A']);
  await shell.send({ type: 'account-clear', id: 'A' });
  assert.deepEqual(shell.clear, []);
  assert.equal(shell.prompts[0].defaultId, 0);
  assert.match(shell.prompts[0].message, /账户 A/);
  assert.equal(await shell.send({ type: 'account-clear', id: 'A' }), undefined);
  assert.deepEqual(shell.clear, ['persist:account-A']);
  assert.deepEqual(Object.keys(shell.state().settings.profiles), ['B', 'A']);
  assert.equal(shell.state().account, 'A');
  assert.deepEqual(Object.keys(JSON.parse(await readFile(path.join(shell.user, 'settings.json'), 'utf8')).profiles), ['B', 'A']);
  assert.equal(await readFile(path.join(legacy, 'edge.txt'), 'utf8'), 'legacy');
});

test('清理失败时保留账号配置，网页帧无权发送清理命令', windows, async t => {
  const shell = await start(t, null, { port: null, decisions: [1], failClear: 'persist:account-A' });
  assert.throws(() => shell.handlers.get('shell:command')({
    sender: shell.window.webContents, senderFrame: { url: 'https://web.example.test/' }
  }, { type: 'account-clear', id: 'A' }), /未知/);
  assert.deepEqual(shell.clear, []);
  assert.match(await shell.send({ type: 'account-clear', id: 'A' }), /账号配置已保留/);
  assert.deepEqual(shell.clear, ['persist:account-A']);
  assert.deepEqual(Object.keys(shell.state().settings.profiles), ['A', 'B']);
});

test('撤销关闭重新挂载同一个网页，后台导航进认证页时丢弃缓存', windows, async t => {
  const shell = await start(t, null, { fakePages: true });
  const first = shell.state().active;
  await shell.send({ type: 'navigate', url: 'https://example.test/thread' });
  await until(() => shell.pages[0]?.webContents.loads === 1);
  const view = shell.pages[0];
  await shell.send({ type: 'close', id: first });
  assert.equal(shell.attached.has(view), false);
  assert.equal(view.webContents.isAudioMuted(), true);
  assert.equal(view.webContents.destroyed, false);
  assert.deepEqual(view.webContents.open({ url: 'https://example.test/popup' }), { action: 'deny' });
  await shell.send({ type: 'restore' });
  await until(() => shell.attached.has(view));
  assert.equal(shell.state().active, first);
  assert.equal(view.webContents.loads, 1);
  assert.equal(view.webContents.isAudioMuted(), false);
  await shell.send({ type: 'close', id: first });
  let blocked = false;
  view.webContents.emit('will-navigate', { url: 'https://example.test/login', preventDefault() { blocked = true; } });
  assert.equal(blocked, true);
  assert.equal(view.webContents.destroyed, true);
  await shell.send({ type: 'restore' });
  await until(() => shell.pages.some(next => next !== view && next.webContents.getURL() === 'https://example.test/thread'));
});


test('移除当前账号后切到剩余账号，取消与最后一个账号规则均有效', windows, async t => {
  const shell = await start(t, null, { port: null, decisions: [0, 1, 1] });
  await shell.send({ type: 'add-account' });
  assert.equal(await shell.send({ type: 'create-account',
    profile: { name: '测试账号', language: 'en-US', zone: 'system', mail: '' } }), undefined);
  const generated = shell.state().account;
  await shell.send({ type: 'account', id: 'A' });
  await shell.send({ type: 'account-remove', id: 'A' });
  assert.deepEqual(shell.clear, []);
  assert.equal(await shell.send({ type: 'account-remove', id: 'A' }), undefined);
  assert.equal(shell.state().account, 'B');
  assert.deepEqual(shell.clear, ['persist:account-A']);
  assert.equal(await shell.send({ type: 'account-remove', id: generated }), undefined);
  assert.deepEqual(shell.clear, ['persist:account-A', 'persist:account-' + generated]);
  assert.match(await shell.send({ type: 'account-remove', id: 'B' }), /至少/);
  assert.equal(shell.prompts.length, 3);
  assert.deepEqual(Object.keys((await loadSettings(shell.user)).profiles), ['B']);
  const stateFile = JSON.parse(await readFile(path.join(shell.user, 'window-state.json'), 'utf8'));
  assert.deepEqual(Object.keys(stateFile.workspaces), ['B']);
});

test('安装版用与快捷方式一致的标识，沿用便携资料时支持原分区且关闭便携更新入口', windows, async t => {
  const shell = await start(t, { config: policy }, { port: null, installed: 'reuse' });
  assert.equal(shell.app.appId, windowsAppId);
  assert.equal(shell.window.details.appId, windowsAppId);
  assert.equal(shell.dataPaths.get('userData'), path.join(shell.user, 'electron'));
  assert.equal(shell.dataPaths.get('sessionData'), path.join(shell.user, 'electron'));
  assert.deepEqual(shell.checks, []);
  assert.equal(shell.menu()[0].label, '更新策略无效，检查已暂停');
});

test('安装版使用自己的签名更新源及状态目录，沿用账号资料时也不会进入便携源', windows, async t => {
  const shell = await start(t, { config: setupPolicy }, { installed: 'reuse' });
  await until(() => shell.menu()[0].label === '发现更新 0.5.2');
  assert.deepEqual(shell.requests, [setupFeed]);
  const stateFile = path.join(shell.installedRoot, 'update-state', 'win32-x64-stable-setup.json');
  assert.equal(JSON.parse(await readFile(stateFile, 'utf8')).version, '0.5.2');
  await assert.rejects(readFile(path.join(shell.user, 'update-state', 'win32-x64-stable.json')), { code: 'ENOENT' });
  shell.app.emit('second-instance');
  await until(() => shell.requests.length === 2);
  assert.deepEqual(shell.requests, [setupFeed, setupFeed]);
});

test('安装版首次选择现有资料后保存位置并等待重启，不启动网页窗口', windows, async t => {
  const shell = await start(t, null, { port: null, installed: 'choose', decisions: [1] });
  assert.equal(shell.app.relaunched, true);
  assert.equal(shell.window, undefined);
  assert.deepEqual(readInstalledChoice(shell.installedRoot), { kind: 'portable', root: shell.user });
});

test('A 和 B 分别打开共享邮箱标签，第二个邮箱拥有独立分区，旧邮箱继续用原分区', windows, async t => {
  const shell = await start(t, null, { fakePages: true, decisions: [1] });
  const first = { name: '工作邮箱', address: 'work@example.test', url: 'https://mail.example.test/' };
  await shell.send({ type: 'open', destination: 'mail' });
  const legacyTab = shell.state().active;
  await until(() => shell.pages.some(view => view.webContents.session.id === 'A'));
  await shell.send({ type: 'mailboxes', open: true });
  assert.equal(await shell.send({ type: 'mailbox-add', owner: 'A', mailbox: first }), undefined);
  const [firstId] = Object.keys(shell.state().settings.mailboxes);
  const aTab = shell.state().active;
  assert.notEqual(aTab, legacyTab);
  await until(() => shell.pages.some(view => view.webContents.url === first.url));
  const aView = shell.pages.find(view => view.webContents.url === first.url);
  await shell.send({ type: 'navigate', url: 'https://mail.example.test/message-a' });
  await until(() => aView.webContents.url.endsWith('/message-a'));
  await shell.send({ type: 'account', id: 'B' });
  assert.match(await shell.send({ type: 'mailbox-open', owner: 'A', id: firstId }), /失效/);
  await shell.send({ type: 'mailbox-open', owner: 'B', id: firstId });
  const bTab = shell.state().active;
  await until(() => shell.pages.some(view => view !== aView && view.webContents.url === first.url));
  const bView = shell.pages.find(view => view !== aView && view.webContents.url === first.url);
  assert.notEqual(aTab, bTab);
  assert.equal(aView.webContents.session, bView.webContents.session);
  assert.equal(bView.webContents.session.id, 'mailbox:' + firstId);
  assert.match(aView.webContents.url, /message-a$/);
  await shell.send({ type: 'mailbox-open', owner: 'B', id: firstId });
  assert.equal(shell.state().active, bTab);
  assert.equal(shell.state().tabs.filter(tab => tab.mailboxId === firstId).length, 1);
  await shell.send({ type: 'mailboxes', open: true });
  const second = { name: '个人邮箱', address: 'personal@example.test', url: 'https://mail.example.test/' };
  await shell.send({ type: 'mailbox-add', owner: 'B', mailbox: second });
  const secondId = shell.state().tabs.find(tab => tab.id === shell.state().active).mailboxId;
  await until(() => shell.pages.some(view => view.webContents.session.id === 'mailbox:' + secondId));
  assert.notEqual(firstId, secondId);
  assert.equal(await shell.send({ type: 'account-clear', id: 'A' }), undefined);
  assert.equal(bView.webContents.destroyed, false);
  await shell.send({ type: 'account', id: 'A' });
  await shell.send({ type: 'close', id: aTab });
  await shell.send({ type: 'restore' });
  assert.equal(shell.state().active, aTab);
  const restored = loadState(shell.user, ['A','B'], (await loadSettings(shell.user)).mailboxes);
  assert.equal(restored.workspaces.A.tabs.find(tab => tab.id === legacyTab).mailboxId, undefined);
  assert.equal(restored.workspaces.A.tabs.find(tab => tab.id === aTab).mailboxId, firstId);
  assert.equal(restored.workspaces.B.tabs.find(tab => tab.id === bTab).mailboxId, firstId);
  assert.notEqual(aView.webContents.session, shell.pages.find(view => view.webContents.session.id === 'A').webContents.session);
});

test('邮箱 Claude 链接只在明确确认的账号打开一次，取消和切号作废旧选择，地址不进入壳和恢复文件', windows, async t => {
  const mailboxId = 'eeef9159-99f8-4fc5-aa8d-4562419419a1';
  const mailbox = { name: '工作邮箱', address: 'example@example.test', url: 'https://mail.example.test/' };
  const shell = await start(t, null, { fakePages: true, savedSettings: { ...defaults, mailboxes: { [mailboxId]: mailbox } } });
  await shell.send({ type: 'mailbox-open', owner: 'A', id: mailboxId });
  const aMail = shell.state().active;
  await until(() => shell.pages[0]?.webContents.url === mailbox.url);
  const mail = shell.pages[0].webContents;
  const url = 'https://claude.ai/synthetic-private-path?token=synthetic-private-value#test';
  const open = (link, options = {}) => mail.open({ url: link, disposition: 'foreground-tab', ...options });
  assert.equal(open('https://accounts.google.com/signin', { disposition: 'new-window' }).overrideBrowserWindowOptions.webPreferences.session, mail.session);
  assert.deepEqual(open(url, { postBody: { data: [] } }), { action: 'deny' });
  assert.equal(shell.state().claudeLink, undefined);
  assert.deepEqual(open(url), { action: 'deny' });
  await until(() => shell.state().claudeLink);
  const first = shell.state().claudeLink;
  assert.deepEqual(Object.keys(first).sort(), ['id', 'source']);
  assert.equal(first.source, 'A');
  assert.equal(mail.url, mailbox.url);
  await shell.send({ type: 'claude-link', id: first.id });
  assert.equal(shell.state().claudeLink, undefined);
  assert.equal(shell.state().active, aMail);
  assert.equal(shell.pages.some(view => view.webContents.url === url), false);
  mail.requestLink(url);
  await until(() => shell.state().claudeLink);
  const stale = shell.state().claudeLink.id;
  await shell.send({ type: 'account', id: 'B' });
  await shell.send({ type: 'claude-link', id: stale, target: 'B' });
  assert.equal(shell.pages.some(view => view.webContents.url === url), false);
  await shell.send({ type: 'account', id: 'A' });
  mail.requestLink(url);
  await until(() => shell.state().claudeLink);
  const current = shell.state().claudeLink.id;
  await shell.send({ type: 'claude-link', id: current, target: 'B' });
  await shell.send({ type: 'claude-link', id: current, target: 'A' });
  await until(() => shell.pages.some(view => view.webContents.url === url));
  assert.equal(shell.state().account, 'B');
  assert.deepEqual(shell.pages.filter(view => view.webContents.url === url).map(view => view.webContents.session.id), ['B']);
  assert.doesNotMatch(JSON.stringify(shell.state()), /synthetic-private/);
  const file = path.join(shell.user, 'window-state.json');
  assert.doesNotMatch(await readFile(file, 'utf8'), /synthetic-private/);
  await shell.send({ type: 'account', id: 'A' });
  assert.equal(shell.state().active, aMail);
  assert.equal(mail.url, mailbox.url);
  mail.requestLink(url + '-a');
  await until(() => shell.state().claudeLink);
  await shell.send({ type: 'claude-link', id: shell.state().claudeLink.id, target: 'A' });
  await until(() => shell.pages.some(view => view.webContents.url === url + '-a'));
  assert.equal(shell.state().account, 'A');
  assert.deepEqual(shell.pages.filter(view => view.webContents.url === url + '-a').map(view => view.webContents.session.id), ['A']);
});
