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
import { defaults } from '../settings.mjs';
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

async function until(condition) {
  for (let pass = 0; pass < 100; pass++) {
    if (condition()) return;
    await setTimeout(10);
  }
  assert.fail('main process did not publish the expected state');
}

async function start(t, release, { port = 30202, decisions = [], failClear, fakePages = false,
  platform = process.platform, arch = process.arch, manifest = envelope } = {}) {
  const parent = path.resolve(tmpdir());
  const root = await mkdtemp(path.join(parent, 'claude-production-shell-'));
  let dispose = async () => {};
  t.after(async () => {
    await dispose();
    assert.equal(path.dirname(root), parent);
    assert.match(path.basename(root), /^claude-production-shell-/);
    await rm(root, { recursive: true, force: true });
  });
  const appData = path.join(root, 'Application Support');
  const user = platform === 'darwin' ? path.join(appData, 'Claude Browser') : path.join(root, '.browser-local');
  await mkdir(user, { recursive: true });
  await writeFile(path.join(user, 'settings.json'), JSON.stringify({ ...defaults, port }));
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
    getVersion: () => '0.5.0', whenReady: async () => {}, getPath(key) { assert.equal(key, 'appData'); return appData; },
    setPath: (key, value) => dataPaths.set(key, value),
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
        async fetch(url) { requests.push(url); return new Response(manifest); }
      };
    }
  };
  class Window extends EventEmitter {
    constructor(options) {
      super();
      this.options = options;
      currentWindow = this;
      this.webContents = Object.assign(new EventEmitter(), { setWindowOpenHandler() {}, send() {} });
      this.contentView = { addChildView: view => attached.add(view), removeChildView: view => attached.delete(view) };
    }
    getContentSize() { return [900, 650]; }
    isFullScreen() { return false; }
    setTitle() {}
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
      async showMessageBox(_parent, options) {
        prompts.push(options);
        return { response: decisions.shift() ?? 0 };
      }
    }
  };
  const source = fileURLToPath(new URL('../shell/main.ts', import.meta.url));
  const { outputFiles } = await build({
    entryPoints: [source], bundle: true, platform: 'node', format: 'cjs', write: false, logLevel: 'silent',
    external: ['electron'], define: { __DESKTOP_RELEASE__: JSON.stringify(release) },
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
          ' async prepare(){return true;}',
          ' async disconnect(id){this.spaces.delete(id);}',
          ' close(){this.spaces.clear();}',
          '}'
        ].join('\n') }));
      }
    } }]
  });
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
    if (previous === undefined) delete process.env.PORTABLE_EXECUTABLE_DIR;
    else process.env.PORTABLE_EXECUTABLE_DIR = previous;
    if (previousOverride === undefined) delete process.env.CLAUDE_BROWSER_DATA_DIR;
    else process.env.CLAUDE_BROWSER_DATA_DIR = previousOverride;
  };
  const nativeRequire = createRequire(import.meta.url);
  const module = { exports: {} };
  const runtime = Object.create(process, { platform: { value: platform }, arch: { value: arch } });
  new Function('require', 'module', 'exports', '__dirname', 'process', outputFiles[0].text)(
    id => id === 'electron' ? electron : nativeRequire(id), module, module.exports, path.dirname(source), runtime
  );
  await until(() => currentWindow?.webContents.mainFrame);
  const trusted = () => ({ sender: currentWindow.webContents, senderFrame: currentWindow.webContents.mainFrame });
  return {
    app, power: electron.powerMonitor, checks, requests, dataPaths, user, handlers,
    window: currentWindow, appMenu: () => menu, menu: () => menu.find(item => item.label === '更新').submenu, proxy: () => proxy,
    send: command => handlers.get('shell:command')(trusted(), command),
    state: () => handlers.get('shell:read')(trusted()),
    clear, prompts, pages, attached
  };
}

const windows = { skip: process.platform !== 'win32' || process.arch !== 'x64' };

test('macOS 主入口使用 Application Support 和原生窗口，保留账号配置与菜单', async t => {
  const shell = await start(t, null, { platform: 'darwin', port: null });
  assert.equal(shell.dataPaths.get('userData'), path.join(shell.user, 'electron'));
  assert.equal(shell.state().platform, 'darwin');
  assert.deepEqual(Object.keys(shell.state().settings.profiles), ['A', 'B']);
  assert.equal(shell.window.options.autoHideMenuBar, false);
  assert.equal(Object.hasOwn(shell.window.options, 'titleBarOverlay'), false);
  assert.equal(shell.appMenu()[0].role, 'appMenu');
  assert.equal(shell.appMenu().find(item => item.label === '标签页').submenu[0].accelerator, 'CommandOrControl+T');
  assert.equal(shell.menu()[0].label, '未配置生产更新源');
});

test('macOS 双架构主入口各查签名清单，常规恢复不重查，退出安装入口保持关闭', async t => {
  for (const arch of ['arm64', 'x64']) {
    await t.test(arch, async t => {
      const feed = `https://manifest.example.test/darwin-${arch}.json`;
      const config = { ...policy, targets: {
        [`darwin-${arch}`]: { feed, assets: [base], minSequence: 10, teamId: 'A1B2C3D4E5' }
      } };
      const manifest = signReleaseManifest({
        schema: 1, product, channel: 'stable', platform: 'darwin', arch,
        version: '0.5.1', sequence: 10, expiresAt: Date.now() + 600_000,
        size: 1, sha256: sha256(Buffer.from([1])), url: base + `ClaudeBrowser-${arch}.zip`
      }, privateKey);
      const shell = await start(t, { config }, { platform: 'darwin', arch, manifest });
      await until(() => shell.menu()[0].label === '发现更新 0.5.1');
      assert.equal(shell.dataPaths.get('userData'), path.join(shell.user, 'electron'));
      assert.deepEqual(shell.requests, [feed]);
      assert.equal(shell.proxy().proxyRules, 'http://127.0.0.1:43210');
      assert.ok(shell.menu().some(item => item.label === 'macOS 应用内下载暂未启用' && item.enabled === false));
      assert.ok(!shell.menu().some(item => typeof item.click === 'function' && /下载|安装/.test(item.label)));
      shell.power.emit('resume');
      shell.window.focus();
      assert.deepEqual(shell.requests, [feed]);
      shell.app.emit('second-instance');
      await until(() => shell.requests.length === 2 && shell.menu()[0].label === '发现更新 0.5.1');
      assert.deepEqual(shell.requests, [feed, feed]);
    });
  }
});

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
