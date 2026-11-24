import path from 'node:path';
import { existsSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { app, BrowserWindow, dialog, ipcMain, Menu, powerMonitor, screen, session, WebContentsView } from 'electron';
import type { IpcMainInvokeEvent, MenuItemConstructorOptions, WebContents } from 'electron';
import { addProfile, checkPort, checkProfile, loadSettings, moveProfile, removeProfile, saveSettings } from '../settings.mjs';
import { effectiveMailbox } from '../preferences.mjs';
import { detectWindowsProxyPort } from './proxy-detection';
import { AccountNetwork, securePreferences } from './network';
import { address, environmentWidth, home, linkedTabMode, maxTabs, profileName, restorableURL, webURL } from './model';
import { configuredPageEnvironment, decodePageEnvironment } from './environment';
import type { Account, Command, Destination, Page, PageEnvironment, Profile, Saved, Settings, SettingsPanelKind, ShellState, Tab } from './model';
import { initialWorkspace, insertLinkedTab, loadState, makeTab, saveState } from './state';
import { cacheablePageURL, ClosedPages } from './closed-pages';
import { createProductionUpdates } from './production-updates';
import type { ProductionUpdates } from './production-updates';
import { choosePortableDirectory, installedMarker, readInstalledChoice, saveInstalledChoice, windowsTaskbarDetails } from './windows-edition';

declare const __DESKTOP_RELEASE__: unknown;

const topHeight = 44;
const shellHeight = 92;
const html = path.join(__dirname, 'index.html');
const shellURL = pathToFileURL(html).href;
const emptyPage = path.join(__dirname, 'profile-empty.html');
const appIcon = path.join(__dirname, 'icon.png');
const windowsPackage = process.platform === 'win32' && app.isPackaged;
const installedEdition = windowsPackage && typeof process.resourcesPath === 'string' &&
  existsSync(path.join(process.resourcesPath, installedMarker));
const installDir = process.env.PORTABLE_EXECUTABLE_DIR ||
  (app.isPackaged ? path.dirname(process.execPath) : app.getAppPath());
const productionBuild = app.isPackaged && typeof __DESKTOP_RELEASE__ !== 'undefined' && __DESKTOP_RELEASE__ !== null;
const dataOverride = productionBuild ? undefined : process.env.CLAUDE_BROWSER_DATA_DIR;
const taskbar = windowsTaskbarDetails(installedEdition ? 'installed' : 'portable',
  installedEdition ? process.execPath : process.env.PORTABLE_EXECUTABLE_FILE);
let root: string;
for (const [name, value] of [
  ['disable-quic', ''], ['disable-background-networking', ''], ['no-pings', ''],
  ['force-webrtc-ip-handling-policy', 'disable_non_proxied_udp'],
  ['host-resolver-rules', 'MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']
]) app.commandLine.appendSwitch(name, value);
app.enableSandbox();

type Space = Awaited<ReturnType<AccountNetwork['connect']>>;
type LiveTab = {
  account: Account;
  space: Space;
  view: WebContentsView;
  cachedMute?: boolean;
  page: Page;
  requested?: string;
  startingNativeNavigation?: boolean;
  environment?: { reading?: PageEnvironment };
};

let win: BrowserWindow | undefined;
let productionUpdates: ProductionUpdates | undefined;
let updatePolicyInvalid = false;
let settings: Settings;
let saved: Saved;
let account: Account = 'A';
let resettingAccount: Account | undefined;
let panel: SettingsPanelKind = null;
let environmentOpen = false;
let notice: string | undefined;
let closing = false;
let queued: Promise<unknown> = Promise.resolve();

const network = new AccountNetwork(publish);
const live = new Map<string, LiveTab>();
const closedPages = new ClosedPages(closeView);
const pending = new Map<string, Promise<LiveTab | undefined>>();
const failures = new Map<string, string>();
const popups = new Map<BrowserWindow, { account: Account; sourceTabId: string; ready: boolean }>();

const workspace = (id = account) => saved.workspaces[id];
const accountLabel = (id = account) => profileName(id, settings.profiles[id]);

function knownAccount(id: unknown): Account {
  if (typeof id !== 'string' || !Object.hasOwn(settings.profiles, id)) throw new Error('无效的账号。');
  return id;
}
const selected = () => workspace().tabs.find(tab => tab.id === workspace().active)!;
const tabById = (id: string) => {
  const tab = workspace().tabs.find(candidate => candidate.id === id);
  if (!tab) throw new Error('标签不属于当前账户。');
  return tab;
};

function environmentVisible(): boolean {
  return environmentOpen && !panel;
}

function activeEnvironment(): ShellState['environment'] {
  if (!environmentVisible()) return;
  const entry = live.get(workspace().active);
  const reading = entry && !entry.page.error ? entry.environment?.reading : undefined;
  return {
    ...(reading ?? configuredPageEnvironment(
      settings.profiles[account], app.getPreferredSystemLanguages(), Intl.DateTimeFormat().resolvedOptions().timeZone
    )),
    source: reading ? 'page' : 'settings',
    exit: network.exits.read(account)
  };
}

function snapshot(): ShellState {
  const space = workspace();
  return {
    account, active: space.active, canRestore: space.closed.length > 0,
    tabs: space.tabs.map(tab => ({
      ...tab, ...live.get(tab.id)?.page, url: live.get(tab.id)?.page.url ?? tab.url, error: failures.get(tab.id) ?? live.get(tab.id)?.page.error
    })),
    settings, status: network.status(account, settings.port), panel, environment: activeEnvironment(),
    fullscreen: win?.isFullScreen() ?? false, notice
  };
}

function layout(): void {
  if (!win || win.isDestroyed() || !saved) return;
  const [width, height] = win.getContentSize();
  for (const [id, entry] of live) {
    if (closedPages.has(id)) {
      if (!network.canReuse(entry.account, entry.space)) closedPages.discard(id);
      continue;
    }
    entry.view.setVisible(!panel && id === workspace().active && !!entry.requested &&
      !entry.startingNativeNavigation && !entry.page.error && !failures.has(id));
    if (id === workspace().active) {
      const pageWidth = width - (environmentVisible() ? environmentWidth : 0);
      entry.view.setBounds({ x: 0, y: shellHeight, width: Math.max(pageWidth, 1), height: Math.max(height - shellHeight, 1) });
    }
  }
  for (const [popup, info] of popups) {
    if (popup.isDestroyed()) continue;
    if (info.account !== account && popup.isVisible()) popup.hide();
    if (info.account === account && info.ready && !popup.isVisible()) popup.showInactive();
  }
}

function readActivePageEnvironment(): void {
  if (!environmentVisible()) return;
  const tabId = workspace().active;
  const entry = live.get(tabId);
  if (!entry?.requested || entry.startingNativeNavigation || entry.environment || entry.page.loading || entry.page.error) return;
  const contents = entry.view.webContents;
  if (contents.isDestroyed() || contents.isLoadingMainFrame() || !webURL(contents.getURL())) return;

  const attempt: NonNullable<LiveTab['environment']> = {};
  entry.environment = attempt;
  // Read native preferences in a separate world without trusting the remote page's JavaScript.
  void contents.executeJavaScriptInIsolatedWorld(1001, [{
    code: '({ language: navigator.language, zone: Intl.DateTimeFormat().resolvedOptions().timeZone })'
  }]).then((raw: unknown) => {
    if (live.get(tabId) !== entry || entry.environment !== attempt || contents.isDestroyed()) return;
    attempt.reading = decodePageEnvironment(raw);
    if (attempt.reading && account === entry.account && workspace().active === tabId && environmentVisible()) publish();
  }).catch(() => {});
}

function publish(): void {
  if (!win || win.isDestroyed() || closing) return;
  layout();
  win.webContents.send('shell:state', snapshot());
  readActivePageEnvironment();
}

function persist(): void {
  try {
    saveState(root, saved);
  } catch {
    notice = '无法保存标签和窗口状态。请检查应用目录的写入权限。';
  }
}

function prepareUpdateExit(): Promise<void> {
  return serialize(async () => {
    if (!win || win.isDestroyed() || closing) throw new Error('应用窗口已经开始关闭。');
    saved.bounds = { ...win.getNormalBounds(), maximized: win.isMaximized() };
    saveState(root, saved);
    await network.flushStorage();
    if (closing) throw new Error('应用窗口已经开始关闭。');
  });
}

function serialize<T>(run: () => Promise<T> | T): Promise<T> {
  const result = queued.then(run);
  queued = result.catch(() => {});
  return result;
}

function notify(message: string): void {
  notice = message;
  publish();
}

function navControls(contents: WebContents): MenuItemConstructorOptions[] {
  return [
    { label: '后退', enabled: contents.navigationHistory.canGoBack(), click: () => contents.navigationHistory.goBack() },
    { label: '前进', enabled: contents.navigationHistory.canGoForward(), click: () => contents.navigationHistory.goForward() },
    { label: '重新加载', click: () => contents.reload() }
  ];
}

function configureRemote(contents: WebContents, owner: Account, space: Space, sourceTabId: string): void {
  contents.on('will-navigate', (event) => {
    if (closedPages.has(sourceTabId) || resettingAccount === owner) {
      event.preventDefault();
      closedPages.discard(sourceTabId);
      return;
    }
    if (!webURL(event.url) && event.url !== 'about:blank') {
      event.preventDefault();
      if (account === owner) notify('已拦截这个链接使用的协议。');
    }
  });
  contents.on('will-redirect', (event) => {
    if (event.isMainFrame && (closedPages.has(sourceTabId) || resettingAccount === owner)) {
      event.preventDefault();
      closedPages.discard(sourceTabId);
      return;
    }
    if (event.isMainFrame && !webURL(event.url)) {
      event.preventDefault();
      if (account === owner) notify('已拦截这个重定向使用的协议。');
    }
  });
  contents.on('will-attach-webview', event => event.preventDefault());
  contents.on('context-menu', (_event, params) => {
    const focused = BrowserWindow.getFocusedWindow() ?? win;
    if (!focused || focused.isDestroyed()) return;
    const items: MenuItemConstructorOptions[] = [];
    const target = webURL(params.linkURL);
    if (target) {
      items.push({ label: '在新标签打开链接', click: () => addFromPage(owner, target.href) });
      items.push({ type: 'separator' });
    }
    if (params.isEditable) items.push({ role: 'cut' }, { role: 'copy' }, { role: 'paste' });
    else if (params.selectionText) items.push({ role: 'copy' });
    if (items.length && items.at(-1)?.type !== 'separator') items.push({ type: 'separator' });
    items.push(...navControls(contents));
    Menu.buildFromTemplate(items).popup({ window: focused });
  });

  contents.setWindowOpenHandler(details => {
    const target = webURL(details.url);
    if (!win || closing || closedPages.has(sourceTabId) || resettingAccount === owner || !Object.hasOwn(settings.profiles, owner) ||
        contents.session !== space.session || (!target && details.url !== 'about:blank')) {
      return { action: 'deny' };
    }
    const mode = linkedTabMode(details.disposition);
    if (mode) {
      if (workspace(owner).tabs.length >= maxTabs) {
        if (owner === account) notify('标签页已达上限，请先关闭不需要的标签。');
        return { action: 'deny' };
      }
      return {
        action: 'allow',
        outlivesOpener: true,
        overrideBrowserWindowOptions: { webPreferences: network.webPreferences(space) },
        createWindow(options) {
          // Electron also supplies webContents at runtime for this callback.
          const { webContents: guest } = options as typeof options & { webContents: WebContents };
          return adoptLinkedTab(owner, sourceTabId, guest, space, details.url, mode === 'foreground');
        }
      };
    }
    if (popups.size >= 16) {
      if (account === owner) notify('窗口数量已达上限，请先关闭不用的登录窗口。');
      return { action: 'deny' };
    }
    return {
      action: 'allow',
      overrideBrowserWindowOptions: {
        parent: win, modal: false, show: false, frame: true, autoHideMenuBar: true,
        width: 620, height: 760, minWidth: 420, minHeight: 480,
        title: accountLabel(owner) + ' · 网页窗口', icon: appIcon, webPreferences: network.webPreferences(space)
      },
      createWindow(options) {
        // options.webContents carries Chromium's original guest and its opener.
        const popup = new BrowserWindow(options);
        const guest = popup.webContents;
        const info = { account: owner, sourceTabId, ready: false };
        popups.set(popup, info);
        popup.setMenu(null);
        configureRemote(guest, owner, space, sourceTabId);
        guest.on('before-input-event', (event, input) => {
          if (input.type === 'keyDown' && input.control && input.key.toLowerCase() === 'w') {
            event.preventDefault();
            popup.close();
          }
        });
        popup.on('page-title-updated', event => {
          event.preventDefault();
          popup.setTitle(accountLabel(owner) + ' · ' + (webURL(guest.getURL())?.host || '网页窗口'));
        });
        guest.on('did-fail-load', (_event, code, description, _url, mainFrame) => {
          if (mainFrame && code !== -3 && account === owner) notify('弹窗加载失败（' + description + '）。');
        });
        popup.once('closed', () => popups.delete(popup));
        void network.preparePopup(guest, space).then(failure => {
          if (popup.isDestroyed()) return;
          if (failure) {
            popup.destroy();
            if (account === owner) notify('无法打开网页弹窗（' + failure + '）。请从原页面重试。');
            return;
          }
          info.ready = true;
          if (owner === account) popup.show();
        });
        return guest;
      }
    };
  });
}

function addFromPage(owner: Account, url: string): void {
  void serialize(() => {
    if (!closing && resettingAccount !== owner && Object.hasOwn(settings.profiles, owner)) {
      addTab(owner, url, undefined, account === owner);
    }
  }).catch(error => {
    if (account === owner) notify(error.message);
  });
}

function constructTab(owner: Account, tab: Tab, space: Space, guest?: WebContents): LiveTab {
  const view = new WebContentsView(guest ? { webContents: guest } : { webPreferences: network.webPreferences(space) });
  const contents = view.webContents;
  view.setVisible(false);
  view.setBackgroundColor('#ffffff');
  win!.contentView.addChildView(view);
  const entry: LiveTab = { account: owner, space, view, page: {} };
  live.set(tab.id, entry);
  configureRemote(contents, owner, space, tab.id);
  function update(patch: Page = {}): void {
    if (live.get(tab.id) !== entry || contents.isDestroyed()) return;
    const url = webURL(contents.getURL())?.href;
    Object.assign(entry.page, patch, {
      url, back: contents.navigationHistory.canGoBack(), forward: contents.navigationHistory.canGoForward()
    });
    publish();
  }
  function navigated(url: string): void {
    if (live.get(tab.id) !== entry || contents.isDestroyed()) return;
    const clean = restorableURL(url);
    if (clean && clean !== tab.url) {
      tab.url = clean;
      persist();
    }
    update({ error: undefined });
  }
  contents.on('did-start-navigation', event => {
    if (event.isMainFrame && closedPages.has(tab.id)) {
      closedPages.discard(tab.id);
      return;
    }
    if (event.isMainFrame && !event.isSameDocument) entry.environment = undefined;
  });
  contents.on('did-start-loading', () => update({ loading: true, error: undefined }));
  contents.on('did-stop-loading', () => update({ loading: false }));
  contents.on('page-title-updated', (_event, title) => update({
    title: title.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 180)
  }));
  contents.on('did-navigate', (_event, url) => navigated(url));
  contents.on('did-navigate-in-page', (_event, url, mainFrame) => { if (mainFrame) navigated(url); });
  contents.on('did-fail-load', (_event, code, description, _url, mainFrame) => {
    if (mainFrame && code !== -3) update({ loading: false, error: '网页加载失败（' + description + '）。' });
  });
  contents.on('render-process-gone', () => {
    if (closedPages.has(tab.id)) closedPages.discard(tab.id);
    else update({ loading: false, error: '网页进程已退出，请重试。' });
  });
  contents.once('destroyed', () => closedPages.discard(tab.id));
  return entry;
}

function adoptLinkedTab(owner: Account, sourceTabId: string, guest: WebContents, space: Space,
  url: string, foreground: boolean): WebContents {
  const work = workspace(owner);
  const tab = makeTab(restorableURL(url) ?? home);
  const entry = constructTab(owner, tab, space, guest);
  // Chromium owns the first navigation, including its initiator and any POST body.
  entry.requested = url;
  entry.startingNativeNavigation = true;
  entry.page = { loading: true, url };

  insertLinkedTab(work, tab, sourceTabId);
  if (foreground && owner === account) {
    work.active = tab.id;
    panel = null;
  }
  guest.once('destroyed', () => {
    void serialize(() => {
      if (!closing && live.get(tab.id) === entry) closeTab(tab.id, owner);
    }).catch(error => {
      if (owner === account) notify(error.message);
    });
  });
  void network.preparePopup(guest, space).then(failure => {
    if (live.get(tab.id) !== entry || guest.isDestroyed() || closing) return;
    if (failure) {
      closeView(tab.id);
      failures.set(tab.id, '无法初始化新标签（' + failure + '）。请从原页面重新打开。');
      publish();
      return;
    }
    entry.startingNativeNavigation = false;
    entry.page.loading = guest.isLoadingMainFrame();
    publish();
    if (owner === account && work.active === tab.id && !panel && !entry.page.error) guest.focus();
  });
  persist();
  publish();
  return guest;
}

function mount(owner: Account, tab: Tab): Promise<LiveTab | undefined> {
  const opening = pending.get(tab.id);
  if (opening) return opening;
  const existing = live.get(tab.id);
  if (existing && !existing.view.webContents.isDestroyed()) return Promise.resolve(existing);
  if (!settings.port || closing || resettingAccount === owner) return Promise.resolve(undefined);
  failures.delete(tab.id);

  const task = network.connect(owner, settings.port, settings.profiles[owner]).then(async space => {
    if (pending.get(tab.id) !== task || closing) return;
    const entry = constructTab(owner, tab, space);
    const ok = await network.prepare(entry.view.webContents, space, emptyPage);
    if (pending.get(tab.id) !== task || closing) return;
    if (!ok) {
      closeView(tab.id);
      failures.set(tab.id, '无法初始化网页的账户语言和时区。请重试或检查时区设置。');
      return;
    }
    return entry;
  }).catch(() => {
    if (pending.get(tab.id) === task && !closing)
      failures.set(tab.id, '无法连接本地代理。请检查端口并重试。');
    return undefined;
  }).finally(() => {
    if (pending.get(tab.id) === task) pending.delete(tab.id);
    publish();
  });
  pending.set(tab.id, task);
  return task;
}

function load(entry: LiveTab, url: string): void {
  const contents = entry.view.webContents;
  if (contents.isDestroyed()) return;
  entry.requested = url;
  entry.environment = undefined;
  entry.page.error = undefined;
  entry.page.loading = true;
  entry.page.url = url;
  publish();
  void contents.loadURL(url).catch(error => {
    if (!contents.isDestroyed() && entry.requested === url && error.code !== 'ERR_ABORTED') {
      entry.page.loading = false;
      entry.page.error ||= '网页未能打开。请检查代理和网页地址后重试。';
      publish();
    }
  });
}

function showTab(owner = account, tab = selected(), target?: string, focus = true): void {
  publish();
  void mount(owner, tab).then(entry => {
    if (!entry || closing || (owner !== account || tab.id !== workspace().active)) return;
    if (target || !entry.requested) load(entry, target ?? tab.url);
    if (focus && !panel && !entry.startingNativeNavigation && !entry.page.error && !entry.view.webContents.isDestroyed()) {
      entry.view.webContents.focus();
    }
  });
}

function closeView(id: string): void {
  closedPages.forget(id);
  pending.delete(id);
  failures.delete(id);
  const entry = live.get(id);
  if (!entry) return;
  live.delete(id);
  if (win && !win.isDestroyed() && entry.cachedMute === undefined) win.contentView.removeChildView(entry.view);
  if (!entry.view.webContents.isDestroyed()) entry.view.webContents.close({ waitForBeforeUnload: false });
}

function addTab(owner: Account, url = home, destination?: Destination, activate = true): void {
  const space = workspace(owner);
  if (space.tabs.length >= maxTabs) throw new Error('标签页已达上限，请先关闭不需要的标签。');
  const tab = makeTab(url, destination);
  space.tabs.push(tab);
  if (activate) {
    space.active = tab.id;
    panel = null;
  }
  persist();
  if (activate) showTab(owner, tab);
  else publish();
}

function openDestination(destination: Destination): void {
  if (destination !== 'claude' && destination !== 'mail') throw new Error('无效的网页入口。');
  const target = destination === 'claude' ? home : effectiveMailbox(settings.profiles[account].mail);
  const tab = workspace().tabs.find(item => item.destination === destination);
  if (!tab) {
    addTab(account, target, destination);
    return;
  }
  const current = live.get(tab.id)?.page.url ?? tab.url;
  const useTarget = webURL(current)?.origin !== webURL(target)?.origin ||
    (destination === 'mail' && !current.startsWith(target) && !live.has(tab.id));
  if (useTarget) tab.url = target;
  workspace().active = tab.id;
  panel = null;
  persist();
  showTab(account, tab, useTarget ? target : undefined);
}

function closeTab(id: string, owner = account): void {
  const space = workspace(owner);
  const index = space.tabs.findIndex(tab => tab.id === id);
  if (index < 0) throw new Error('标签不属于当前账户。');
  const tab = space.tabs[index];
  const entry = live.get(id);
  const contents = entry?.view.webContents;
  const retain = win && !win.isDestroyed() && entry?.requested && !pending.has(id) &&
    !entry.startingNativeNavigation && !entry.page.error && !failures.has(id) && contents &&
    !contents.isDestroyed() && !contents.isLoadingMainFrame() && cacheablePageURL(contents.getURL()) &&
    network.canReuse(owner, entry.space) && ![...popups.values()].some(info => info.sourceTabId === id);
  space.tabs.splice(index, 1);
  space.closed = [tab, ...space.closed].slice(0, 12);
  if (retain && entry && contents && win) {
    entry.view.setVisible(false);
    entry.cachedMute = contents.isAudioMuted();
    contents.setAudioMuted(true);
    win.contentView.removeChildView(entry.view);
    closedPages.remember(id, owner);
  } else closeView(id);
  if (!space.tabs.length) space.tabs.push(makeTab(home, 'claude'));
  if (space.active === id) space.active = space.tabs[Math.min(index, space.tabs.length - 1)].id;
  persist();
  if (owner === account) showTab();
  else publish();
}

function restoreTab(): void {
  const space = workspace();
  if (space.tabs.length >= maxTabs) throw new Error('标签页已达上限，请先关闭不需要的标签。');
  const tab = space.closed.shift();
  if (!tab) return;
  if (closedPages.take(tab.id, account)) {
    const entry = live.get(tab.id);
    const contents = entry?.view.webContents;
    if (win && entry?.cachedMute !== undefined && contents && !contents.isDestroyed() &&
        !contents.isLoadingMainFrame() && cacheablePageURL(contents.getURL()) && network.canReuse(account, entry.space)) {
      win.contentView.addChildView(entry.view);
      contents.setAudioMuted(entry.cachedMute);
      entry.cachedMute = undefined;
    } else closeView(tab.id);
  }
  space.tabs.push(tab);
  sortTabs();
  space.active = tab.id;
  panel = null;
  persist();
  showTab();
}

function sortTabs(): void {
  workspace().tabs.sort((a, b) => Number(b.pinned) - Number(a.pinned));
}

async function createAccount(draft: Profile): Promise<void> {
  const next = addProfile(settings, draft);
  await saveSettings(root, next.settings);
  if (closing) return;
  saved.workspaces[next.id] = initialWorkspace();
  settings = next.settings;
  persist();
  environmentOpen = true;
  switchAccount(next.id);
}

async function orderAccount(id: Account, direction: -1 | 1): Promise<void> {
  const next = moveProfile(settings, knownAccount(id), direction);
  if (next === settings) return;
  await saveSettings(root, next);
  settings = next;
  refreshMenu();
  publish();
}

async function closeAccountContents(id: Account): Promise<void> {
  const entries = [...live].filter(([, entry]) => entry.account === id);
  const windows = [...popups].filter(([popup, info]) => info.account === id && !popup.isDestroyed())
    .map(([popup]) => popup);
  const contents = [...entries.map(([, entry]) => entry.view.webContents), ...windows.map(popup => popup.webContents)];
  const waiting = new Map<WebContents, () => void>();
  for (const item of contents) {
    if (!item.isDestroyed()) {
      const closed = () => waiting.delete(item);
      waiting.set(item, closed);
      item.once('destroyed', closed);
    }
  }
  for (const tab of workspace(id).tabs) pending.delete(tab.id);
  try {
    for (const [tabId] of entries) closeView(tabId);
    for (const popup of windows) popup.destroy();
    for (let attempts = 0; waiting.size && attempts < 100; attempts++) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    if (waiting.size) throw new Error('账号的网页尚未退出。');
  } finally {
    for (const [item, listener] of waiting) item.removeListener('destroyed', listener);
  }
}

async function resetAccount(id: Account, remove: boolean): Promise<void> {
  knownAccount(id);
  const next = remove ? removeProfile(settings, id) : settings;
  const label = accountLabel(id);
  const action = remove ? '移除账号' : '清除本机登录';
  const { response } = await dialog.showMessageBox(win!, {
    type: 'warning', message: action + '「' + label + '」？',
    detail: '将关闭该账号的标签和弹窗，清除 Cookie、网站存储和缓存，网站本地草稿也可能丢失。' +
      (remove ? '该账号的设置和本机标签记录也会删除。' : '该账号的设置和已保存的标签地址会保留。'),
    buttons: ['取消', action], defaultId: 0, cancelId: 0, noLink: true
  });
  if (response !== 1 || closing) return;
  resettingAccount = id;
  try {
    await closeAccountContents(id);
    if (closing) return;
    await network.clearAccountData(id);
    if (remove) {
      await saveSettings(root, next);
      settings = next;
      delete saved.workspaces[id];
      if (account === id) account = Object.keys(settings.profiles)[0];
    } else {
      workspace(id).closed = [];
    }
  } catch {
    throw new Error('账号配置已保留。本机清理可能只完成了一部分，请重试。');
  } finally {
    resettingAccount = undefined;
  }
  if (closing) return;
  persist();
  panel = null;
  switchAccount(account);
  notify('已' + action + '「' + label + '」。');
}

async function updateSettings(id: Account, port: number, draft: Profile): Promise<void> {
  knownAccount(id);
  checkPort(port);
  const profile = checkProfile(draft);
  const portChanged = settings.port !== port;
  const previous = settings.profiles[id];
  const preferencesChanged = previous.language !== profile.language || previous.zone !== profile.zone;
  const affected = portChanged ? Object.keys(settings.profiles) : preferencesChanged ? [id] : [];
  const next = { port, profiles: { ...settings.profiles, [id]: profile } };
  await saveSettings(root, next);
  settings = next;
  if (portChanged) productionUpdates?.proxyChanged();
  if (previous.mail !== profile.mail && profile.mail) {
    for (const tab of [...workspace(id).tabs, ...workspace(id).closed].filter(tab => tab.destination === 'mail')) {
      tab.url = profile.mail;
      closeView(tab.id);
    }
    persist();
  }
  for (const owner of affected) {
    for (const [tabId, entry] of live) if (entry.account === owner) closeView(tabId);
    for (const tab of workspace(owner).tabs) pending.delete(tab.id);
    for (const [popup, data] of popups) if (data.account === owner) popup.destroy();
  }
  await Promise.all(affected.map(owner => network.disconnect(owner)));
  if (closing) return;
  panel = null;
  win?.setTitle(accountLabel() + ' · Claude Browser');
  refreshMenu();
  showTab();
}

function menuAction(command: Command): () => void {
  return () => {
    void serialize(() => dispatch(command)).catch(error => notify(error.message));
  };
}

function popupMenu(items: MenuItemConstructorOptions[], x?: number, y?: number): void {
  if (!win) return;
  const [width, height] = win.getContentSize();
  const coordinate = (n: number | undefined, max: number) =>
    Number.isFinite(n) ? Math.max(0, Math.min(max - 1, Math.round(n!))) : undefined;
  Menu.buildFromTemplate(items).popup({ window: win, x: coordinate(x, width), y: coordinate(y, height) });
}

function appMenu(): MenuItemConstructorOptions[] {
  return [
    { label: '标签页', submenu: [
      { label: '新建标签页', accelerator: 'Ctrl+T', click: menuAction({ type: 'new' }) },
      { label: '关闭当前标签页', accelerator: 'Ctrl+W', click: () => menuAction({ type: 'close', id: selected().id })() },
      { label: '恢复关闭的标签页', accelerator: 'Ctrl+Shift+T', click: menuAction({ type: 'restore' }) },
      { type: 'separator' },
      { label: '下一个标签页', accelerator: 'Ctrl+Tab', click: () => stepTab(1) },
      { label: '上一个标签页', accelerator: 'Ctrl+Shift+Tab', click: () => stepTab(-1) }
    ] },
    { label: '编辑', submenu: [
      { label: '撤销', role: 'undo' }, { label: '重做', role: 'redo' }, { type: 'separator' },
      { label: '剪切', role: 'cut' }, { label: '复制', role: 'copy' }, { label: '粘贴', role: 'paste' },
      { label: '全选', role: 'selectAll' }
    ] },
    { label: '浏览', submenu: [
      { label: '打开 Claude', click: menuAction({ type: 'open', destination: 'claude' }) },
      { label: '打开邮箱', click: menuAction({ type: 'open', destination: 'mail' }) },
      { label: '转到地址栏', accelerator: 'Ctrl+L', click: focusAddress },
      { label: '后退', accelerator: 'Alt+Left', click: menuAction({ type: 'back' }) },
      { label: '前进', accelerator: 'Alt+Right', click: menuAction({ type: 'forward' }) },
      { label: '重新加载', accelerator: 'Ctrl+R', click: menuAction({ type: 'reload' }) },
      { label: '强制刷新', accelerator: 'Ctrl+Shift+R', click: menuAction({ type: 'force-reload' }) }
    ] },
    { label: '账户', submenu: accountMenu() },
    productionUpdates?.menu() ?? { label: '更新', submenu: [{
      label: updatePolicyInvalid ? '更新策略无效，检查已暂停' : '未配置生产更新源', enabled: false
    }] },
    { label: '窗口', submenu: [
      { label: '最小化', role: 'minimize' },
      { label: '最大化或还原', click: () => { if (win?.isMaximized()) win.unmaximize(); else win?.maximize(); } },
      { label: '切换全屏', accelerator: 'F11', click: menuAction({ type: 'fullscreen' }) },
      { type: 'separator' },
      { label: '关闭窗口', accelerator: 'Ctrl+Shift+W', role: 'close' }
    ] }
  ];
}

function accountMenu(): MenuItemConstructorOptions[] {
  return [
    ...Object.keys(settings.profiles).map(id => ({
      label: accountLabel(id), type: 'radio' as const, checked: id === account,
      accelerator: id === 'A' ? 'Ctrl+Alt+1' : id === 'B' ? 'Ctrl+Alt+2' : undefined,
      click: menuAction({ type: 'account', id })
    })),
    { type: 'separator' },
    { label: '添加账号', accelerator: 'Ctrl+Shift+N', click: menuAction({ type: 'add-account' }) },
    { label: '账户环境', click: menuAction({ type: 'environment', open: true }) },
    { label: '账户与代理设置', click: menuAction({ type: 'settings', open: true }) }
  ];
}

function refreshMenu(): void {
  Menu.setApplicationMenu(Menu.buildFromTemplate(appMenu()));
  win?.setMenuBarVisibility(false);
}

function switchAccount(id: Account): void {
  if (!win || win.isDestroyed() || closing) return;
  account = id;
  win.setTitle(accountLabel() + ' · Claude Browser');
  panel = null;
  refreshMenu();
  showTab(id, selected(), undefined, !environmentOpen);
}

function focusAddress(): void {
  if (!win || win.isDestroyed()) return;
  win.webContents.focus();
  win.webContents.send('shell:address');
}

function stepTab(step: number): void {
  const space = workspace();
  const current = space.tabs.findIndex(tab => tab.id === space.active);
  const index = (current + step + space.tabs.length) % space.tabs.length;
  menuAction({ type: 'select', id: space.tabs[index].id })();
}

async function dispatch(command: Command): Promise<void> {
  if (closing || !win || win.isDestroyed()) return;
  const tab = selected();
  const page = live.get(tab.id)?.view.webContents;
  const history = page && !page.isDestroyed() ? page.navigationHistory : undefined;
  notice = undefined;
  switch (command.type) {
    case 'account':
      switchAccount(knownAccount(command.id));
      break;
    case 'account-order':
      await orderAccount(command.id, command.direction);
      break;
    case 'account-clear':
    case 'account-remove':
      await resetAccount(command.id, command.type === 'account-remove');
      break;
    case 'add-account':
      panel = 'add-account';
      publish();
      break;
    case 'create-account':
      if (panel !== 'add-account') throw new Error('请先打开添加账号页面。');
      await createAccount(command.profile);
      break;
    case 'environment': {
      if (typeof command.open !== 'boolean') throw new Error('无效的环境卡操作。');
      const resumePage = panel && command.open;
      environmentOpen = command.open;
      if (resumePage) {
        panel = null;
        showTab(account, tab, undefined, false);
      } else publish();
      break;
    }
    case 'check-exit':
      if (!environmentVisible() || command.id !== account) throw new Error('请在当前账户的环境卡检测出口。');
      network.checkExit(account);
      break;
    case 'settings':
      if (typeof command.open !== 'boolean') throw new Error('无效的设置操作。');
      panel = command.open ? 'settings' : null;
      publish();
      if (!panel) showTab();
      break;
    case 'save':
      await updateSettings(command.id, command.port, command.profile);
      break;
    case 'open': openDestination(command.destination); break;
    case 'new': addTab(account); break;
    case 'select':
      workspace().active = tabById(command.id).id;
      panel = null;
      persist();
      showTab();
      break;
    case 'close': closeTab(command.id); break;
    case 'restore': restoreTab(); break;
    case 'pin': {
      const item = tabById(command.id);
      item.pinned = !item.pinned;
      sortTabs();
      persist();
      publish();
      break;
    }
    case 'move': {
      const space = workspace();
      const from = tabById(command.id);
      const to = tabById(command.target);
      if (from === to || from.pinned !== to.pinned) break;
      const index = space.tabs.indexOf(to);
      space.tabs.splice(space.tabs.indexOf(from), 1);
      space.tabs.splice(index, 0, from);
      persist();
      publish();
      break;
    }
    case 'navigate': {
      const target = typeof command.url === 'string' ? address(command.url) : undefined;
      if (!target) throw new Error('请输入有效的 HTTP 或 HTTPS 地址。');
      tab.url = restorableURL(target) || tab.url;
      panel = null;
      persist();
      showTab(account, tab, target);
      break;
    }
    case 'back': if (history?.canGoBack()) history.goBack(); break;
    case 'forward': if (history?.canGoForward()) history.goForward(); break;
    case 'stop': if (history) page!.stop(); break;
    case 'force-reload':
    case 'reload': {
      const entry = live.get(tab.id);
      if (!history || !entry?.requested || entry.page.error) {
        showTab(account, tab, entry?.page.url || entry?.requested || tab.url);
      } else if (command.type === 'force-reload') page!.reloadIgnoringCache();
      else page!.reload();
      break;
    }
    case 'retry': {
      const entry = live.get(tab.id);
      const target = entry?.page.url || entry?.requested || tab.url;
      closeView(tab.id);
      showTab(account, tab, target);
      break;
    }
    case 'fullscreen': win.setFullScreen(!win.isFullScreen()); break;
    case 'tab-menu': {
      const item = tabById(command.id);
      popupMenu([
        { label: item.pinned ? '取消固定' : '固定标签', click: menuAction({ type: 'pin', id: item.id }) },
        { label: '关闭标签', click: menuAction({ type: 'close', id: item.id }) },
        { label: '恢复关闭的标签页', enabled: workspace().closed.length > 0, click: menuAction({ type: 'restore' }) }
      ]);
      break;
    }
    case 'menu': {
      const items = command.menu === 'app' ? appMenu() : command.menu === 'accounts' ? accountMenu() :
        command.menu === 'tabs' ? workspace().tabs.map(item => ({
          label: pageTitle(item), type: 'radio' as const, checked: item.id === tab.id,
          click: menuAction({ type: 'select', id: item.id })
        })) : undefined;
      if (!items) throw new Error('无效的菜单。');
      popupMenu(items, command.x, command.y);
      break;
    }
    default: throw new Error('未知的浏览器操作。');
  }
}

function pageTitle(tab: Tab): string {
  return live.get(tab.id)?.page.title || (tab.destination === 'claude' ? 'Claude' :
    tab.destination === 'mail' ? '邮箱' : webURL(tab.url)?.host || '新标签页');
}

function trusted(event: IpcMainInvokeEvent): boolean {
  return !!win && !win.isDestroyed() && event.sender === win.webContents &&
    event.senderFrame === win.webContents.mainFrame && event.senderFrame?.url === shellURL;
}

function createWindow(): void {
  const { maximized, ...stored } = saved.bounds;
  const point = typeof stored.x === 'number' && typeof stored.y === 'number' ? { x: stored.x, y: stored.y } : undefined;
  const onScreen = point && screen.getAllDisplays().some(({ workArea }) =>
    point.x + Math.min(stored.width, 150) > workArea.x && point.x < workArea.x + workArea.width &&
    point.y + 36 > workArea.y && point.y < workArea.y + workArea.height);
  win = new BrowserWindow({
    ...stored, ...(onScreen ? {} : { x: undefined, y: undefined }),
    minWidth: 780, minHeight: 540, title: accountLabel() + ' · Claude Browser', icon: appIcon, show: false,
    backgroundColor: '#f9f7f4', autoHideMenuBar: true, titleBarStyle: 'hidden',
    titleBarOverlay: { color: '#eeeae4', symbolColor: '#322822', height: topHeight },
    webPreferences: { ...securePreferences, preload: path.join(__dirname, 'preload.cjs') }
  });
  if (windowsPackage) win.setAppDetails(taskbar);
  win.webContents.on('will-navigate', event => event.preventDefault());
  win.webContents.on('will-redirect', event => event.preventDefault());
  win.webContents.on('will-attach-webview', event => event.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  refreshMenu();
  win.once('ready-to-show', () => {
    if (maximized) win?.maximize();
    win?.show();
    showTab();
  });
  win.on('resize', layout);
  win.on('focus', () => productionUpdates?.resume());
  win.on('enter-full-screen', publish);
  win.on('leave-full-screen', publish);
  win.once('close', () => {
    closing = true;
    if (win) {
      saved.bounds = { ...win.getNormalBounds(), maximized: win.isMaximized() };
      persist();
    }
    for (const id of [...live.keys(), ...pending.keys()]) closeView(id);
    for (const popup of popups.keys()) if (!popup.isDestroyed()) popup.destroy();
    network.close();
  });
  win.once('closed', () => { win = undefined; });
  void win.loadFile(html).catch(() => {
    dialog.showErrorBox('Claude Browser', '应用界面文件无法加载。请重新获取完整的应用包。');
    app.quit();
  });
}

async function pickInstalledData(localRoot: string): Promise<boolean> {
  for (;;) {
    const { response } = await dialog.showMessageBox({
      type: 'question', title: 'Claude Browser 资料目录', message: '选择安装版使用的账号资料',
      detail: '可建立一份安装版资料，也可沿用现有便携版的账号、登录和标签。沿用前请退出便携版。',
      buttons: ['使用安装版资料', '沿用便携版资料', '退出'], defaultId: 0, cancelId: 2, noLink: true
    });
    if (response === 0) {
      saveInstalledChoice(localRoot, { kind: 'local' });
      return true;
    }
    if (response !== 1) return false;
    const selected = await dialog.showOpenDialog({ title: '选择便携版资料目录', properties: ['openDirectory'] });
    if (selected.canceled || !selected.filePaths[0]) continue;
    let portableRoot: string;
    try {
      portableRoot = choosePortableDirectory(selected.filePaths[0]);
      await loadSettings(portableRoot);
    } catch {
      await dialog.showMessageBox({ type: 'warning', title: 'Claude Browser',
        message: '无法读取所选目录的资料。请选择便携版所在的目录，或其中的 .browser-local 文件夹。' });
      continue;
    }
    saveInstalledChoice(localRoot, { kind: 'portable', root: portableRoot });
    app.relaunch();
    return false;
  }
}

async function start(): Promise<void> {
  const installedRoot = installedEdition ? path.join(app.getPath('appData'), 'Claude Browser') : undefined;
  const choice = installedRoot ? readInstalledChoice(installedRoot) : undefined;
  root = choice?.kind === 'portable' ? choice.root :
    installedRoot ?? path.resolve(dataOverride || path.join(installDir, '.browser-local'));
  const dataDir = path.join(root, 'electron');
  if (windowsPackage) app.setAppUserModelId(taskbar.appId);
  mkdirSync(dataDir, { recursive: true });
  app.setPath('userData', dataDir);
  app.setPath('sessionData', dataDir);
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return;
  }
  app.on('second-instance', () => {
    productionUpdates?.open();
    if (win?.isMinimized()) win.restore();
    win?.show();
    win?.focus();
  });
  app.on('window-all-closed', () => app.quit());
  await app.whenReady();
  if (installedRoot && !choice && !await pickInstalledData(installedRoot)) {
    app.quit();
    return;
  }
  session.defaultSession.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*'] },
    (_details, callback) => callback({ cancel: true }));
  settings = await loadSettings(root);
  if (!Object.hasOwn(settings.profiles, account)) account = Object.keys(settings.profiles)[0];
  saved = loadState(root, Object.keys(settings.profiles));
  try {
    productionUpdates = createProductionUpdates(root, () => settings.port, () => win, refreshMenu, prepareUpdateExit, installedRoot);
  } catch {
    updatePolicyInvalid = true;
  }
  if (productionUpdates) {
    const updates = productionUpdates;
    const resume = () => updates.resume();
    powerMonitor.on('resume', resume);
    app.once('will-quit', event => {
      event.preventDefault();
      powerMonitor.removeListener('resume', resume);
      void updates.close().finally(() => app.quit()).catch(() => {});
    });
  }
  ipcMain.handle('shell:read', event => {
    if (!trusted(event)) throw new Error('未知的应用界面。');
    return snapshot();
  });
  ipcMain.handle('shell:detect-proxy', event => {
    if (!trusted(event) || !panel) throw new Error('请在账户设置中识别代理端口。');
    return detectWindowsProxyPort();
  });
  ipcMain.handle('shell:command', (event, input: Command) => {
    if (!trusted(event)) throw new Error('未知的应用界面。');
    if (!input || typeof input !== 'object') throw new Error('无效的浏览器操作。');
    return serialize(() => dispatch(input)).then(() => undefined,
      error => error instanceof Error ? error.message : '无法完成操作。');
  });
  createWindow();
  productionUpdates?.open();
}

void start().catch(() => {
  dialog.showErrorBox('Claude Browser', '无法打开应用资料。请检查资料目录的写入权限与设置文件格式。');
  app.quit();
});
