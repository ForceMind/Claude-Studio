import { setImmediate as nextTurn } from 'node:timers/promises';
import { app, session } from 'electron';
import type { Session, WebContents, WebPreferences } from 'electron';
import { startRelay } from '../relay.mjs';
import { acceptLanguage, languagesFor } from './model';
import { ExitChecks, probeExit } from './environment';
import { isClaudeSite, isMailboxSpace, partitionForSpace, transferableClaudeURL } from './mailbox-route';
import type { Account, Profile, ShellState } from './model';

type Relay = Awaited<ReturnType<typeof startRelay>>;
type AgentMetadata = Record<string, unknown> & { uaFullVersion?: string };
type Space = { session: Session; relay: Relay; profile: Profile; languages: string[]; agent?: AgentMetadata };
type LinkRequest = (url: string) => void;
type Connection = { status: ShellState['status']; pending: Promise<Space>; space?: Space };
const webFilters = { urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*'] };

export const securePreferences: WebPreferences = {
  sandbox: true, contextIsolation: true, nodeIntegration: false, webviewTag: false,
  webSecurity: true, allowRunningInsecureContent: false, devTools: false
};

export class AccountNetwork {
  private entries = new Map<Account, Connection>();
  private sessions = new Map<Account, Session>();
  private mainFrames = new Map<number, { contents: WebContents; space: Space; ready?: Promise<boolean>; requestLink?: LinkRequest }>();

  readonly exits: ExitChecks;

  constructor(private changed: () => void) {
    this.exits = new ExitChecks(changed);
  }

  status(id: Account, port: number | null): ShellState['status'] {
    if (!port) return 'unset';
    const entry = this.entries.get(id);
    if (entry?.space) return entry.space.relay.online ? 'online' : 'offline';
    return entry?.status ?? 'connecting';
  }

  canReuse(id: Account, space: Space): boolean {
    return this.entries.get(id)?.space === space && space.relay.online;
  }

  connect(id: Account, port: number, profile: Profile): Promise<Space> {
    const existing = this.entries.get(id);
    if (existing && existing.status !== 'offline') return existing.pending;
    const pending = this.configure(id, port, profile);
    const entry: Connection = { status: 'connecting', pending };
    this.entries.set(id, entry);
    void pending.then(space => {
      entry.space = space;
      entry.status = 'online';
      this.changed();
    }, () => {
      entry.status = 'offline';
      this.changed();
    });
    return pending;
  }

  private async configure(id: Account, port: number, profile: Profile): Promise<Space> {
    const relay = await startRelay(port, online => {
      if (this.entries.get(id)?.space?.relay !== relay) return;
      if (!online) this.exits.invalidate(id);
      this.changed();
    });
    try {
      const configured = this.sessions.get(id);
      const accountSession = configured ?? session.fromPartition(partitionForSpace(id));
      const languages = languagesFor(profile.language, app.getPreferredSystemLanguages());
      const header = acceptLanguage(languages);
      accountSession.setUserAgent(accountSession.getUserAgent(), languages.join(','));
      accountSession.webRequest.onBeforeSendHeaders(webFilters, (details, callback) => {
        const requestHeaders = { ...details.requestHeaders };
        for (const key of Object.keys(requestHeaders)) {
          if (key.toLowerCase() === 'accept-language') delete requestHeaders[key];
        }
        requestHeaders['Accept-Language'] = header;
        callback({ requestHeaders });
      });
      if (!configured) {
        accountSession.setPermissionCheckHandler((_contents, permission) => permission === 'clipboard-sanitized-write');
        accountSession.setPermissionRequestHandler((_contents, permission, callback) => {
          callback(permission === 'clipboard-sanitized-write');
        });
        accountSession.setDisplayMediaRequestHandler((_request, callback) => callback({}));
        accountSession.setDevicePermissionHandler(() => false);
        accountSession.on('will-download', event => event.preventDefault());
        accountSession.webRequest.onBeforeRequest(webFilters, (details, callback) => {
          const activeSpace = this.entries.get(id)?.space;
          if (isMailboxSpace(id) && isClaudeSite(details.url)) {
            const contentsId = details.webContentsId ?? details.webContents?.id;
            const frame = contentsId === undefined ? undefined : this.mainFrames.get(contentsId);
            const registeredMainFrame = details.resourceType === 'mainFrame' && frame && frame.space === activeSpace &&
              !frame.contents.isDestroyed() ? frame : undefined;
            const target = registeredMainFrame && activeSpace?.relay.online && details.method === 'GET' &&
              !details.uploadData?.length && transferableClaudeURL(details.url);
            // Cancel the navigation in Chromium before rejecting the request to preserve the source document.
            try { registeredMainFrame?.contents.stop(); }
            catch { /* The frame can close while the request is being intercepted. */ }
            finally { callback({ cancel: true }); }
            if (target) registeredMainFrame?.requestLink?.(target);
            return;
          }
          if (!activeSpace?.relay.online) {
            callback({ cancel: true });
            return;
          }
          if (details.resourceType !== 'mainFrame') {
            callback({});
            return;
          }
          const contentsId = details.webContentsId ?? details.webContents?.id;
          const frame = contentsId === undefined ? undefined : this.mainFrames.get(contentsId);
          if (frame?.space !== activeSpace) {
            callback({ cancel: true });
            return;
          }
          if (!frame.ready) {
            callback({});
            return;
          }
          void frame.ready.then(ok => callback({ cancel: !ok || this.entries.get(id)?.space !== activeSpace ||
            !activeSpace.relay.online || this.mainFrames.get(contentsId!) !== frame }));
        });
        this.sessions.set(id, accountSession);
      }
      await accountSession.setProxy({
        mode: 'fixed_servers', proxyRules: 'http://127.0.0.1:' + relay.port, proxyBypassRules: '<-loopback>'
      });
      await accountSession.closeAllConnections();
      return { session: accountSession, relay, profile, languages };
    } catch (error) {
      relay.close();
      throw error;
    }
  }

  webPreferences(space: Space): WebPreferences {
    const explicit = space.profile.language;
    return {
      ...securePreferences, session: space.session,
      additionalArguments: explicit === 'system' ? [] : ['--lang=' + explicit]
    };
  }

  private registerFrame(contents: WebContents, space: Space, ready?: Promise<boolean>, requestLink?: LinkRequest): void {
    const id = contents.id;
    this.mainFrames.set(id, { contents, space, ready, requestLink });
    contents.once('destroyed', () => this.mainFrames.delete(id));
  }

  prepare(contents: WebContents, space: Space, bootstrap: string, requestLink?: LinkRequest): Promise<boolean> {
    const ready = this.applyEnvironment(contents, space, bootstrap).then(failure => !failure);
    this.registerFrame(contents, space, ready, requestLink);
    return ready;
  }

  preparePopup(contents: WebContents, space: Space, requestLink?: LinkRequest): Promise<string | undefined> {
    if (contents.session !== space.session) {
      contents.stop();
      return Promise.resolve('账号会话不匹配');
    }
    try {
      contents.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
    } catch {
      contents.stop();
      return Promise.resolve('应用网络策略失败');
    }
    // Native navigation can be required for the renderer to acknowledge CDP commands.
    // Register the account's proxy route synchronously, then start CDP after handing back the guest.
    this.registerFrame(contents, space, undefined, requestLink);
    return nextTurn().then(() => this.applyEnvironment(contents, space));
  }

  private async applyEnvironment(contents: WebContents, space: Space, bootstrap?: string): Promise<string | undefined> {
    let step = bootstrap ? '启动网页进程' : '连接网页进程';
    async function configure(): Promise<void> {
      if (bootstrap) {
        // A local empty document starts the renderer and supplies its real client hints.
        await contents.loadFile(bootstrap);
        space.agent ??= await contents.executeJavaScript(
          'navigator.userAgentData?.getHighEntropyValues([' +
          '"architecture","bitness","model","platformVersion","uaFullVersion","fullVersionList","wow64"])'
        ) as AgentMetadata | undefined;
        contents.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
      }
      step = '连接网页进程';
      if (contents.isDestroyed()) throw new Error('Web contents closed');
      contents.debugger.attach('1.3');
      step = '应用网页语言';
      const { uaFullVersion, ...metadata } = space.agent ?? {};
      await contents.debugger.sendCommand('Emulation.setUserAgentOverride', {
        userAgent: contents.getUserAgent(),
        acceptLanguage: space.languages.join(','),
        ...(space.agent ? { userAgentMetadata: { ...metadata, fullVersion: uaFullVersion } } : {})
      });
      if (space.profile.zone !== 'system') {
        step = '应用网页时区';
        await contents.debugger.sendCommand('Emulation.setTimezoneOverride', { timezoneId: space.profile.zone });
      }
    }

    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        configure().then(() => undefined, () => step + '失败'),
        new Promise<string>(resolve => {
          timer = setTimeout(() => resolve(step + '超时'), 8000);
        })
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  checkExit(id: Account): void {
    const space = this.entries.get(id)?.space;
    if (!space?.relay.online) throw new Error('本地代理连通后才能检测出口。');
    void this.exits.check(id, signal => probeExit(space.session, space.relay.port, signal));
  }

  async disconnect(id: Account): Promise<void> {
    this.exits.invalidate(id);
    const entry = this.entries.get(id);
    this.entries.delete(id);
    if (!entry) return;
    const space = await entry.pending.catch(() => undefined);
    space?.relay.close();
    await space?.session.closeAllConnections().catch(() => undefined);
  }

  async clearAccountData(id: Account): Promise<void> {
    await this.disconnect(id);
    const accountSession = this.sessions.get(id) ?? session.fromPartition(partitionForSpace(id));
    await accountSession.closeAllConnections();
    await accountSession.clearData();
    await accountSession.clearAuthCache();
  }

  async flushStorage(): Promise<void> {
    await Promise.all([...this.sessions.values()].map(async accountSession => {
      accountSession.flushStorageData();
      await accountSession.cookies.flushStore();
    }));
  }

  close(): void {
    for (const [id, entry] of this.entries) {
      this.exits.invalidate(id);
      entry.space?.relay.close();
      if (!entry.space) void entry.pending.then(space => space.relay.close(), () => {});
    }
    this.entries.clear();
  }
}
