import { readFileSync } from 'node:fs';
import path from 'node:path';
import { app, dialog, net, session } from 'electron';
import type { BrowserWindow, ClientRequestConstructorOptions, MenuItemConstructorOptions } from 'electron';
import { DesktopUpdates, ReleaseDataError } from '../update/desktop-updates.mjs';
import { desktopTarget } from '../update/desktop-policy.mjs';
import { createUpdateTransport } from '../update/proxy-transport.mjs';
import { sha256 } from '../update/release-manifest.mjs';
import { handoffWindowsInstall, lastWindowsInstall, portableInstallContext, setupInstallContext } from '../update/windows-install.mjs';
import { verifyWindowsArtifact } from '../platform/windows-artifact.mjs';
import { getMacArtifactVerificationAvailability } from '../platform/macos-artifact.mjs';
import { InvalidManifest, UpdateCheck } from './update-check';
import type { UpdateStatus } from './update-check';

declare const __DESKTOP_RELEASE__: { config: unknown; verifierHash?: string } | null;

export interface ProductionUpdates {
  open(): void;
  resume(): void;
  proxyChanged(): void;
  close(): Promise<void>;
  menu(): MenuItemConstructorOptions;
}

export function createProductionUpdates(root: string, port: () => number | null, window: () => BrowserWindow | undefined,
  changed: () => void, prepareExit: () => Promise<void>, setupRoot?: string): ProductionUpdates | undefined {
  // A release embeds this object in main.cjs at build time. Do not load a runtime policy file.
  const compiled = typeof __DESKTOP_RELEASE__ === 'undefined' ? null : __DESKTOP_RELEASE__;
  if (!app.isPackaged || !compiled) return;
  const edition = setupRoot ? 'setup' : undefined;
  const target = desktopTarget(compiled.config, process.platform, process.arch, app.getVersion(), edition);
  const verifier = path.join(__dirname, 'windows-authenticode.exe');
  const verifyPlatform = process.platform === 'win32' && compiled.verifierHash ?
    async (file: string, candidate: { version: string; sha256: string }, signal: AbortSignal) => {
      if (sha256(readFileSync(verifier)) !== compiled.verifierHash) throw new Error('随包签名验证器完整性检查失败。');
      const result = await verifyWindowsArtifact(file, { verifierPath: verifier,
        signerPins: target.signerPins, version: candidate.version, signal, edition: edition ?? 'portable' });
      if (result.sha256 !== candidate.sha256) throw new Error('原生验证的文件与签名清单不匹配。');
    } : undefined;
  const unavailable = process.platform === 'darwin' && !getMacArtifactVerificationAvailability().available;
  const appImage = process.execPath, appPid = process.pid, currentVersion = app.getVersion();
  const installContext = verifyPlatform && (setupRoot ?
    setupInstallContext({ appImage, root: setupRoot, appPid, currentVersion }) :
    portableInstallContext({ launcher: process.env.PORTABLE_EXECUTABLE_FILE, appImage, root,
      appPid, launcherPid: process.ppid, currentVersion }));
  let status: UpdateStatus | undefined;
  let lastInstall = '';
  let action = '';
  let dialogOpen = false;

  const updateSession = session.fromPartition('claude-release-updates', { cache: false });
  const transport = createUpdateTransport({
    session: updateSession,
    openRequest: (options: ClientRequestConstructorOptions) => net.request({ ...options, session: updateSession }),
    readPort: port, onOnline: () => checker.online()
  });
  const updater = new DesktopUpdates({ target, request: transport.request, root: setupRoot ?? root, verifyPlatform,
    onReady: () => {
      if (!dialogOpen) action = '';
      changed();
    } });
  const checker = new UpdateCheck(async signal => {
    try { return await updater.check(signal); }
    catch (error) {
      if (error instanceof ReleaseDataError) throw new InvalidManifest(error.message);
      throw error;
    }
  }, next => {
    status = next;
    if (!dialogOpen) action = '';
    changed();
  });
  if (installContext) void lastWindowsInstall(installContext).then(result => {
    if (!result) return;
    lastInstall = result.status === 'installed' && result.version === app.getVersion() ? '已应用上次更新 ' + result.version :
      result.status === 'recovery-required' ? (setupRoot ? '上次升级未完成，请使用同版 Setup 修复安装' :
        '上次安装需要恢复，请检查原目录的更新备份') : '请核对上次安装结果和程序版本';
    changed();
  });

  async function choose(work: (parent: BrowserWindow) => Promise<void>): Promise<void> {
    const parent = window();
    if (!parent || parent.isDestroyed() || dialogOpen) return;
    dialogOpen = true;
    try { await work(parent); }
    catch (error) {
      action = error instanceof Error && 'code' in error && error.code === 'EEXIST' ?
        '保存路径已有文件，请另选文件名。' : '更新包操作失败，请重新检查。';
    } finally {
      dialogOpen = false;
      changed();
    }
  }

  return {
    open: () => checker.open(),
    resume: () => checker.resume(),
    proxyChanged() {
      transport.invalidate();
      checker.online();
    },
    async close() {
      checker.close();
      transport.close();
      await updater.close();
    },
    menu() {
      const offer = status?.kind === 'available' ? updater.offer : undefined;
      const ready = status?.kind === 'available' ? updater.ready : undefined;
      const label = action || (
        status?.kind === 'available' ? '发现更新 ' + status.version :
        status?.kind === 'current' ? '已是最新版本' :
        status?.kind === 'invalid' ? '更新清单验证失败' :
        status?.kind === 'unreachable' ? '无法通过本地代理检查更新' :
        '正在检查更新'
      );
      return { label: '更新', submenu: [
        { label, enabled: false },
        ...(lastInstall ? [{ label: lastInstall, enabled: false }] : []),
        { label: '检查更新', enabled: status?.kind !== 'checking', click: () => { action = ''; checker.open(); } },
        ...(unavailable ? [{ label: 'macOS 应用内下载暂未启用', enabled: false }] : []),
        ...(offer && !ready ? [{
          label: '下载并验包 ' + offer.version, enabled: !dialogOpen, click: () => {
            void choose(async parent => {
              const result = await dialog.showMessageBox(parent, {
                type: 'question', buttons: ['取消', '下载'], defaultId: 0, cancelId: 0,
                message: '下载 Claude Browser ' + offer.version + '？',
                detail: '下载完成后会验证文件和发布者签名。'
              });
              if (result.response !== 1) return;
              action = '正在下载和验证更新包';
              changed();
              await updater.download(offer.token);
              action = '更新包已验证';
            });
          }
        }] : []),
        ...(ready && installContext && compiled.verifierHash ? [{
          label: '退出并安装 ' + ready.version, enabled: !dialogOpen, click: () => {
            void choose(async parent => {
              const result = await dialog.showMessageBox(parent, {
                type: 'question', buttons: ['取消', '退出并安装'], defaultId: 0, cancelId: 0,
                message: '退出 Claude Browser 并安装 ' + ready.version + '？',
                detail: setupRoot ? '应用会先保存标签和账户会话。安装校验成功后会重新打开。' :
                  '应用会先保存标签和账户会话。替换结束后，可从原目录重新打开。'
              });
              if (result.response !== 1) return;
              action = '正在保存会话并移交安装';
              changed();
              await updater.installVerified(ready.token, (
                verified: { file: string; candidate: { sha256: string; version: string; expiresAt: number } },
                revalidate: () => Promise<unknown>, signal: AbortSignal
              ) => handoffWindowsInstall(installContext, {
                ...verified, verifierPath: verifier, verifierHash: compiled.verifierHash,
                prepare: prepareExit, revalidate, signal
              }));
              app.quit();
            });
          }
        }] : []),
        ...(ready ? [{
          label: '保存已验证的安装包…', enabled: !dialogOpen, click: () => {
            void choose(async parent => {
              const selection = await dialog.showSaveDialog(parent, {
                defaultPath: 'ClaudeBrowser-' + ready.version + (setupRoot ? '-Setup' : '') + target.extension,
                filters: [{ name: 'Claude Browser', extensions: [target.extension.slice(1)] }]
              });
              if (selection.canceled || !selection.filePath) return;
              await updater.saveVerified(ready.token, selection.filePath);
              action = '已保存已验证的安装包';
            });
          }
        }] : [])
      ] };
    }
  };
}
