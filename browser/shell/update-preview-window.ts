import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { app, BrowserWindow, ipcMain, powerMonitor } from 'electron';
import type { IpcMainInvokeEvent } from 'electron';
import { securePreferences } from './network';
import { UpdateCheck } from './update-check';
import type { UpdateStatus } from './update-check';
import { checkPreviewManifest, previewEndpoint, readPreviewFeed } from './update-preview-feed';

export function showUpdatePreview(fixture: string): void {
  const { publicKey, envelope } = JSON.parse(readFileSync(fixture, 'utf8')) as { publicKey: string; envelope: string };
  const prefix = '--update-preview-feed=';
  const feedArg = process.argv.find(argument => argument.startsWith(prefix));
  const endpoint = feedArg === undefined ? undefined : previewEndpoint(feedArg.slice(prefix.length));
  const version = app.getVersion();
  const source = endpoint ? '本机回环测试源' : '内置签名测试清单';
  const html = path.join(__dirname, 'update-preview.html');
  const page = pathToFileURL(html).href;
  const window = new BrowserWindow({
    title: 'Claude Browser 更新检查预览',
    width: 520, height: 385, minWidth: 380, minHeight: 330, show: false,
    icon: path.join(__dirname, 'icon.png'), backgroundColor: '#f9f7f4', autoHideMenuBar: true,
    webPreferences: { ...securePreferences, preload: path.join(__dirname, 'update-preview-preload.cjs') }
  });
  let status: UpdateStatus | undefined;
  const checker = new UpdateCheck(async signal => {
    const manifest = endpoint ? await readPreviewFeed(endpoint, signal) : envelope;
    return checkPreviewManifest(manifest, publicKey, version);
  }, result => {
    status = result;
    if (!window.isDestroyed() && !window.webContents.isDestroyed()) {
      window.webContents.send('update-preview:status', status);
    }
  });
  const trusted = (event: IpcMainInvokeEvent) => !window.isDestroyed() && event.sender === window.webContents &&
    event.senderFrame === window.webContents.mainFrame && event.senderFrame?.url === page;
  ipcMain.handle('update-preview:read', event => trusted(event) ? { version, source, status } : undefined);
  ipcMain.handle('update-preview:online', event => {
    if (trusted(event)) checker.online();
  });
  const resume = () => checker.resume();
  const reopen = () => {
    checker.open();
    if (window.isMinimized()) window.restore();
    window.show();
    window.focus();
  };
  window.webContents.on('will-navigate', event => event.preventDefault());
  window.webContents.on('will-redirect', event => event.preventDefault());
  window.webContents.on('will-attach-webview', event => event.preventDefault());
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.once('ready-to-show', () => window.show());
  window.on('focus', resume);
  powerMonitor.on('resume', resume);
  app.on('second-instance', reopen);
  window.once('closed', () => {
    checker.close();
    powerMonitor.removeListener('resume', resume);
    app.removeListener('second-instance', reopen);
    ipcMain.removeHandler('update-preview:read');
    ipcMain.removeHandler('update-preview:online');
  });
  void window.loadFile(html).catch(() => app.quit());
  checker.open();
}
