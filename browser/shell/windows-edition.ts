import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export const installedMarker = 'claude-browser-installed';
export const windowsAppId = 'com.claudestudio.browser';
type DataChoice = { kind: 'local' } | { kind: 'portable'; root: string };

function localDirectory(directory: string): string {
  if (!path.isAbsolute(directory) || directory.startsWith('\\')) throw new Error('请选择本机磁盘上的绝对路径。');
  const canonical = realpathSync(directory);
  if (canonical.startsWith('\\\\') || !statSync(canonical).isDirectory()) {
    throw new Error('请选择本机磁盘上的资料目录。');
  }
  return canonical;
}

function portableDirectory(directory: string): string {
  const root = localDirectory(directory);
  if (!statSync(path.join(root, 'settings.json')).isFile() ||
      !statSync(path.join(root, 'electron')).isDirectory()) {
    throw new Error('目录中缺少 Claude Browser 的设置或浏览器资料。');
  }
  return root;
}

export function choosePortableDirectory(directory: string): string {
  const selected = localDirectory(directory);
  for (const candidate of [path.join(selected, '.browser-local'), selected]) {
    try { return portableDirectory(candidate); } catch { /* Try the other supported layout. */ }
  }
  throw new Error('请选择便携版所在的目录，或其中的 .browser-local 文件夹。');
}

export function readInstalledChoice(localRoot: string): DataChoice | undefined {
  let raw: string;
  try { raw = readFileSync(path.join(localRoot, 'data-location.json'), 'utf8'); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  const value = JSON.parse(raw);
  if (value?.version === 1 && value.kind === 'local') return { kind: 'local' };
  if (value?.version === 1 && value.kind === 'portable' && typeof value.root === 'string') {
    return { kind: 'portable', root: portableDirectory(value.root) };
  }
  throw new Error('安装版资料目录记录无效。');
}

export function saveInstalledChoice(localRoot: string, choice: DataChoice): void {
  mkdirSync(localRoot, { recursive: true });
  const temporary = path.join(localRoot, 'data-location-' + randomUUID() + '.tmp');
  try {
    writeFileSync(temporary, JSON.stringify({ version: 1, ...choice }), { flag: 'wx', flush: true });
    renameSync(temporary, path.join(localRoot, 'data-location.json'));
  } finally {
    rmSync(temporary, { force: true });
  }
}

export function windowsTaskbarDetails(edition: 'installed' | 'portable', launcher: string | undefined) {
  const appId = edition === 'installed' ? windowsAppId : windowsAppId + '.portable';
  if (!launcher || !path.isAbsolute(launcher) || /["\r\n\0]/.test(launcher)) return { appId };
  return { appId, appIconPath: launcher, relaunchDisplayName: 'Claude Browser',
    relaunchCommand: '"' + launcher + '"' };
}
