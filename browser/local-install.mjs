import { constants } from 'node:fs';
import { copyFile, mkdir, readFile, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from './verify-package.mjs';

const configuration = fileURLToPath(new URL('../.browser-local/install-directory.txt', import.meta.url));

export async function updateLocalLauncher(artifact, hash) {
  const configured = await readFile(configuration, 'utf8').catch(error => {
    if (error.code !== 'ENOENT') throw error;
  });
  if (configured === undefined) return;
  const directory = configured.trim();
  if (!path.isAbsolute(directory) || /[\0\r\n]/.test(directory)) {
    throw new Error('本机更新目录必须是一个完整的绝对路径。');
  }

  const launcher = path.join(directory, 'ClaudeBrowser.exe');
  const current = await sha256(launcher).catch(error => {
    if (error.code !== 'ENOENT') throw error;
  });
  if (current === hash) return launcher;

  await mkdir(directory, { recursive: true });
  // Create the staged file on the target drive so the final rename is atomic.
  const staged = path.join(directory, '.claude-browser-update-' + randomUUID() + '.tmp');
  try {
    await copyFile(artifact, staged, constants.COPYFILE_EXCL);
    if (await sha256(staged) !== hash) throw new Error('本机更新文件的 SHA-256 校验失败。');
    await rename(staged, launcher);
  } finally {
    await rm(staged, { force: true });
  }
  return launcher;
}
