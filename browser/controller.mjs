import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { stdin, stdout } from 'node:process';
import { chromium } from 'playwright-core';
import { accounts, checkAccount, checkPort, checkProfile, loadSettings, saveSettings, launchOptions, profilePath } from './settings.mjs';
import { startRelay } from './relay.mjs';

const root = process.env.CLAUDE_BROWSER_DATA_DIR || fileURLToPath(new URL('../.browser-local/', import.meta.url));
const sessions = new Map();
const input = createInterface({ input: stdin, terminal: false });
const emit = message => stdout.write(JSON.stringify(message) + '\n');
const status = () => Object.fromEntries(accounts.map(id => {
  const session = sessions.get(id);
  return [id, !session ? '已停止' : session.relay.online ? '已打开' : '代理端口离线'];
}));
const notify = () => emit({ event: 'status', states: status() });
let settings;

async function edit(id, port, draft) {
  checkPort(port);
  const profile = checkProfile(draft);
  if (sessions.size && port !== settings.port) throw new Error('更换共用端口前，请停止所有已打开的空间。');
  if (sessions.has(id) && JSON.stringify(profile) !== JSON.stringify(settings.profiles[id]))
    throw new Error('请先停止本账户，再修改其设置。');
  const next = { port, profiles: { ...settings.profiles, [id]: profile } };
  await saveSettings(root, next);
  settings = next;
}

async function open(id, destination) {
  if (!settings.port) throw new Error('请先保存本地代理端口。');
  const profile = settings.profiles[id];
  const url = destination === 'mail' ? profile.mail : 'https://claude.ai/';
  if (!url) throw new Error('请先设置本账户的 HTTPS 邮箱主页。');
  let session = sessions.get(id);
  if (session && !session.relay.online) throw new Error('本地代理端口离线，请恢复后重试。');
  if (!session) {
    const relay = await startRelay(settings.port, notify);
    let context;
    try {
      context = await chromium.launchPersistentContext(profilePath(root, id), launchOptions(profile, relay.port));
    } catch {
      relay.close();
      throw new Error('Edge 启动失败。请确认已安装 Edge，且本账户资料目录未被其他窗口占用。');
    }
    session = { context, relay, tabs: new Map() };
    sessions.set(id, session);
    context.once('close', () => {
      relay.close();
      if (sessions.get(id) === session) sessions.delete(id);
      notify();
    });
    notify();
  }
  const existing = session.tabs.get(destination);
  if (existing && !existing.isClosed()) { await existing.bringToFront(); return; }
  const page = session.context.pages().find(candidate => candidate.url() === 'about:blank') ?? await session.context.newPage();
  await page.bringToFront();
  try {
    await page.goto(url, { waitUntil: 'commit', timeout: 20000 });
    session.tabs.set(destination, page);
  } catch {
    throw new Error('网页未完成导航。请检查账户窗口、本地代理及目标站点后重试。');
  }
}

async function stop(id) {
  const session = sessions.get(id);
  if (!session) return;
  session.relay.close();
  await session.context.close();
}

try {
  settings = await loadSettings(root);
  emit({ event: 'ready', settings, states: status() });
  for await (const line of input) {
    try {
      const command = JSON.parse(line);
      if (command.action === 'quit') break;
      const id = checkAccount(command.id);
      if (command.action === 'save') await edit(id, command.port, command.profile);
      else if (command.action === 'claude' || command.action === 'mail') {
        await edit(id, command.port, command.profile);
        await open(id, command.action);
      } else if (command.action === 'stop') await stop(id);
      else throw new Error('未知操作。');
      emit({ event: 'done', settings, states: status() });
    } catch (e) {
      emit({ event: 'failure', message: e.message, settings, states: status() });
    }
  }
} catch {
  emit({ event: 'fatal', message: '无法读取本工作树的账户设置。请检查 .browser-local/settings.json。' });
} finally {
  await Promise.allSettled(accounts.map(stop));
  input.close();
}
