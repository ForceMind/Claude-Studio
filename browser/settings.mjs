import path from 'node:path';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

export const accounts = ['A', 'B'];
export const maxProfiles = 32;

function validAccountId(id) {
  return accounts.includes(id) ||
    (typeof id === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id));
}
export const defaults = {
  port: null,
  profiles: {
    A: { language: 'en-US', zone: 'Asia/Shanghai', mail: '' },
    B: { language: 'en-US', zone: 'America/Los_Angeles', mail: '' }
  }
};

export function checkAccount(id) {
  if (!accounts.includes(id)) throw new Error('无效的账户。');
  return id;
}

export function checkPort(value) {
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error('代理端口应为 1–65535 的整数。');
  return value;
}

export function checkProfile(profile) {
  if (!profile || typeof profile !== 'object') throw new Error('账户设置格式错误。');
  const { language, zone, mail, name } = profile;
  if (typeof language !== 'string' || typeof zone !== 'string' || typeof mail !== 'string')
    throw new Error('账户设置格式错误。');
  try {
    if (language !== 'system') Intl.getCanonicalLocales(language);
    if (zone !== 'system') new Intl.DateTimeFormat('en', { timeZone: zone });
  } catch { throw new Error('请使用有效的语言代码和 IANA 时区。'); }
  if (mail) {
    let url;
    try { url = new URL(mail); } catch { throw new Error('请输入完整的 HTTPS 邮箱主页地址。'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash)
      throw new Error('仅保存 HTTPS 邮箱主页地址，请去掉账号密码、查询参数和片段。');
  }
  if (name !== undefined && (typeof name !== 'string' || !name.trim() || name.length > 40 || /[\u0000-\u001f\u007f]/.test(name))) {
    throw new Error('请输入 1–40 个字符的账号名称。');
  }
  return { language, zone, mail, ...(name !== undefined ? { name: name.trim() } : {}) };
}

export function profilePath(root, id) {
  return path.join(root, 'profiles', checkAccount(id));
}

export async function loadSettings(root) {
  let raw;
  try { raw = await readFile(path.join(root, 'settings.json'), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return structuredClone(defaults); throw error; }
  const data = JSON.parse(raw);
  if (data.port !== null) checkPort(data.port);
  if (!data.profiles || typeof data.profiles !== 'object' || Array.isArray(data.profiles)) {
    throw new Error('账号配置格式错误。');
  }
  const entries = Object.entries(data.profiles);
  if (!entries.length) throw new Error('至少需要保留一个账号。');
  if (entries.length > maxProfiles) throw new Error('账号配置超过允许的数量。');
  const profiles = Object.fromEntries(entries.map(([id, value]) => {
    if (!validAccountId(id)) throw new Error('账号标识无效。');
    const profile = checkProfile(value);
    if (!accounts.includes(id) && !profile.name) throw new Error('自建账号缺少名称。');
    return [id, profile];
  }));
  return { port: data.port, profiles };
}

export function addProfile(settings, draft) {
  if (Object.keys(settings.profiles).length >= maxProfiles) throw new Error('最多支持 ' + maxProfiles + ' 个账号空间。');
  const profile = checkProfile(draft);
  if (!profile.name) throw new Error('请输入账号名称。');
  const id = randomUUID();
  return { id, settings: { ...settings, profiles: { ...settings.profiles, [id]: profile } } };
}

export function moveProfile(settings, id, direction) {
  if (!Object.hasOwn(settings.profiles, id) || (direction !== -1 && direction !== 1)) {
    throw new Error('无效的账号排序。');
  }
  const entries = Object.entries(settings.profiles);
  const from = entries.findIndex(([key]) => key === id);
  const to = from + direction;
  if (to < 0 || to >= entries.length) return settings;
  [entries[from], entries[to]] = [entries[to], entries[from]];
  return { ...settings, profiles: Object.fromEntries(entries) };
}

export function removeProfile(settings, id) {
  if (!Object.hasOwn(settings.profiles, id)) throw new Error('无效的账号。');
  const { [id]: removed, ...profiles } = settings.profiles;
  if (!Object.keys(profiles).length) throw new Error('至少需要保留一个账号。');
  return { ...settings, profiles };
}

export async function saveSettings(root, settings) {
  await mkdir(root, { recursive: true });
  const temp = path.join(root, randomUUID() + '.tmp');
  try {
    await writeFile(temp, JSON.stringify(settings, null, 2), { flag: 'wx', flush: true });
    await rename(temp, path.join(root, 'settings.json'));
  } finally {
    await rm(temp, { force: true });
  }
}

export function launchOptions(profile, relayPort) {
  const system = new Intl.DateTimeFormat().resolvedOptions();
  const language = profile.language === 'system' ? system.locale : profile.language;
  const timezoneId = profile.zone === 'system' ? system.timeZone : profile.zone;
  return {
    channel: 'msedge', headless: false, chromiumSandbox: true, viewport: null,
    locale: language, timezoneId, timeout: 20000,
    proxy: { server: 'http://127.0.0.1:' + checkPort(relayPort), bypass: '<-loopback>' },
    args: [
      '--lang=' + language, '--disable-quic', '--disable-background-networking',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'
    ]
  };
}
