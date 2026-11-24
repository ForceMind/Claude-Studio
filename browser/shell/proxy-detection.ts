import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';

const internetSettingsKey = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const query = promisify(execFile);

function loopbackHttpPort(endpoint: string): number | null {
  const match = /^(?:http:\/\/)?(?:127\.0\.0\.1|localhost):([0-9]{1,5})\/?$/i.exec(endpoint.trim());
  const port = match ? Number(match[1]) : 0;
  return port > 0 && port <= 65535 ? port : null;
}

export function parseProxyPort(source: string): number | null {
  const entries = source.split(';').map(entry => entry.trim()).filter(Boolean);
  if (entries.length === 1 && !entries[0].includes('=')) return loopbackHttpPort(entries[0]);
  if (entries.some(entry => !/^[a-z\d]+=/i.test(entry))) return null;
  const ports = entries.filter(entry => /^https?=/i.test(entry))
    .map(entry => loopbackHttpPort(entry.slice(entry.indexOf('=') + 1)));
  const [first] = ports;
  return first && ports.every(port => port === first) ? first : null;
}

export function proxyPortFromRegistry(enabled: string, server: string): number | null {
  const flag = /^[ \t]*ProxyEnable[ \t]+REG_DWORD[ \t]+(0x[\da-f]+)[ \t]*$/im.exec(enabled);
  if (!flag || Number(flag[1]) !== 1) return null;
  const value = /^[ \t]*ProxyServer[ \t]+REG_(?:EXPAND_)?SZ[ \t]+([^\r\n]*)$/im.exec(server)?.[1];
  return value ? parseProxyPort(value) : null;
}

export async function detectWindowsProxyPort(): Promise<number | null> {
  const system = process.env.SystemRoot;
  if (process.platform !== 'win32' || !system || !path.win32.isAbsolute(system)) return null;
  const reg = path.win32.join(system, 'System32', 'reg.exe');
  try {
    const values = await Promise.all(['ProxyEnable', 'ProxyServer'].map(name =>
      query(reg, ['query', internetSettingsKey, '/v', name], { windowsHide: true, timeout: 3000, maxBuffer: 8192 })
    ));
    return proxyPortFromRegistry(values[0].stdout, values[1].stdout);
  } catch {
    return null;
  }
}
