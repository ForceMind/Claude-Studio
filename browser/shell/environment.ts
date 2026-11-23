import { isIP } from 'node:net';
import { languagesFor } from './model.ts';
import type { Account, ExitState, PageEnvironment, Profile } from './model.ts';

export const exitURL = 'https://api64.ipify.org/';
const maxResponseBytes = 64;

type ExitSession = {
  resolveProxy(url: string): Promise<string>;
  fetch(url: string, init: RequestInit): Promise<Response>;
};

async function resolveRoute(session: ExitSession, signal: AbortSignal): Promise<string> {
  signal.throwIfAborted();
  let cancel: () => void = () => {};
  const aborted = new Promise<never>((_, reject) => {
    cancel = () => reject(signal.reason);
    signal.addEventListener('abort', cancel, { once: true });
  });
  try {
    return await Promise.race([session.resolveProxy(exitURL), aborted]);
  } finally {
    signal.removeEventListener('abort', cancel);
  }
}

export async function probeExit(session: ExitSession, relayPort: number, cancelled: AbortSignal): Promise<string> {
  const signal = AbortSignal.any([cancelled, AbortSignal.timeout(8000)]);
  const route = await resolveRoute(session, signal);
  if (route.trim() !== 'PROXY 127.0.0.1:' + relayPort) throw new Error('Unexpected exit probe route');
  signal.throwIfAborted();
  const response = await session.fetch(exitURL, {
    credentials: 'omit', redirect: 'error', cache: 'no-store', signal,
    headers: { Accept: 'text/plain', 'Cache-Control': 'no-cache, no-store' }
  });
  if (!response.ok || response.redirected || !response.body) {
    void response.body?.cancel().catch(() => {});
    throw new Error('Unexpected exit probe response');
  }

  const reader = response.body.getReader();
  const buffer = new Uint8Array(maxResponseBytes);
  let length = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      if (done) break;
      if (length + value.length > buffer.length) throw new Error('Oversized exit probe response');
      buffer.set(value, length);
      length += value.length;
    }
  } finally {
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  signal.throwIfAborted();
  const address = new TextDecoder().decode(buffer.subarray(0, length)).trim();
  if (!isIP(address) || address.includes('%')) throw new Error('Invalid exit address');
  return address;
}

type Check = {
  pending?: AbortController;
  result: ExitState;
};

export class ExitChecks {
  private checks = new Map<Account, Check>();

  private readonly changed: () => void;

  constructor(changed: () => void) {
    this.changed = changed;
  }

  read(account: Account): ExitState {
    return this.checks.get(account)?.result ?? { state: 'unmeasured' };
  }

  async check(account: Account, probe: (signal: AbortSignal) => Promise<string>): Promise<void> {
    if (this.checks.get(account)?.pending) return;
    const controller = new AbortController();
    const current: Check = { pending: controller, result: { state: 'checking' } };
    this.checks.set(account, current);
    this.changed();
    try {
      const address = await probe(controller.signal);
      current.result = { state: 'checked', address, checkedAt: Date.now() };
    } catch {
      current.result = { state: 'failed' };
    } finally {
      current.pending = undefined;
      if (this.checks.get(account) === current) this.changed();
    }
  }

  invalidate(account: Account): void {
    const current = this.checks.get(account);
    this.checks.delete(account);
    current?.pending?.abort();
  }
}

export function configuredPageEnvironment(profile: Profile, systemLanguages: string[], systemZone: string): PageEnvironment {
  return {
    language: languagesFor(profile.language, systemLanguages)[0] ?? '—',
    zone: profile.zone === 'system' ? systemZone : profile.zone
  };
}

export function decodePageEnvironment(raw: unknown): PageEnvironment | undefined {
  if (typeof raw !== 'object' || !raw) return;
  const { language, zone } = raw as Partial<PageEnvironment>;
  if (typeof language !== 'string' || language.length > 100 ||
      typeof zone !== 'string' || zone.length > 100 || !/^[A-Za-z0-9_+/-]+$/.test(zone)) return;
  try {
    const [canonical] = Intl.getCanonicalLocales(language);
    if (!canonical) return;
    new Intl.DateTimeFormat('en', { timeZone: zone });
    return { language: canonical, zone };
  } catch {
    return;
  }
}
