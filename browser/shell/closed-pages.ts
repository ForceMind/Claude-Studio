import { restorableURL, webURL } from './model.ts';

const capacity = 5;
const lifetime = 10 * 60_000;
type Schedule = (work: () => void, delay: number) => () => void;

function scheduleExpiry(work: () => void, delay: number): () => void {
  const timer = setTimeout(work, delay);
  timer.unref();
  return () => clearTimeout(timer);
}

export function cacheablePageURL(value: unknown): boolean {
  const url = webURL(value);
  if (!url || !restorableURL(url.href)) return false;
  const privateRoute = /(?:^|[\/?&#=_-])(?:temporary(?:[-_]?chat)?|incognito|login|sign[-_]?in|sign[-_]?up|register|oauth2?|sso|saml|authorize|callback|verify|verification|kyc|token|code|state)(?:$|[\/?&#=_-])/i;
  return !privateRoute.test(url.pathname + url.search + url.hash);
}

export class ClosedPages {
  private entries = new Map<string, { owner: string; expires: number; cancel: () => void }>();

  constructor(dispose: (id: string) => void, now = Date.now, schedule: Schedule = scheduleExpiry) {
    this.dispose = dispose;
    this.now = now;
    this.schedule = schedule;
  }

  private readonly dispose: (id: string) => void;
  private readonly now: () => number;
  private readonly schedule: Schedule;

  has(id: string): boolean { return this.entries.has(id); }

  remember(id: string, owner: string): void {
    this.forget(id);
    const expires = this.now() + lifetime;
    this.entries.set(id, { owner, expires, cancel: this.schedule(() => this.discard(id), lifetime) });
    if (this.entries.size > capacity) this.discard(this.entries.keys().next().value!);
  }

  take(id: string, owner: string): boolean {
    const entry = this.entries.get(id);
    if (!entry || entry.owner !== owner) return false;
    if (entry.expires <= this.now()) {
      this.discard(id);
      return false;
    }
    this.forget(id);
    return true;
  }

  forget(id: string): void {
    this.entries.get(id)?.cancel();
    this.entries.delete(id);
  }

  discard(id: string): void {
    if (!this.entries.has(id)) return;
    this.forget(id);
    this.dispose(id);
  }
}
