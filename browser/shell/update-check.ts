const minute = 60_000;
const day = 24 * 60 * minute;
const noonOffset = 4 * 60 * minute; // Asia/Shanghai 12:00 is 04:00 UTC.
const retryDelays = [30_000, 2 * minute, 10 * minute];

export type Trigger = 'startup' | 'noon' | 'both';
export type UpdateStatus =
  | { kind: 'checking'; trigger: Trigger }
  | { kind: 'available'; trigger: Trigger; checkedAt: number; version: string }
  | { kind: 'current' | 'unreachable' | 'invalid'; trigger: Trigger; checkedAt: number };

type Clock = {
  now(): number;
  schedule(callback: () => void, delay: number): () => void;
};

const systemClock: Clock = {
  now: Date.now,
  schedule(callback, delay) {
    const timer = setTimeout(callback, delay);
    return () => clearTimeout(timer);
  }
};

export class InvalidManifest extends Error {}

function latestNoon(now: number): number {
  return Math.floor((now - noonOffset) / day) * day + noonOffset;
}

export class UpdateCheck {
  private readonly check: (signal: AbortSignal) => Promise<string | undefined>;
  private readonly publish: (status: UpdateStatus) => void;
  private readonly clock: Clock;
  private readonly openedAt: number;
  private pendingOpen = false;
  private completedNoon = -Infinity;
  private observedNoon = -Infinity;
  private retryAt = -Infinity;
  private failures = 0;
  private cancelTimer?: () => void;
  private request?: AbortController;
  private closed = false;

  constructor(
    check: (signal: AbortSignal) => Promise<string | undefined>,
    publish: (status: UpdateStatus) => void,
    clock: Clock = systemClock
  ) {
    this.check = check;
    this.publish = publish;
    this.clock = clock;
    this.openedAt = clock.now();
  }

  open(): void {
    this.pendingOpen = true;
    if (!this.request) this.resetRetry();
    this.resume();
  }

  online(): void {
    if (Number.isFinite(this.retryAt)) this.resetRetry();
    this.resume();
  }

  resume(): void {
    this.cancelTimer?.();
    this.cancelTimer = undefined;
    if (this.closed || this.request) return;

    const now = this.clock.now();
    const noon = latestNoon(now);
    const daily = noon > this.openedAt && noon > this.completedNoon;
    if (daily && noon > this.observedNoon) {
      this.observedNoon = noon;
      this.resetRetry();
    }
    const pending = this.pendingOpen || daily;
    if (pending && now >= this.retryAt) {
      const request = new AbortController();
      this.request = request;
      const trigger: Trigger = this.pendingOpen ? (daily ? 'both' : 'startup') : 'noon';
      this.publish({ kind: 'checking', trigger });
      void this.run(request, trigger, daily ? noon : undefined);
      return;
    }
    // Reconcile wall-clock changes even when no focus or resume event arrives.
    const next = Math.min(noon + day, now + minute, pending ? this.retryAt : Infinity);
    this.cancelTimer = this.clock.schedule(() => this.resume(), next - now);
  }

  close(): void {
    this.closed = true;
    this.cancelTimer?.();
    this.request?.abort();
  }

  private resetRetry(): void {
    this.failures = 0;
    this.retryAt = -Infinity;
  }

  private async run(request: AbortController, trigger: Trigger, noon?: number): Promise<void> {
    try {
      const version = await this.check(request.signal);
      if (request.signal.aborted) return;
      this.pendingOpen = false;
      if (noon !== undefined) this.completedNoon = noon;
      this.resetRetry();
      const checkedAt = this.clock.now();
      this.publish(version ? { kind: 'available', trigger, checkedAt, version } : { kind: 'current', trigger, checkedAt });
    } catch (error) {
      if (request.signal.aborted) return;
      const checkedAt = this.clock.now();
      const invalid = error instanceof InvalidManifest;
      const delay = retryDelays[Math.min(this.failures++, retryDelays.length - 1)];
      this.retryAt = invalid ? Infinity : checkedAt + delay;
      this.publish({ kind: invalid ? 'invalid' : 'unreachable', trigger, checkedAt });
    } finally {
      this.request = undefined;
      this.resume();
    }
  }
}
