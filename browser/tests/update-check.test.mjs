import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';
import { InvalidManifest, UpdateCheck } from '../shell/update-check.ts';
import { checkPreviewManifest, previewEndpoint, readPreviewFeed } from '../shell/update-preview-feed.ts';

class TestClock {
  constructor(iso) {
    this.time = Date.parse(iso);
  }

  now() {
    return this.time;
  }

  schedule(callback, delay) {
    const timer = { callback, at: this.time + delay };
    this.timer = timer;
    return () => {
      if (this.timer === timer) this.timer = undefined;
    };
  }

  set(iso) {
    this.time = Date.parse(iso);
  }

  tick(iso) {
    this.set(iso);
    if (this.timer?.at <= this.time) this.timer.callback();
  }
}

function service(t, time, transport = async () => undefined) {
  const clock = new TestClock(time);
  const events = [];
  const checker = new UpdateCheck(transport, result => events.push(result), clock);
  t.after(() => checker.close());
  return { clock, events, checker };
}

function attempts(events) {
  return events.filter(event => event.kind === 'checking').map(event => event.trigger);
}

test('每次打开检查，北京时间中午独立检查且同日去重', async t => {
  const { checker, clock, events } = service(t, '2026-11-23T03:59:45Z', async () => '0.4.3-update-preview.2');
  checker.open();
  await setImmediate();
  assert.equal(events.at(-1).kind, 'available');
  assert.equal(events.at(-1).version, '0.4.3-update-preview.2');
  assert.equal(clock.timer.at, Date.parse('2026-11-23T04:00:00Z'));
  clock.tick('2026-11-23T04:00:00Z');
  await setImmediate();
  checker.resume();
  clock.set('2026-11-23T03:59:58Z');
  checker.resume();
  clock.tick('2026-11-23T04:00:00Z');
  assert.deepEqual(attempts(events), ['startup', 'noon']);
  checker.open();
  await setImmediate();
  assert.deepEqual(attempts(events), ['startup', 'noon', 'startup']);
});

test('重复启动合并在途请求，中午仍等待独立检查', async t => {
  const pending = [];
  const { checker, clock, events } = service(t, '2026-11-23T03:59:59Z', () =>
    new Promise(resolve => pending.push(resolve)));
  checker.open();
  checker.open();
  clock.set('2026-11-23T04:00:01Z');
  checker.resume();
  assert.equal(pending.length, 1);
  pending.shift()();
  await setImmediate();
  assert.deepEqual(attempts(events), ['startup', 'noon']);
  assert.equal(pending.length, 1);
  pending.shift()();
  await setImmediate();
});

test('跨日睡眠恢复时只补最近一次，退出后重开查启动项', async t => {
  const { checker, clock, events } = service(t, '2026-11-21T03:30:00Z');
  checker.open();
  await setImmediate();
  clock.set('2026-11-23T04:10:00Z');
  checker.resume();
  await setImmediate();
  checker.resume();
  assert.deepEqual(attempts(events), ['startup', 'noon']);
  checker.close();
  const next = service(t, '2026-11-23T04:11:00Z');
  next.checker.open();
  await setImmediate();
  assert.deepEqual(attempts(next.events), ['startup']);
});

test('断网保留待办，前台聚焦遵守退避，联网后合并到期触发', async t => {
  let online = false;
  const { checker, clock, events } = service(t, '2026-11-23T03:59:50Z', async () => {
    if (!online) throw new Error('offline');
  });
  checker.open();
  await setImmediate();
  assert.equal(events.at(-1).kind, 'unreachable');
  checker.resume();
  assert.deepEqual(attempts(events), ['startup']);
  clock.tick('2026-11-23T04:00:00Z');
  await setImmediate();
  assert.equal(events.at(-1).kind, 'unreachable');
  online = true;
  checker.online();
  await setImmediate();
  assert.equal(events.at(-1).kind, 'current');
  checker.resume();
  assert.deepEqual(attempts(events), ['startup', 'both', 'both']);
});

test('临时错误自动退避，清单错误等到下一次打开才重新检查', async t => {
  const { checker, clock, events } = service(t, '2026-11-23T01:00:00Z', async () => {
    if (clock.now() === Date.parse('2026-11-23T01:00:00Z')) throw new Error('offline');
    if (clock.now() === Date.parse('2026-11-23T01:00:30Z')) throw new InvalidManifest('signature mismatch');
  });
  checker.open();
  await setImmediate();
  clock.tick('2026-11-23T01:00:30Z');
  await setImmediate();
  assert.equal(events.at(-1).kind, 'invalid');
  clock.tick('2026-11-23T01:05:00Z');
  checker.online();
  assert.deepEqual(attempts(events), ['startup', 'startup']);
  checker.open();
  await setImmediate();
  assert.equal(events.at(-1).kind, 'current');
});

test('退出取消在途检查，不再发送结果或安排定时检查', async t => {
  let received;
  let resolveCheck;
  const { checker, clock, events } = service(t, '2026-11-23T03:59:59Z', signal => {
    received = signal;
    return new Promise(resolve => { resolveCheck = resolve; });
  });
  checker.open();
  checker.close();
  assert.equal(received.aborted, true);
  resolveCheck('0.4.3-update-preview.2');
  await setImmediate();
  clock.tick('2026-11-23T04:00:00Z');
  assert.deepEqual(events, [{ kind: 'checking', trigger: 'startup' }]);
  assert.equal(clock.timer, undefined);
});

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const verificationKey = publicKey.export({ type: 'spki', format: 'pem' });
const current = '0.4.3-update-preview.1';
const candidate = '0.4.3-update-preview.2';
const now = Date.parse('2026-11-23T04:00:00Z');
function signedManifest(overrides = {}) {
  const payload = JSON.stringify({ schema: 1, channel: 'update-preview', version: candidate,
    platform: 'win32', arch: 'x64', expiresAt: now + 1, ...overrides });
  return JSON.stringify({ payload, signature: sign(null, Buffer.from(payload), privateKey).toString('base64') });
}

test('校验签名、目标、有效期和预览版本，篡改或降级不报告可用更新', () => {
  const check = envelope => checkPreviewManifest(envelope, verificationKey, current, now);
  assert.equal(check(signedManifest()), candidate);
  assert.equal(check(signedManifest({ version: current })), undefined);
  assert.equal(check(signedManifest({ version: '0.4.2-update-preview.99' })), undefined);
  assert.throws(() => check(signedManifest().replace(candidate, '0.4.9-update-preview.1')), InvalidManifest);
  for (const invalid of [{ arch: 'arm64' }, { platform: 'darwin' }, { channel: 'stable' },
    { expiresAt: now }, { version: '0.4.4' }]) {
    assert.throws(() => check(signedManifest(invalid)), InvalidManifest);
  }
});

test('回环测试源只读取签名清单，拒绝重定向和非回环来源', async t => {
  let mode = 'ok';
  const server = createServer((request, response) => {
    assert.equal(request.url, '/manifest.json');
    assert.equal(request.headers.cookie, undefined);
    if (mode === 'redirect') {
      response.writeHead(302, { Location: '/other' }).end();
    } else if (mode === 'oversized') {
      response.end('a'.repeat(16_385));
    } else {
      response.end(signedManifest());
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const url = previewEndpoint('http://127.0.0.1:' + server.address().port + '/manifest.json');
  const signal = new AbortController().signal;
  const read = () => readPreviewFeed(url, signal);
  assert.equal(checkPreviewManifest(await read(), verificationKey, current, now), candidate);
  mode = 'redirect';
  await assert.rejects(read(), /302/);
  mode = 'oversized';
  await assert.rejects(read(), InvalidManifest);
  assert.throws(() => previewEndpoint('https://example.invalid/manifest.json'));
});
