import assert from 'node:assert/strict';
import test from 'node:test';
import {
  configuredPageEnvironment, decodePageEnvironment, ExitChecks, exitURL, probeExit
} from '../shell/environment.ts';

const port = 42873;
const expectedProxy = 'PROXY 127.0.0.1:' + port;

test('检查账户出口只接受该账户的代理，并用同一会话读取 IPv4 和 IPv6', async () => {
  for (const ip of ['192.0.2.45', '2001:db8::45']) {
    const calls = [];
    const session = {
      async resolveProxy(url) { calls.push(['proxy', url]); return expectedProxy; },
      async fetch(url, options) {
        calls.push(['fetch', url]);
        assert.equal(options.credentials, 'omit');
        assert.equal(options.redirect, 'error');
        assert.equal(options.cache, 'no-store');
        assert.ok(options.signal instanceof AbortSignal);
        return new Response(ip + '\n');
      }
    };
    const result = await probeExit(session, port, new AbortController().signal);
    assert.equal(result, ip);
    assert.deepEqual(calls, [['proxy', exitURL], ['fetch', exitURL]]);
  }

  for (const route of ['DIRECT', expectedProxy + '; DIRECT', 'PROXY 127.0.0.1:42874']) {
    await assert.rejects(probeExit({
      async resolveProxy() { return route; },
      async fetch() { assert.fail('Unexpected route issued an outbound request'); }
    }, port, new AbortController().signal), /Unexpected exit probe route/);
  }
});

test('拒绝异常出口响应，取消等待中的路由解析时不发起请求', async () => {
  const signal = new AbortController().signal;
  for (const reply of [
    new Response('bad response'),
    new Response('fe80::1%eth0'),
    new Response(' '.repeat(65) + '192.0.2.33'),
    new Response('192.0.2.33', { status: 503 })
  ]) {
    await assert.rejects(probeExit({
      async resolveProxy() { return expectedProxy; },
      async fetch() { return reply; }
    }, port, signal), /exit address|exit probe response/);
  }
  const pending = new AbortController();
  const result = probeExit({
    resolveProxy: () => new Promise(() => {}),
    async fetch() { assert.fail('Cancelled probe issued an outbound request'); }
  }, port, pending.signal);
  pending.abort();
  await assert.rejects(result, { name: 'AbortError' });
});

test('A/B 出口检测独立，断线或改配置后旧检测即使返回也不会覆盖新值', async () => {
  const checks = new ExitChecks(() => {});
  let completeOld;
  let oldSignal;
  const old = checks.check('A', signal => {
    oldSignal = signal;
    return new Promise(resolve => { completeOld = resolve; });
  });
  assert.deepEqual(checks.read('A'), { state: 'checking' });
  assert.deepEqual(checks.read('B'), { state: 'unmeasured' });
  await checks.check('B', async () => '2001:db8::b');
  const b = checks.read('B');
  assert.equal(b.state, 'checked');
  assert.equal(b.address, '2001:db8::b');
  assert.ok(b.checkedAt > 0);
  await checks.check('A', () => assert.fail('Duplicate probe while checking'));

  checks.invalidate('A');
  assert.equal(oldSignal.aborted, true);
  assert.deepEqual(checks.read('A'), { state: 'unmeasured' });
  await checks.check('A', async () => '192.0.2.20');
  completeOld('192.0.2.19');
  await old;
  assert.equal(checks.read('A').address, '192.0.2.20');
  assert.deepEqual(checks.read('B'), b);

  await checks.check('B', async () => { throw new Error('fixture offline'); });
  assert.deepEqual(checks.read('B'), { state: 'failed' });
  await checks.check('B', async () => '192.0.2.90');
  assert.equal(checks.read('B').address, '192.0.2.90');
});

test('环境偏好区分账户设置和可接受的网页读数', () => {
  const a = configuredPageEnvironment(
    { language: 'zh-CN', zone: 'Asia/Shanghai', mail: '' }, ['en-US'], 'America/Los_Angeles'
  );
  const b = configuredPageEnvironment(
    { language: 'system', zone: 'system', mail: '' }, ['ja-JP', 'en-US'], 'America/Los_Angeles'
  );
  assert.deepEqual(a, { language: 'zh-CN', zone: 'Asia/Shanghai' });
  assert.deepEqual(b, { language: 'ja-JP', zone: 'America/Los_Angeles' });
  assert.deepEqual(decodePageEnvironment({ language: 'en-us', zone: 'UTC' }), { language: 'en-US', zone: 'UTC' });
  assert.equal(decodePageEnvironment({ language: '<script>', zone: 'UTC' }), undefined);
  assert.equal(decodePageEnvironment({ language: 'en-US', zone: 'Mars/Phobos' }), undefined);
});
