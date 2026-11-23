import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, readFile, rename, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { checkReleaseManifest, sha256 } from '../update/release-manifest.mjs';
import { applyDemoUpdate, createDemo, demoVersion, runDemoUpdate, startDemoFeed } from '../update/windows-demo.mjs';

const onWindows = { skip: process.platform !== 'win32' };

test('更新清单验证签名、身份、有效期、单调序号、版本、大小和来源', async t => {
  const feed = await startDemoFeed(Buffer.from('synthetic fixture'));
  t.after(() => feed.close());
  const envelope = feed.sign({});
  const candidate = checkReleaseManifest(envelope, feed.policy);
  const previous = { ...feed.policy, previous: candidate.state };
  assert.deepEqual(checkReleaseManifest(envelope, previous), candidate);
  assert.throws(() => checkReleaseManifest(feed.sign({ sequence: 1, version: '1.0.2' }), previous), /序号/);
  assert.throws(() => checkReleaseManifest(envelope, { ...previous, previous: { ...candidate.state, sequence: 2 } }), /序号/);
  const changed = envelope.replace('1.0.1', '1.0.2');
  assert.throws(() => checkReleaseManifest(changed, feed.policy), /签名/);
  for (const invalid of [{ channel: 'stable' }, { product: 'unrelated' }, { platform: 'darwin' },
    { arch: 'arm64' }, { expiresAt: Date.now() - 1 }, { version: '1.0.0' }, { size: 0 },
    { url: 'https://example.invalid/sample.exe' }]) {
    assert.throws(() => checkReleaseManifest(feed.sign(invalid), feed.policy));
  }
});

test('Windows 断开下载与安装确认，取消或校验失败保留旧程序和资料', onWindows, async t => {
  const demo = await createDemo();
  t.after(demo.clean);
  const feed = await startDemoFeed(demo.bytes);
  t.after(() => feed.close());
  const before = await readFile(demo.data, 'utf8');
  assert.equal(await runDemoUpdate(demo, feed, async () => false), 'download-declined');
  assert.equal(feed.assetRequests(), 0);
  assert.equal(await runDemoUpdate(demo, feed, async step => step === 'download'), 'install-declined');
  assert.equal(feed.assetRequests(), 1);
  assert.equal(await demoVersion(demo), '1.0.0');
  const tampered = Buffer.from(demo.bytes);
  tampered[0] ^= 1;
  feed.replaceContent(tampered);
  await assert.rejects(runDemoUpdate(demo, feed, async () => true), /哈希/);
  feed.replaceContent(demo.bytes.subarray(1));
  await assert.rejects(runDemoUpdate(demo, feed, async () => true), /大小/);
  assert.equal(await demoVersion(demo), '1.0.0');
  assert.equal(await readFile(demo.data, 'utf8'), before);
});

test('Windows 用户确认后换包，保留可启动的旧版备份和资料', onWindows, async t => {
  const demo = await createDemo();
  t.after(demo.clean);
  const feed = await startDemoFeed(demo.bytes);
  t.after(() => feed.close());
  const before = await readFile(demo.data, 'utf8');
  assert.equal(await runDemoUpdate(demo, feed, async () => true), 'installed');
  assert.equal(await demoVersion(demo), '1.0.1');
  assert.equal(sha256(await readFile(path.join(demo.root, 'previous.exe'))), demo.previousHash);
  assert.equal(await readFile(demo.data, 'utf8'), before);
});

test('Windows 恢复中断后移走旧包的状态，并在替换前重新校验候选', onWindows, async t => {
  const demo = await createDemo();
  t.after(demo.clean);
  const candidate = { sha256: sha256(demo.bytes) };
  const bad = Buffer.from(demo.bytes);
  bad[0] ^= 1;
  await rename(demo.target, path.join(demo.root, 'previous.exe'));
  await writeFile(path.join(demo.root, 'candidate.pending'), bad);
  await assert.rejects(applyDemoUpdate(demo, candidate), /hash/i);
  assert.equal(await demoVersion(demo), '1.0.0');
  assert.equal(sha256(await readFile(demo.target)), demo.previousHash);
});

test('Windows 拒绝覆盖只读目标，旧程序和资料仍可读取', onWindows, async t => {
  const demo = await createDemo();
  t.after(demo.clean);
  const before = await readFile(demo.data);
  const candidate = { sha256: sha256(demo.bytes) };
  await writeFile(path.join(demo.root, 'candidate.pending'), demo.bytes);
  await chmod(demo.target, 0o444);
  try {
    await assert.rejects(applyDemoUpdate(demo, candidate));
    assert.equal(await demoVersion(demo), '1.0.0');
    assert.deepEqual(await readFile(demo.data), before);
  } finally {
    await chmod(demo.target, 0o666);
  }
});

test('Windows 拒绝替换占用的目标，等待正确的进程且同时只允许一个事务', onWindows, async t => {
  const demo = await createDemo();
  t.after(demo.clean);
  const candidate = { sha256: sha256(demo.bytes) };
  const staged = path.join(demo.root, 'candidate.pending');
  await writeFile(staged, demo.bytes);
  const child = spawn(demo.target, ['--hold'], { stdio: ['pipe', 'pipe', 'ignore'] });
  const exit = once(child, 'exit');
  await once(child.stdout, 'data');
  try {
    await assert.rejects(applyDemoUpdate(demo, candidate));
    assert.equal(sha256(await readFile(demo.target)), demo.previousHash);
    const pending = applyDemoUpdate(demo, candidate, child.pid);
    const second = applyDemoUpdate(demo, candidate, child.pid);
    const outcomes = Promise.allSettled([pending, second]);
    await assert.rejects(Promise.race([pending, second]));
    child.stdin.end();
    const results = await outcomes;
    const errors = results.flatMap(result => result.status === 'rejected' ? [result.reason.stderr || result.reason.message] : []);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1, errors.join(' | '));
  } finally {
    child.stdin.end();
    await exit;
  }
  await stat(path.join(demo.root, 'previous.exe'));
  assert.equal(await demoVersion(demo), '1.0.1');
});
