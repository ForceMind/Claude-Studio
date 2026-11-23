import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { checkMacArtifactMetadata, getMacArtifactVerificationAvailability, verifyMacArtifact } from '../platform/macos-artifact.mjs';

const policy = { teamId: 'A1B2C3D4E5', arch: process.arch === 'arm64' ? 'arm64' : 'x64', version: '0.4.4' };
const candidate = path.join(process.cwd(), 'synthetic-not-opened.zip');
const metadata = {
  platform: 'darwin', bundleId: 'com.claudestudio.browser', ...policy,
  signerType: 'Developer ID Application', hardenedRuntime: true, adHoc: false
};

test('生产能力明确 unavailable，下载/安装门禁默认关闭', () => {
  const availability = getMacArtifactVerificationAvailability();
  assert.equal(availability.available, false);
  assert.equal(availability.installable, false);
  assert.equal(availability.code, 'MAC_OFFLINE_TRUST_UNAVAILABLE');
  assert.equal(availability.hostSupported, process.platform === 'darwin');
  assert.ok(Object.isFrozen(availability));
});

test('合成元数据全部匹配也不能当作真实代码签名或公证通过', () => {
  const checked = checkMacArtifactMetadata(metadata, policy);
  assert.equal(checked.metadataMatched, true);
  assert.equal(checked.signatureVerified, false);
  assert.equal(checked.notarizationVerified, false);
  assert.equal(checked.installable, false);
  assert.ok(Object.isFrozen(checked));
});

test('固定 Bundle ID、指定 Team、当前架构与精确候选版本逐项匹配', () => {
  const invalid = [
    null, [], {},
    { ...metadata, platform: 'win32' },
    { ...metadata, bundleId: 'com.claudestudio.browser.fake' },
    { ...metadata, teamId: 'Z9Y8X7W6V5' },
    { ...metadata, arch: policy.arch === 'arm64' ? 'x64' : 'arm64' },
    { ...metadata, arch: 'universal' },
    { ...metadata, version: '0.4.3' },
    { ...metadata, version: '0.4.5' },
    { ...metadata, version: '0.4.4-preview.1' }
  ];
  for (const value of invalid) assert.throws(() => checkMacArtifactMetadata(value, policy), /元数据/);
});

test('Developer ID、Hardened Runtime 和非 ad-hoc 声明均是必要的元数据门槛', () => {
  for (const value of [
    { ...metadata, signerType: 'Apple Development' },
    { ...metadata, signerType: 'Developer ID Installer' },
    { ...metadata, hardenedRuntime: false },
    { ...metadata, hardenedRuntime: 'true' },
    { ...metadata, adHoc: true },
    { ...metadata, adHoc: undefined }
  ]) assert.throws(() => checkMacArtifactMetadata(value, policy), /元数据/);
});

test('即便调用方声称代码签名、公证、ticket 全部成功，也绝不产生可安装结果', async () => {
  const claimed = { ...metadata, signatureVerified: true, notarizationVerified: true, ticket: 'synthetic-ticket' };
  assert.equal(checkMacArtifactMetadata(claimed, policy).installable, false);
  await assert.rejects(verifyMacArtifact(candidate, { ...policy, metadata: claimed }), error => {
    assert.equal(error.code, 'MAC_OFFLINE_TRUST_UNAVAILABLE');
    assert.equal(error.installable, false);
    return true;
  });
});

test('生产入口在打开或解压不存在的 ZIP 前拒绝，不回退到在线命令或执行候选 App', async () => {
  await assert.rejects(verifyMacArtifact(candidate, policy), error => {
    assert.equal(error.code, 'MAC_OFFLINE_TRUST_UNAVAILABLE');
    assert.equal(error.availability.available, false);
    assert.equal(error.installable, false);
    assert.notEqual(error.code, 'ENOENT');
    return true;
  });
});

test('参数不完整、相对路径、非 ZIP 与控制字符都被拒绝', async () => {
  for (const invalidPolicy of [
    {}, { ...policy, teamId: 'name-only' }, { ...policy, arch: 'universal' },
    { ...policy, version: 'latest' }, { ...policy, version: '0.4.4\n' }
  ]) await assert.rejects(verifyMacArtifact(candidate, invalidPolicy), /明确指定/);
  for (const file of ['relative.zip', path.join(process.cwd(), 'candidate.dmg'), `${candidate}\n`, undefined]) {
    await assert.rejects(verifyMacArtifact(file, policy), /绝对 ZIP/);
  }
});

test('已取消请求保留取消原因，不会被包装成可重试或验签成功', async () => {
  const controller = new AbortController();
  const reason = new Error('synthetic cancellation');
  controller.abort(reason);
  await assert.rejects(verifyMacArtifact(candidate, { ...policy, signal: controller.signal }), error => error === reason);
});
