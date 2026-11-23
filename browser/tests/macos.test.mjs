import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assertMacSigningDetails, buildMacPackages, createMacBuildPlan, getMacBuildArtifacts } from '../platform/macos.mjs';

const projectDir = process.cwd();
const identity = 'Developer ID Application: Example Organization (A1B2C3D4E5)';
const plan = options => createMacBuildPlan({ projectDir, env: {}, ...options });

test('macOS 本地默认生成两种架构 DMG 与 ZIP，隔离 Windows 运行时与发布配置', () => {
  const result = plan();
  assert.deepEqual(result.architectures, ['arm64', 'x64']);
  assert.deepEqual(result.config.mac.target, [
    { target: 'dmg', arch: ['arm64', 'x64'] },
    { target: 'zip', arch: ['arm64', 'x64'] }
  ]);
  assert.equal(result.config.electronDist, null);
  assert.equal(result.config.publish, null);
  assert.equal(result.config.mac.artifactName, 'ClaudeBrowser-${version}-mac-${arch}.${ext}');
  assert.equal(result.config.appId, 'com.claudestudio.browser');
  assert.ok(result.config.files.includes('!**/.browser-local/**'));
  assert.equal(result.verification.runtimeAndProfileMigration, 'requires-arm64-and-x64-mac-validation');
});

test('存在签名、公证环境变量也不将普通构建升级为正式签名或上传', () => {
  const result = plan({ env: { MAC_SIGNING_IDENTITY: identity, APPLE_KEYCHAIN_PROFILE: 'existing-profile' } });
  assert.equal(result.config.mac.identity, '-');
  assert.equal(result.config.mac.hardenedRuntime, false);
  assert.equal(result.config.mac.notarize, false);
  assert.equal(result.config.forceCodeSigning, false);
  assert.equal(result.config.dmg.sign, false);
  assert.equal(result.verification.stapledTicket, false);
});

test('正式签名明确指定 Developer ID，开启 Hardened Runtime 且不自动公证', () => {
  const result = plan({ mode: 'signed', identity });
  assert.equal(result.config.mac.identity, 'Example Organization (A1B2C3D4E5)');
  assert.equal(result.config.mac.type, 'distribution');
  assert.equal(result.config.forceCodeSigning, true);
  assert.equal(result.config.mac.hardenedRuntime, true);
  assert.equal(result.config.mac.notarize, false);
  assert.equal(result.config.dmg.sign, true);
  assert.equal(result.config.directories.output, 'release/macos/signed');
  assert.equal(result.verification.codeSignature, true);
  assert.equal(result.verification.gatekeeper, false);
  for (const bad of [undefined, '-', 'Example Organization', 'Apple Development: Example (A1B2C3D4E5)', `${identity}\nmalicious`]) {
    assert.throws(() => plan({ mode: 'signed', identity: bad }), /Developer ID/);
  }
});

test('显式公证要求完整凭据，支持 builder 26.18 的三种认证方式且不输出秘密', () => {
  assert.throws(() => plan({ mode: 'notarized', identity }), /公证需要/);
  const credentials = [
    { APPLE_ID: 'synthetic@example.invalid', APPLE_APP_SPECIFIC_PASSWORD: 'synthetic-secret', APPLE_TEAM_ID: 'A1B2C3D4E5' },
    { APPLE_API_KEY: '/synthetic/key.p8', APPLE_API_KEY_ID: 'SYNTHETICKEY', APPLE_API_ISSUER: 'synthetic-issuer' },
    { APPLE_KEYCHAIN_PROFILE: 'synthetic-profile' }
  ];
  for (const env of credentials) {
    const result = plan({ mode: 'notarized', identity, env });
    assert.equal(result.config.mac.notarize, true);
    assert.equal(result.verification.stapledTicket, true);
    assert.equal(result.verification.gatekeeper, true);
    for (const [key, value] of Object.entries(env)) {
      assert.ok(!JSON.stringify(result).includes(key));
      if (key !== 'APPLE_TEAM_ID') assert.ok(!JSON.stringify(result).includes(value));
    }
  }
});

test('公证凭据前一组不完整时失败，不能依靠后续有效组掩盖 builder 的实际优先级', () => {
  for (const env of [
    { APPLE_ID: 'synthetic@example.invalid', APPLE_KEYCHAIN_PROFILE: 'later-profile' },
    { APPLE_APP_SPECIFIC_PASSWORD: 'synthetic-secret', APPLE_KEYCHAIN_PROFILE: 'later-profile' },
    { APPLE_API_KEY_ID: 'partial-key', APPLE_KEYCHAIN_PROFILE: 'later-profile' },
    { APPLE_KEYCHAIN_PROFILE: '  ' }
  ]) assert.throws(() => plan({ mode: 'notarized', identity, env }), /凭据不完整/);
});

test('架构、模式和项目路径必须明确有效，不接受 universal 或重复架构', () => {
  for (const architectures of [[], ['universal'], ['arm64', 'arm64'], ['ia32'], 'x64']) {
    assert.throws(() => plan({ architectures }), /架构/);
  }
  assert.throws(() => plan({ mode: 'publish' }), /mode/);
  assert.throws(() => createMacBuildPlan(), /projectDir/);
  assert.deepEqual(plan({ architectures: ['x64'] }).architectures, ['x64']);
});

test('签名验证拒绝错误发布者、错误团队、ad-hoc 与缺少 Hardened Runtime', () => {
  const valid = `Executable=/synthetic/Claude Browser.app\nCodeDirectory v=20500 size=4096 flags=0x10000(runtime) hashes=42\nAuthority=${identity}\nAuthority=Developer ID Certification Authority\nTeamIdentifier=A1B2C3D4E5`;
  assert.doesNotThrow(() => assertMacSigningDetails(valid, identity));
  for (const details of [
    valid.replace('Authority=Developer ID Application:', 'Authority=Apple Development:'),
    valid.replace('TeamIdentifier=A1B2C3D4E5', 'TeamIdentifier=Z9Y8X7W6V5'),
    valid.replace('flags=0x10000(runtime)', 'flags=0x0(none)'),
    'Signature=adhoc\nTeamIdentifier=not set'
  ]) assert.throws(() => assertMacSigningDetails(details, identity));
});

test('Windows 拒绝执行真正的 macOS 打包，不加载 builder 或调用 Apple 工具', { skip: process.platform === 'darwin' }, async () => {
  await assert.rejects(buildMacPackages({ projectDir }), /必须在 macOS/);
});

test('macOS 构建必须本次生成双架构 DMG 和 ZIP，拒绝残留文件与空包', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'claude-mac-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const output = path.join(root, 'release', 'macos', 'local');
  await mkdir(output, { recursive: true });
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ version: '0.5.0' }));
  const files = ['arm64', 'x64'].flatMap(arch => ['dmg', 'zip'].map(ext =>
    path.join(output, `ClaudeBrowser-0.5.0-mac-${arch}.${ext}`)));
  await Promise.all(files.map(file => writeFile(file, 'location fixture')));
  const localBuild = plan();
  assert.deepEqual(await getMacBuildArtifacts(root, localBuild, files), files);
  await assert.rejects(getMacBuildArtifacts(root, localBuild, files.slice(0, -1)), /未输出.*x64.zip/);
  await writeFile(files[3], '');
  await assert.rejects(getMacBuildArtifacts(root, localBuild, files), /产物无效.*x64.zip/);
});
