import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { promisify } from 'node:util';
import { compileWindowsVerifier, verifyWindowsArtifact } from '../platform/windows-artifact.mjs';

const execute = promisify(execFile);
const supported = process.platform === 'win32' && process.arch === 'x64';
const windows = { skip: !supported };
const pin = 'a'.repeat(64);
const version = '1.2.3-synthetic.1';
let scratch, verifier, syntheticVerifier, candidate, x86Candidate, appCandidate, responseFile;
const policy = () => ({ verifierPath: verifier, signerPins: [pin], version });
const successfulSyntheticResult = () => ({ schema: 1, ok: true, offline: true, platform: 'win32',
  product: 'Claude Browser', version, outerMachine: 'i386', architectureScope: 'outer-pe-only',
  signerSha256: pin, sha256: 'b'.repeat(64), trustStatus: '0x00000000' });

before(async () => {
  if (!supported) return;
  scratch = await mkdtemp(path.join(tmpdir(), 'claude-authenticode-test-'));
  verifier = await compileWindowsVerifier(path.join(scratch, 'verifier.exe'), { version: '1.2.3' });
  const compiler = path.join(process.env.SystemRoot || 'C:\\Windows',
    'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  const compile = (source, file, architecture = 'x64') => execute(compiler,
    ['/nologo', '/target:exe', '/platform:' + architecture, '/out:' + file, source], { windowsHide: true });
  const fixture = path.join(scratch, 'unsigned.cs');
  await writeFile(fixture, 'using System.Reflection;\n' +
    '[assembly: AssemblyProduct("Claude Browser")]\n' +
    `[assembly: AssemblyInformationalVersion("${version}")]\n` +
    'class Unsigned { static void Main() {} }');
  candidate = path.join(scratch, 'unsigned-x64.exe');
  x86Candidate = path.join(scratch, 'unsigned-x86.exe');
  await compile(fixture, candidate);
  await compile(fixture, x86Candidate, 'x86');
  const appFixture = path.join(scratch, 'unsigned-app.cs');
  await writeFile(appFixture, (await readFile(fixture, 'utf8')).replace(version, '1.2.3.0'));
  appCandidate = path.join(scratch, 'unsigned-app.exe');
  await compile(appFixture, appCandidate);

  // Synthetic protocol peer only: it exercises JS's process/result boundary.
  // This is never used as evidence of trusted Authenticode acceptance.
  syntheticVerifier = path.join(scratch, 'synthetic-verifier.exe');
  responseFile = syntheticVerifier + '.json';
  const peerSource = path.join(scratch, 'peer.cs');
  await writeFile(peerSource, 'using System; using System.IO; using System.Reflection;\n' +
    'class Peer { static int Main(string[] args) {' +
    'string text = File.ReadAllText(Assembly.GetExecutingAssembly().Location + ".json");' +
    'if (text == "WAIT") { System.Threading.Thread.Sleep(30000); return 1; }' +
    'Console.WriteLine(text); return text.Contains("\\\"ok\\\":false") ? 1 : 0; } }');
  await compile(peerSource, syntheticVerifier);
});

after(async () => {
  if (scratch) await rm(scratch, { recursive: true, force: true });
});

test('非 Windows x64 环境禁止构建或验证，不选择弱化替代工具', { skip: supported }, async () => {
  await assert.rejects(compileWindowsVerifier('/synthetic/verifier.exe'), /Windows x64/);
  await assert.rejects(verifyWindowsArtifact('/synthetic/asset.exe', {}), /Windows x64/);
});

test('真实离线 WinVerifyTrust 拒绝产品和版本匹配的无签名 x64 与 x86 外壳', windows, async () => {
  await assert.rejects(verifyWindowsArtifact(candidate, { ...policy(), edition: 'setup' }), { code: 'EDITION_MISMATCH' });
  for (const file of [candidate, x86Candidate]) {
    await assert.rejects(verifyWindowsArtifact(file, policy()), error => {
      assert.equal(error.code, 'UNSIGNED_ARTIFACT');
      assert.equal(error.trustStatus, '0x800B0100');
      return true;
    });
  }
});

test('安装后的 x64 主程序接受零修订号，Setup 仍要求清单的精确版本，助手带正式产品元数据', windows, async () => {
  const stable = { ...policy(), version: '1.2.3' };
  await assert.rejects(verifyWindowsArtifact(appCandidate, { ...stable, edition: 'application' }), { code: 'UNSIGNED_ARTIFACT' });
  await assert.rejects(verifyWindowsArtifact(appCandidate, { ...stable, edition: 'setup' }), { code: 'VERSION_MISMATCH' });
  await assert.rejects(verifyWindowsArtifact(appCandidate, { ...stable, edition: 'application', version: '1.2.4' }),
    { code: 'VERSION_MISMATCH' });
  await assert.rejects(verifyWindowsArtifact(x86Candidate, { ...policy(), edition: 'application' }), { code: 'WRONG_ARCHITECTURE' });
  await assert.rejects(verifyWindowsArtifact(verifier, stable), { code: 'UNSIGNED_ARTIFACT' });
});

test('原生工具拒绝错误 PE、ARM64 和 DLL，不执行候选程序', windows, async () => {
  const bad = path.join(scratch, 'invalid.pending');
  await writeFile(bad, 'not a PE executable');
  await assert.rejects(verifyWindowsArtifact(bad, policy()), { code: 'INVALID_PE' });
  const original = await readFile(candidate);
  const pe = original.readUInt32LE(60);
  const arm = Buffer.from(original);
  arm.writeUInt16LE(0xaa64, pe + 4);
  await writeFile(bad, arm);
  await assert.rejects(verifyWindowsArtifact(bad, policy()), { code: 'WRONG_ARCHITECTURE' });
  const dll = Buffer.from(original);
  dll.writeUInt16LE(dll.readUInt16LE(pe + 22) | 0x2000, pe + 22);
  await writeFile(bad, dll);
  await assert.rejects(verifyWindowsArtifact(bad, policy()), { code: 'INVALID_EXECUTABLE' });
});

test('原生工具直接读取 PE 的产品和完整版本资源，拒绝缺失或损坏资源', windows, async () => {
  await assert.rejects(verifyWindowsArtifact(candidate, { ...policy(), version: '1.2.4' }), { code: 'VERSION_MISMATCH' });
  const original = await readFile(candidate);
  const changedProduct = Buffer.from(original);
  const productOffset = changedProduct.indexOf(Buffer.from('Claude Browser\0', 'utf16le'));
  assert.ok(productOffset > 0);
  changedProduct.writeUInt16LE('X'.charCodeAt(0), productOffset);
  const bad = path.join(scratch, 'bad-metadata.pending');
  await writeFile(bad, changedProduct);
  await assert.rejects(verifyWindowsArtifact(bad, policy()), { code: 'PRODUCT_MISMATCH' });
  const changedResource = Buffer.from(original);
  const rootOffset = changedResource.indexOf(Buffer.from('VS_VERSION_INFO\0', 'utf16le'));
  assert.ok(rootOffset > 6);
  changedResource.writeUInt16LE(1, rootOffset - 6);
  await writeFile(bad, changedResource);
  await assert.rejects(verifyWindowsArtifact(bad, policy()), { code: 'INVALID_VERSION_RESOURCE' });
});

test('候选文件存在可写句柄时原生验证失败关闭', windows, async () => {
  const held = await open(candidate, 'r+');
  try {
    await assert.rejects(verifyWindowsArtifact(candidate, policy()), { code: 'VERIFIER_UNAVAILABLE' });
  } finally { await held.close(); }
});

test('JS 入口拒绝 SHA-1、空 pin、发布者名称、不完整版本及相对路径', windows, async () => {
  for (const signerPins of [[], ['a'.repeat(40)], ['Example Publisher'], [null], undefined]) {
    await assert.rejects(verifyWindowsArtifact(candidate, { ...policy(), signerPins }), /SHA-256/);
  }
  for (const invalid of ['1.2', '', '01.2.3', '1.2.3\n', undefined]) {
    await assert.rejects(verifyWindowsArtifact(candidate, { ...policy(), version: invalid }), /精确/);
  }
  await assert.rejects(verifyWindowsArtifact('candidate.exe', policy()), /绝对/);
  await assert.rejects(verifyWindowsArtifact(candidate, { ...policy(), verifierPath: 'verifier.exe' }), /绝对/);
});

test('合成进程协议保留撤销缓存缺失原因；缺失验签器也失败关闭', windows, async () => {
  await writeFile(responseFile, JSON.stringify({ ok: false, code: 'REVOCATION_CACHE_UNAVAILABLE', trustStatus: '0x80092013' }));
  await assert.rejects(verifyWindowsArtifact(candidate, { ...policy(), verifierPath: syntheticVerifier }), error => {
    assert.equal(error.code, 'REVOCATION_CACHE_UNAVAILABLE');
    assert.equal(error.trustStatus, '0x80092013');
    return true;
  });
  await assert.rejects(verifyWindowsArtifact(candidate, { ...policy(), verifierPath: path.join(scratch, 'missing.exe') }),
    { code: 'VERIFIER_UNAVAILABLE' });
});

test('合成进程协议逐项拒绝证书、产品、版本、架构、在线模式及不完整结果', windows, async () => {
  const options = { ...policy(), verifierPath: syntheticVerifier };
  for (const override of [{ signerSha256: 'c'.repeat(64) }, { product: 'Other Browser' },
    { version: '1.2.4' }, { outerMachine: 'arm64' }, { architectureScope: 'x64-payload' },
    { offline: false }, { ok: false }, { trustStatus: '0x800B0100' }, { sha256: 'bad' }, { schema: 2 }]) {
    await writeFile(responseFile, JSON.stringify({ ...successfulSyntheticResult(), ...override }));
    await assert.rejects(verifyWindowsArtifact(candidate, options));
  }
  await writeFile(responseFile, 'not JSON');
  await assert.rejects(verifyWindowsArtifact(candidate, options), /无效结果/);
  await writeFile(responseFile, JSON.stringify(successfulSyntheticResult()));
  const accepted = await verifyWindowsArtifact(candidate, options);
  assert.equal(accepted.outerMachine, 'i386');
  assert.equal(accepted.arch, undefined, 'does not claim the outer stub proves an x64 payload');
  assert.equal(Object.isFrozen(accepted), true);
});

test('取消会中止合成验签进程，调用方不会取得可安装结果', windows, async () => {
  await writeFile(responseFile, 'WAIT');
  const controller = new AbortController();
  const pending = verifyWindowsArtifact(candidate, { ...policy(), verifierPath: syntheticVerifier, signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, { code: 'ABORT_ERR' });
});
