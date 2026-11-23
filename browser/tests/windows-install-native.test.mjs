import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { copyFile, link, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { after, before, test } from 'node:test';
import { compileWindowsVerifier } from '../platform/windows-artifact.mjs';

const execute = promisify(execFile);
const windows = { skip: process.platform !== 'win32' || process.arch !== 'x64' };
const pin = 'a'.repeat(64);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const platformSource = name => fileURLToPath(new URL(`../platform/${name}`, import.meta.url));
let root, currentImage, candidateImage, syntheticHelper, disabledHelper, productionHelper, currentHash, nextHash;
const children = new Set();

before(async () => {
  if (windows.skip) return;
  root = await mkdtemp(path.join(tmpdir(), 'claude-native-install-'));
  const compiler = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  const compile = (output, sources, defines = []) => execute(compiler,
    ['/nologo', '/target:exe', '/platform:x64', '/r:System.Web.Extensions.dll', ...defines,
      '/out:' + output, ...sources], { windowsHide: true, timeout: 30_000 });
  const actor = await readFile(new URL('./fixtures/windows-install-actor.cs', import.meta.url), 'utf8');
  const actorSource = path.join(root, 'actor.cs');
  currentImage = path.join(root, 'current-fixture.exe');
  candidateImage = path.join(root, 'candidate-fixture.exe');
  await writeFile(actorSource, actor.replace('SYNTHETIC_VERSION', '1.0.0'));
  await compile(currentImage, [actorSource]);
  await writeFile(actorSource, actor.replace('SYNTHETIC_VERSION', '1.0.1'));
  await compile(candidateImage, [actorSource]);
  currentHash = digest(await readFile(currentImage)); nextHash = digest(await readFile(candidateImage));
  const trustSource = path.join(root, 'trust.cs');
  const trust = await readFile(new URL('./fixtures/windows-install-trust.cs', import.meta.url), 'utf8');
  await writeFile(trustSource, trust.replace('SYNTHETIC_CURRENT_HASH', currentHash).replace('SYNTHETIC_CANDIDATE_HASH', nextHash));
  const authSource = path.join(root, 'auth.cs');
  const auth = await readFile(platformSource('windows-authenticode.cs'), 'utf8');
  await writeFile(authSource, auth.replace('private const string EmbeddedInstallPins = ""; // BUILD_INSTALL_PINS',
    `private const string EmbeddedInstallPins = "${pin}";`));
  syntheticHelper = path.join(root, 'synthetic-helper.exe');
  await compile(syntheticHelper, [authSource, platformSource('windows-install.cs'), trustSource], ['/define:CLAUDE_INSTALL_NATIVE_TEST']);
  disabledHelper = await compileWindowsVerifier(path.join(root, 'disabled-helper.exe'));
  productionHelper = await compileWindowsVerifier(path.join(root, 'production-helper.exe'), { installPins: [pin] });
});

after(async () => {
  // Each case waits its synthetic launcher; never terminate an unrelated PID.
  for (const child of children) if (child.exitCode === null) await once(child, 'exit');
  if (root) {
    assert.equal(path.dirname(root), path.resolve(tmpdir()));
    assert.ok(path.basename(root).startsWith('claude-native-install-'));
    await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  }
});

async function makeCase({ helper = syntheticHelper, expiryMs = 30_000, hash = nextHash, current = '1.0.0', candidate = '1.0.1' } = {}) {
  const installDir = await mkdtemp(path.join(root, 'case-'));
  const launcher = path.join(installDir, 'ClaudeBrowser.exe');
  const inner = path.join(installDir, 'inner', 'ClaudeBrowser.exe');
  const work = path.join(installDir, '.browser-local', 'update-install');
  const job = path.join(work, 'job-' + randomBytes(16).toString('hex'));
  await mkdir(job, { recursive: true }); await mkdir(path.dirname(inner));
  const helperFile = path.join(job, 'windows-authenticode.exe');
  await Promise.all([copyFile(currentImage, launcher), copyFile(currentImage, inner),
    copyFile(candidateImage, path.join(job, 'candidate.exe')), copyFile(helper, helperFile)]);
  const profile = path.join(installDir, '.browser-local', 'synthetic-profile.json');
  await writeFile(profile, '{"accountA":"synthetic-a","accountB":"synthetic-b","tabs":["about:blank"]}');
  const previousId = (await stat(launcher, { bigint: true })).ino;
  return { installDir, launcher, inner, job, helperFile, profile, previousId,
    args: ['--launcher', inner, helperFile, job, hash, String(Date.now() + expiryMs), 'normal', current, candidate] };
}

function launch(fixture, scenario = 'normal') {
  const args = [...fixture.args]; args[6] = scenario;
  const child = spawn(fixture.launcher, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  children.add(child);
  let output = '', error = '';
  child.stdout.on('data', chunk => { output += chunk; }); child.stderr.on('data', chunk => { error += chunk; });
  let processError;
  child.on('error', value => { processError = value; });
  return { child, output: () => output, diagnostics: () => `${output}\n${error}\n${processError || ''}` };
}
async function until(predicate, diagnostic, timeout = 15_000) {
  const expiry = Date.now() + timeout;
  while (Date.now() < expiry) { const value = await predicate(); if (value) return value; await delay(20); }
  assert.fail('等待原生交接结果超时：' + diagnostic());
}
async function ready(run) {
  const line = await until(() => run.output().split(/\r?\n/).find(value => /^(?:READY |RESULT )/.test(value)), run.diagnostics);
  assert.match(line, /^READY [a-f0-9]{64}$/, run.diagnostics());
  return line.slice(6);
}
async function result(fixture, run) {
  const value = await until(async () => {
    try { return JSON.parse(await readFile(path.join(fixture.job, 'result.json'), 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error; return null; }
  }, run.diagnostics);
  if (run.child.exitCode === null) await once(run.child, 'exit');
  return value;
}
async function commit(fixture, run) {
  const nonce = await ready(run);
  run.child.stdin.end('COMMIT ' + nonce + '\n');
  await until(() => run.output().includes('COMMITTED ' + nonce), run.diagnostics);
  return result(fixture, run);
}
async function oldPreserved(fixture) {
  assert.equal(digest(await readFile(fixture.launcher)), currentHash);
  assert.equal(await readFile(fixture.profile, 'utf8'), '{"accountA":"synthetic-a","accountB":"synthetic-b","tabs":["about:blank"]}');
}

test('生产编译默认关闭安装；不接受运行参数开启测试或指定安装 pin', windows, async () => {
  for (const args of [['--install'], ['--install', '--test', pin]]) {
    await assert.rejects(execute(disabledHelper, args, { windowsHide: true }), error => {
      assert.equal(JSON.parse(error.stdout.trim().slice(7)).code, 'INSTALL_DISABLED'); return true;
    });
  }
  await assert.rejects(compileWindowsVerifier(path.join(root, 'bad-pins.exe'), { installPins: ['a'.repeat(40)] }), /SHA-256/);
});

test('两组真实合成 launcher/app 进程经 ACK 退出后同卷换入，旧版备份和资料保留', windows, async () => {
  for (let group = 0; group < 2; group++) {
    const fixture = await makeCase();
    const run = launch(fixture);
    const installed = await commit(fixture, run);
    assert.equal(installed.status, 'installed', run.diagnostics() + JSON.stringify(installed));
    assert.equal(installed.code, 'INSTALLED');
    assert.equal(digest(await readFile(fixture.launcher)), nextHash);
    assert.notEqual((await stat(fixture.launcher, { bigint: true })).ino, fixture.previousId);
    assert.equal(digest(await readFile(path.join(fixture.job, 'previous.exe'))), currentHash);
    assert.equal(installed.backupName, 'previous.exe');
    assert.match(await readFile(fixture.profile, 'utf8'), /synthetic-a/);
  }
});

test('EOF 与错误 nonce 不提交且保留当前程序和资料', windows, async () => {
  for (const message of [null, 'COMMIT ' + '0'.repeat(64) + '\n']) {
    const fixture = await makeCase(); const run = launch(fixture); await ready(run);
    run.child.stdin.end(message || undefined);
    const refused = await result(fixture, run);
    assert.equal(refused.code, 'COMMIT_REJECTED'); await oldPreserved(fixture);
  }
});

test('app 或 NSIS launcher 继续运行时过期，不杀进程、不替换', windows, async () => {
  for (const scenario of ['hold-app', 'hold-launcher']) {
    const fixture = await makeCase({ expiryMs: 2000 }); const run = launch(fixture, scenario);
    const refused = await commit(fixture, run);
    assert.equal(refused.code, 'PROCESS_EXIT_TIMEOUT', run.diagnostics()); await oldPreserved(fixture);
  }
});

test('原生拒绝候选哈希、精确版本和降级异常', windows, async () => {
  for (const [options, code] of [[{ hash: '0'.repeat(64) }, 'CANDIDATE_HASH_MISMATCH'],
    [{ current: '0.9.0' }, 'VERSION_MISMATCH'], [{ candidate: '1.0.0' }, 'DOWNGRADE_REJECTED']]) {
    const fixture = await makeCase(options); const run = launch(fixture); run.child.stdin.end();
    const line = await until(() => run.output().split(/\r?\n/).find(value => value.startsWith('RESULT ')), run.diagnostics);
    assert.equal(JSON.parse(line.slice(7)).code, code, run.diagnostics());
    if (run.child.exitCode === null) await once(run.child, 'exit'); await oldPreserved(fixture);
  }
});

test('生产安装验证不使用合成信任夹具：无签名实际映像不能进入 READY', windows, async () => {
  const fixture = await makeCase({ helper: productionHelper }); const run = launch(fixture); run.child.stdin.end();
  const refused = await result(fixture, run);
  assert.equal(refused.code, 'UNSIGNED_ARTIFACT', run.diagnostics());
  assert.doesNotMatch(run.output(), /^READY /m); await oldPreserved(fixture);
});

test('同一安装目录并发事务由原生锁拒绝，首个事务仍能完成', windows, async () => {
  const first = await makeCase(); const firstRun = launch(first); await ready(firstRun);
  const secondJob = path.join(path.dirname(first.job), 'job-' + randomBytes(16).toString('hex'));
  await mkdir(secondJob);
  const secondHelper = path.join(secondJob, 'windows-authenticode.exe');
  await copyFile(syntheticHelper, secondHelper); await copyFile(candidateImage, path.join(secondJob, 'candidate.exe'));
  const second = { ...first, job: secondJob, helperFile: secondHelper, args: [...first.args] };
  second.args[2] = secondHelper; second.args[3] = secondJob;
  const secondRun = launch(second); secondRun.child.stdin.end();
  const line = await until(() => secondRun.output().split(/\r?\n/).find(value => value.startsWith('RESULT ')), secondRun.diagnostics);
  assert.equal(JSON.parse(line.slice(7)).code, 'INSTALL_BUSY', secondRun.diagnostics());
  if (secondRun.child.exitCode === null) await once(secondRun.child, 'exit');
  await oldPreserved(first);
  // READY was observed already, so commit with that original nonce.
  const nonce = firstRun.output().match(/^READY ([a-f0-9]{64})/m)[1];
  firstRun.child.stdin.end('COMMIT ' + nonce + '\n');
  assert.equal((await result(first, firstRun)).status, 'installed');
});

test('原生拒绝候选硬链接和映像目录 junction，保留旧程序', windows, async () => {
  const linked = await makeCase();
  await link(path.join(linked.job, 'candidate.exe'), path.join(linked.job, 'candidate-hardlink.exe'));
  const linkedRun = launch(linked); linkedRun.child.stdin.end();
  assert.equal((await result(linked, linkedRun)).code, 'HARD_LINK_REJECTED'); await oldPreserved(linked);

  const junction = await makeCase(); const alias = path.join(junction.installDir, 'inner-junction');
  await symlink(path.dirname(junction.inner), alias, 'junction');
  junction.args[1] = path.join(alias, 'ClaudeBrowser.exe');
  const junctionRun = launch(junction); junctionRun.child.stdin.end();
  const line = await until(() => junctionRun.output().split(/\r?\n/).find(value => value.startsWith('RESULT ')), junctionRun.diagnostics);
  assert.equal(JSON.parse(line.slice(7)).code, 'REPARSE_PATH', junctionRun.diagnostics());
  if (junctionRun.child.exitCode === null) await once(junctionRun.child, 'exit'); await oldPreserved(junction);
});

test('原生拒绝伪造调用进程、UNC 和回收站路径', windows, async () => {
  const fixture = await makeCase();
  const args = ['--install', fixture.job, fixture.launcher, fixture.inner, String(process.pid), String(process.ppid),
    '1.0.0', '1.0.1', nextHash, String(Date.now() + 30_000)];
  await assert.rejects(execute(fixture.helperFile, args, { windowsHide: true }), error => {
    assert.equal(JSON.parse(error.stdout.trim().slice(7)).code, 'PROCESS_IMAGE_MISMATCH'); return true;
  });
  for (const unsafe of ['\\\\synthetic.invalid\\share\\job', 'C:\\$Recycle.Bin\\job', 'C:\\safe\\..\\job']) {
    const bad = [...args]; bad[1] = unsafe;
    await assert.rejects(execute(fixture.helperFile, bad, { windowsHide: true }), error => {
      assert.equal(JSON.parse(error.stdout.trim().slice(7)).code, 'UNSAFE_PATH'); return true;
    });
  }
  await oldPreserved(fixture);
});

test('替换前合成故障保留旧入口；替换后合成故障恢复已验证备份', windows, async () => {
  for (const [marker, code, recovered] of [['fail-before-replace', 'SYNTHETIC_REPLACE_FAILURE', false],
    ['fail-after-replace', 'SYNTHETIC_POST_REPLACE_FAILURE', true]]) {
    const fixture = await makeCase(); await writeFile(path.join(fixture.job, marker), 'synthetic fault');
    const run = launch(fixture); const refused = await commit(fixture, run);
    assert.equal(refused.status, 'failed', run.diagnostics() + JSON.stringify(refused));
    assert.equal(refused.code, code); assert.equal(refused.recovered, recovered); await oldPreserved(fixture);
  }
});
