import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';
import test from 'node:test';
import { promisify } from 'node:util';
import { sha256 } from '../update/release-manifest.mjs';
import { handoffWindowsInstall, lastWindowsInstall, portableInstallContext, setupInstallContext } from '../update/windows-install.mjs';

const execute = promisify(execFile);
const windows = { skip: process.platform !== 'win32' || process.arch !== 'x64' };
const fixtureBytes = Buffer.from('only a handoff fixture');

async function fixture(t, behavior = 'ok', edition) {
  const parent = await realpath(tmpdir());
  const directory = await mkdtemp(path.join(parent, 'claude-handoff-test-'));
  t.after(async () => {
    assert.equal(path.dirname(directory), parent);
    assert.match(path.basename(directory), /^claude-handoff-test-/);
    for (let attempt = 0; ; attempt++) {
      try {
        await rm(directory, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt >= 10 || !['EBUSY', 'EPERM', 'ENOTEMPTY'].includes(error.code)) throw error;
        await setTimeout(25);
      }
    }
  });
  const root = path.join(directory, '.browser-local');
  await mkdir(root);
  const source = path.join(directory, 'Fixture.cs');
  const verifierPath = path.join(directory, 'fixture.exe');
  await writeFile(source, 'using System; using System.IO; class Fixture { static int Main(string[] args) {' +
    (behavior === 'reject' ? 'Console.WriteLine("REJECTED"); return 1;' :
      'string nonce = new string(\'a\',64); Console.WriteLine("READY " + nonce); Console.Out.Flush();' +
      'if (Console.ReadLine() != "COMMIT " + nonce) return 1;' +
      'File.WriteAllText(Path.Combine(args[1], "test-commit.txt"), nonce);' +
      'File.WriteAllText(Path.Combine(args[1], "test-mode.txt"), args[0]);' +
      'Console.WriteLine("COMMITTED " + ' + (behavior === 'bad-echo' ? 'new string(\'b\',64)' : 'nonce') + ');' +
      'Console.Out.Flush(); return 0;') + '}}');
  const compiler = path.join(process.env.SystemRoot || 'C:\\Windows',
    'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  await execute(compiler, ['/nologo', '/target:exe', '/out:' + verifierPath, source], { windowsHide: true });
  const file = path.join(directory, 'fixture-candidate.exe');
  await writeFile(file, fixtureBytes);
  const context = edition === 'setup' ? setupInstallContext({
    appImage: path.join(directory, 'installed', 'ClaudeBrowser.exe'), root, appPid: 111, currentVersion: '0.5.0'
  }) : portableInstallContext({
    launcher: path.join(directory, 'ClaudeBrowser.exe'), appImage: path.join(directory, 'unpacked', 'ClaudeBrowser.exe'),
    root, appPid: 111, launcherPid: 222, currentVersion: '0.5.0'
  });
  assert.ok(context);
  const options = { file, candidate: { version: '0.5.1', sha256: sha256(fixtureBytes), expiresAt: Date.now() + 30_000 },
    verifierPath, verifierHash: sha256(await readFile(verifierPath)), signal: new AbortController().signal,
    async prepare() {}, async revalidate() {} };
  async function jobPath(name) {
    const base = path.join(root, edition === 'setup' ? 'update-install-setup' : 'update-install');
    const jobs = await readdir(base);
    assert.equal(jobs.length, 1);
    return path.join(base, jobs[0], name);
  }
  return { context, root, options, jobPath };
}

test('生产安装入口限定 Windows 本机的原便携文件和资料位置', windows, () => {
  const input = {
    launcher: 'C:\\product\\ClaudeBrowser.exe', appImage: 'C:\\temp\\ClaudeBrowser.exe',
    root: 'C:\\product\\.browser-local', appPid: 5, launcherPid: 6, currentVersion: '0.5.0'
  };
  assert.ok(portableInstallContext(input));
  assert.equal(portableInstallContext({ ...input, launcher: '\\\\host\\share\\ClaudeBrowser.exe' }), undefined);
  assert.equal(portableInstallContext({ ...input, launcher: 'C:\\product\\other.exe' }), undefined);
  assert.equal(portableInstallContext({ ...input, root: 'C:\\other\\.browser-local' }), undefined);
  assert.equal(portableInstallContext({ ...input, launcherPid: input.appPid }), undefined);
  assert.equal(portableInstallContext({ ...input, appImage: input.launcher }), undefined);
});

test('交接先准备资料、再重新验证，匹配的 COMMITTED 才结束', windows, async t => {
  const demo = await fixture(t);
  const ordered = [];
  await handoffWindowsInstall(demo.context, { ...demo.options,
    async prepare() {
      ordered.push('prepare');
      await assert.rejects(readFile(await demo.jobPath('test-commit.txt')), { code: 'ENOENT' });
    },
    async revalidate() { ordered.push('revalidate'); }
  });
  assert.deepEqual(ordered, ['revalidate', 'prepare', 'revalidate']);
  assert.deepEqual(await readFile(await demo.jobPath('candidate.exe')), fixtureBytes);
  assert.equal(await readFile(await demo.jobPath('test-commit.txt'), 'utf8'), 'a'.repeat(64));
});

test('保存失败或状态过期时不发送提交', windows, async t => {
  const failedSave = await fixture(t);
  await assert.rejects(handoffWindowsInstall(failedSave.context, { ...failedSave.options,
    async prepare() { throw new Error('cannot persist profile'); }
  }), /persist profile/);
  await assert.rejects(readFile(await failedSave.jobPath('test-commit.txt')), { code: 'ENOENT' });

  const stale = await fixture(t);
  let checks = 0;
  await assert.rejects(handoffWindowsInstall(stale.context, { ...stale.options,
    async revalidate() {
      if (++checks === 2) throw new Error('stale manifest');
    }
  }), /stale manifest/);
  await assert.rejects(readFile(await stale.jobPath('test-commit.txt')), { code: 'ENOENT' });
});

test('不接受原生子程序拒绝或不匹配确认，读取最近一次独立结果', windows, async t => {
  const rejected = await fixture(t, 'reject');
  await assert.rejects(handoffWindowsInstall(rejected.context, rejected.options), /安装助手/);
  const forged = await fixture(t, 'bad-echo');
  await assert.rejects(handoffWindowsInstall(forged.context, forged.options), /不匹配/);
  await writeFile(await forged.jobPath('result.json'),
    JSON.stringify({ schema: 1, candidateVersion: '0.5.1', status: 'failed' }));
  assert.equal((await lastWindowsInstall(forged.context)).status, 'failed');
});


test('安装版交接隔离临时目录、选择 Setup 模式，并在资料保存失败时取消', windows, async t => {
  const accepted = await fixture(t, 'ok', 'setup');
  await handoffWindowsInstall(accepted.context, accepted.options);
  assert.equal(await readFile(await accepted.jobPath('test-mode.txt'), 'utf8'), '--install-setup');
  await assert.rejects(readdir(path.join(accepted.root, 'update-install')), { code: 'ENOENT' });
  const denied = await fixture(t, 'ok', 'setup');
  await assert.rejects(handoffWindowsInstall(denied.context, { ...denied.options,
    async prepare() { throw new Error('cannot save synthetic profile'); }
  }), /cannot save/);
  await assert.rejects(readFile(await denied.jobPath('test-commit.txt')), { code: 'ENOENT' });
});
