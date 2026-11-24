const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);
const baseline = 'simulated project baseline\n';

async function git(directory, args) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^git_/i.test(key)));
  Object.assign(env, {GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: 'NUL'});
  const {stdout} = await run('git', ['-c', 'core.autocrlf=false', '-C', directory, ...args],
    {env, windowsHide: true, timeout: 10000});
  return stdout;
}

// Only the simulator's own generated worktree is eligible for a grant.
function projectAccess(root) {
  const directory = path.join(root, 'projects', 'shared');
  const grants = new Map();

  async function prepare() {
    const parent = path.dirname(directory);
    await fs.mkdir(parent, {recursive: true});
    if ((await fs.lstat(parent)).isSymbolicLink()) throw new Error('INVALID_TEST_REPO');
    try {
      const info = await fs.lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('INVALID_TEST_REPO');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const staging = await fs.mkdtemp(path.join(parent, 'init-'));
      try {
        await git(staging, ['init', '--quiet', '--template=']);
        await fs.writeFile(path.join(staging, 'note.txt'), baseline, {flag:'wx'});
        await git(staging, ['add', '--', 'note.txt']);
        await fs.writeFile(path.join(staging, '.git', 'studio-simulator'), 'mock-project-v1');
        await fs.rename(staging, directory);
      } catch (failure) {
        if (path.dirname(path.resolve(staging)) === path.resolve(parent) && path.basename(staging).startsWith('init-')) {
          await fs.rm(staging, {recursive:true, force:true});
        }
        throw failure;
      }
    }
    if (await fs.readFile(path.join(directory, '.git', 'studio-simulator'), 'utf8') !== 'mock-project-v1') {
      throw new Error('INVALID_TEST_REPO');
    }
  }
  return {
    release: id => grants.delete(id),
    async grant(id, mode, candidate = directory) {
      if (!['ro','rw'].includes(mode)) throw new Error('INVALID_MODE');
      await prepare();
      const canonical = await fs.realpath(candidate);
      if (path.relative(await fs.realpath(directory), canonical) !== '') throw new Error('UNAUTHORIZED_PROJECT');
      const info = await fs.stat(canonical, {bigint:true});
      const key = info.dev + '/' + info.ino;
      for (const [owner, grant] of grants) {
        if (owner !== id && mode === 'rw' && grant.mode === 'rw' && grant.key === key) throw new Error('WRITE_CONFLICT');
      }
      grants.set(id, {directory: canonical, mode, key});
      return {mode, directory: canonical};
    },
    require(id, operation) {
      const grant = grants.get(id);
      if (!grant) throw new Error('UNAUTHORIZED_PROJECT');
      if (operation === 'write' && grant.mode !== 'rw') throw new Error('READ_ONLY');
      return grant;
    }
  };
}

module.exports = {projectAccess, git, baseline};
