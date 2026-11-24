const { join, resolve, basename, dirname } = require('node:path');
const fs = require('node:fs/promises');
const { existsSync } = require('node:fs');
const { promisify } = require('node:util');
const { execFile } = require('node:child_process');
const electron = require('electron');
const { launchWorker } = require('./space-process.cjs');
const { verifySpaces } = require('./verify-spaces.cjs');
const { foregroundWindow } = require('./space-native.cjs');
const run = promisify(execFile);

const workspace = resolve(__dirname, '..', '.prototype');
const workflows = process.argv.includes('--verify-workflows');
const verify = workflows || process.argv.includes('--verify');
const environment = {...process.env, SPACE_NODE: process.execPath, SPACE_ELECTRON: electron, SPACE_VERIFY: verify ? 'yes' : 'no'};
for (const key of ['TZ', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_TIME', 'LC_MESSAGES', 'ELECTRON_RUN_AS_NODE']) delete environment[key];

async function hostPreferences() {
  const {stdout} = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    '[TimeZoneInfo]::Local.Id; [Globalization.CultureInfo]::CurrentUICulture.Name; [Globalization.CultureInfo]::CurrentCulture.Name'],
  {timeout: 8000, windowsHide: true, env: environment});
  const [windowsZone, uiLanguage, locale] = stdout.trim().split(/\r?\n/);
  return {windowsZone, uiLanguage, locale};
}

async function main() {
  await fs.mkdir(workspace, {recursive: true});
  const root = verify ? await fs.mkdtemp(join(workspace, 'mock-spaces-test-')) : join(workspace, 'mock-spaces');
  let launcher;
  let interrupted = false;
  const interrupt = () => { interrupted = true; void launcher?.stop(); };
  process.on('SIGINT', interrupt);
  const start = async () => {
    if (interrupted) throw new Error('Simulator run interrupted');
    launcher = await launchWorker(electron, [join(__dirname, 'spaces.cjs')], {...environment, SPACE_ROOT: root});
    if (interrupted) {
      await launcher.stop();
      throw new Error('Simulator run interrupted');
    }
    return launcher;
  };
  const report = {simulator:require('electron/package.json').version, passed: false};
  try {
    if (verify) {
      if (workflows) await require('./verify-workflows.cjs').verifyWorkflows({start, root, report});
      else await verifySpaces({start, report, hostPreferences, foregroundWindow, interactive: process.argv.includes('--interactive')});
      report.passed = true;
    } else {
      await (await start()).closed;
    }
  } catch (error) {
    report.error = error.message;
    throw error;
  } finally {
    process.off('SIGINT', interrupt);
    if (launcher) report.launcherExit = await launcher.stop();
    if (verify && dirname(root) === workspace && basename(root).startsWith('mock-spaces-test-')) {
      await fs.rm(root, {recursive: true, force: true, maxRetries: 5, retryDelay: 200});
      report.testDataRemoved = !existsSync(root);
      if (report.passed && (!report.testDataRemoved || report.launcherExit?.code !== 0)) {
        report.passed = false;
        report.error = 'Simulator shutdown did not complete cleanly';
        process.exitCode = 1;
      }
      report.finished = new Date().toISOString();
      const folder = join(workspace, 'mock-results');
      await fs.mkdir(folder, {recursive: true});
      const file = join(folder, workflows ? 'workflows.json' : 'spaces.json');
      await fs.writeFile(file, JSON.stringify(report, null, 2) + '\n');
      console.log(file);
    }
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
