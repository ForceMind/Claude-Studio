const { app } = require('electron');
const fs = require('node:fs/promises');
const { join } = require('node:path');
const { randomUUID } = require('node:crypto');
const { execFile } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const { promisify } = require('node:util');
const { serveWorker } = require('./space-process.cjs');
const { foregroundWindow } = require('./space-native.cjs');

const run = promisify(execFile);

async function accountMarker(directory) {
  await fs.mkdir(directory, {recursive: true});
  const file = join(directory, 'simulated-marker.txt');
  try {
    await fs.writeFile(file, randomUUID(), {flag: 'wx'});
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  return fs.readFile(file, 'utf8');
}

async function serveSpaceWindow(window, profile) {
  const { SPACE_ROOT: root, SPACE_LANGUAGE: language, SPACE_NODE: node, MOCK_URL: url, MOCK_PEER: proxy } = process.env;
  const session = window.webContents.session;
  const handle = window.getNativeWindowHandle().toString('hex');
  const page = window.webContents;
  async function read() {
    return {
      profile, pid: process.pid, handle, visible: window.isVisible(), focused: window.isFocused(),
      desktop: await page.executeJavaScript('document.getElementById("space-note").value'),
      mail: await accountMarker(join(root, 'mail')),
      code: await accountMarker(join(root, 'code'))
    };
  }
  async function probe() {
    const route = await session.resolveProxy(url);
    if (route !== 'PROXY ' + proxy) throw new Error('Simulator probe did not select its loopback proxy');
    const response = await session.fetch(url, { signal: AbortSignal.timeout(5000), redirect: 'error', cache: 'no-store' });
    if (!response.ok) throw new Error('Simulator probe failed: ' + response.status);
    return { route, ...await response.json() };
  }
  const mail = await require('./mock-mail.cjs').attachMail(window, root, profile);
  serveWorker({
    mail: mail.verify,
    openMailbox: mail.openMail,
    read,
    async project({operation, grant}) {
      const {stdout} = await run(node, [join(__dirname, 'project-worker.cjs'), operation,
        grant.directory, grant.key, grant.mode], {timeout: 5000, windowsHide: true});
      return JSON.parse(stdout);
    },
    async focus() {
      if (window.isMinimized()) window.restore();
      window.show();
      window.focus();
      for (let attempt = 0; attempt < 10 && !window.isFocused(); attempt++) await delay(50);
      return read();
    },
    activate({target}) {
      return foregroundWindow(target);
    },
    async write({text}) {
      if (process.env.SPACE_VERIFY !== 'yes' || typeof text !== 'string' || text.length > 200) {
        throw new Error('Invalid simulator test note');
      }
      await page.executeJavaScript(`(() => {
        const input = document.getElementById('space-note');
        input.value = ${JSON.stringify(text)};
        input.dispatchEvent(new Event('input'));
      })()`);
      session.flushStorageData();
      return read();
    },
    probe,
    async preferences() {
      const renderer = await page.executeJavaScript(`({
        clocks: window.readClocks(),
        language: navigator.language,
        languages: navigator.languages,
        intlLocale: new Intl.DateTimeFormat().resolvedOptions().locale
      })`);
      const network = await probe();
      const {stdout} = await run(node, [join(__dirname, 'space-code.cjs'), language, join(root, 'code')], {
        timeout: 5000, windowsHide: true
      });
      const {stdout: nativeZone} = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
        '[TimeZoneInfo]::Local.Id'], {timeout: 8000, windowsHide: true});
      return {...renderer, network, appLocale: app.getLocale(), code: JSON.parse(stdout), windowsZone: nativeZone.trim()};
    }
  });
  const network = await probe();
  await page.executeJavaScript('document.getElementById("proxy").textContent = ' + JSON.stringify(network.route + ' · 在线'));
  process.send({value: await read()});
}

module.exports = { serveSpaceWindow };
