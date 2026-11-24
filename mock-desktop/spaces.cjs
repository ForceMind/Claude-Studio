const { app, BrowserWindow, ipcMain } = require('electron');
const { join } = require('node:path');
const fs = require('node:fs/promises');
const { mkdirSync } = require('node:fs');
const { randomUUID } = require('node:crypto');
const { createServer } = require('node:http');
const { once } = require('node:events');
const { launchWorker, serveWorker } = require('./space-process.cjs');
const { foregroundWindow } = require('./space-native.cjs');
const { projectAccess } = require('./mock-project.cjs');

const { SPACE_ROOT: root, SPACE_NODE: node, SPACE_ELECTRON: electron } = process.env;
if (!root || !node || !electron || !process.send) throw new Error('Start this simulator with npm run spaces');
const profiles = ['A', 'B'];
const defaults = {
  A: {language: 'zh-CN', zone: 'Asia/Shanghai'},
  B: {language: 'en-US', zone: 'America/Los_Angeles'}
};
const workers = new Map();
const projects = projectAccess(root);
const settingsFile = join(root, 'settings.json');
const launcherData = join(root, 'launcher');
mkdirSync(launcherData, {recursive: true});
app.setPath('userData', launcherData);

let control;
let server;
let settings;
let queue = Promise.resolve();
let shuttingDown = false;
let cleanupComplete = false;
let focusSamples;

function serialize(operation) {
  const next = queue.then(() => {
    if (shuttingDown) throw new Error('Simulator is shutting down');
    return operation();
  });
  queue = next.catch(() => {});
  return next;
}

async function loadSettings() {
  try { return JSON.parse(await fs.readFile(settingsFile, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return defaults;
    throw error;
  }
}

function closeProxy() {
  if (!server?.listening) return Promise.resolve();
  const closed = once(server, 'close');
  server.close();
  server.closeAllConnections();
  return closed;
}

app.on('before-quit', event => {
  if (cleanupComplete) return;
  event.preventDefault();
  if (shuttingDown) return;
  shuttingDown = true;
  void queue.then(async () => {
    await Promise.allSettled([...workers.values()].map(worker => worker.stop()));
    await closeProxy();
  }).catch(error => console.error(error.message)).finally(() => {
    cleanupComplete = true;
    app.quit();
  });
});
process.on('disconnect', () => app.quit());

async function main() {
  settings = await loadSettings();
  const nonce = randomUUID();
  let address;
  server = createServer((req, res) => {
    const profile = profiles.find(id => req.url === 'http://' + address + '/' + nonce + '/' + id);
    if (!profile || req.method !== 'GET') {
      res.writeHead(403).end();
      return;
    }
    res.writeHead(200, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'})
      .end(JSON.stringify({profile, acceptLanguage: req.headers['accept-language'] || ''}));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  address = '127.0.0.1:' + server.address().port;

  const state = () => Object.fromEntries(profiles.map(id => [id, {...settings[id], running: workers.has(id)}]));
  const actions = {
    state,
    async mailbox(id) {
      if (!workers.has(id)) await actions.open(id);
      return workers.get(id).request('openMailbox');
    },
    async project(id, {operation, candidate}) {
      const worker = workers.get(id);
      if (!worker) throw new Error('SPACE_STOPPED');
      if (operation === 'ro' || operation === 'rw') return projects.grant(id, operation, candidate);
      if (!['read','write'].includes(operation)) throw new Error('INVALID_OPERATION');
      const grant = projects.require(id, operation);
      return worker.request('project', {operation, grant});
    },
    async save(id, {language, zone}) {
      if (!['', 'zh-CN', 'en-US'].includes(language) || !['', 'Asia/Shanghai', 'America/Los_Angeles'].includes(zone)) {
        throw new Error('不支持的模拟语言或时区');
      }
      const next = {...settings, [id]: {language, zone}};
      const pending = settingsFile + '.tmp';
      await fs.writeFile(pending, JSON.stringify(next, null, 2) + '\n');
      await fs.rename(pending, settingsFile);
      settings = next;
    },
    async open(id) {
      const current = workers.get(id);
      if (current) {
        const before = focusSamples ? await foregroundWindow() : undefined;
        const window = await current.request('focus');
        const target = {pid: current.pid, handle: window.handle};
        const active = await foregroundWindow(target);
        if (active.pid !== current.pid) {
          const owner = [...workers.values()].find(worker => worker.pid === active.pid);
          if (owner) await owner.request('activate', {target});
        }
        const result = await current.request('read');
        if (before && focusSamples) {
          const after = await foregroundWindow();
          focusSamples[id] = {pid: result.pid, handle: result.handle, before, after};
        }
        return result;
      }
      const {language, zone} = settings[id];
      const account = join(root, id);
      const desktop = join(account, 'desktop');
      await fs.mkdir(desktop, {recursive: true});
      const env = {
        ...process.env, SPACE_ROOT: account, SPACE_LANGUAGE: language, MOCK_PROFILE: id, MOCK_DIR: desktop,
        MOCK_ZONE: zone, MOCK_PEER: address, MOCK_URL: 'http://' + address + '/' + nonce + '/' + id,
        MOCK_RECOVER: 'no', MOCK_DROP: 'no'
      };
      if (zone) env.TZ = zone;
      const args = ['--user-data-dir=' + desktop, '--proxy-server=http://' + address, '--proxy-bypass-list=<-loopback>'];
      if (language) args.push('--lang=' + language);
      args.push(join(__dirname, 'main.cjs'));
      const worker = await launchWorker(electron, args, env);
      workers.set(id, worker);
      void worker.closed.then(() => {
        if (workers.get(id) === worker) {
          projects.release(id);
          workers.delete(id);
        }
      });
      return worker.initial;
    },
    async stop(id) {
      const worker = workers.get(id);
      if (worker) {
        await worker.stop();
        projects.release(id);
        workers.delete(id);
      }
      return { stopped: true, pid: worker?.pid };
    }
  };

  control = new BrowserWindow({
    width: 540, height: 640, title: 'Claude Studio 模拟启动器', autoHideMenuBar: true,
    webPreferences: {preload: join(__dirname, 'spaces-preload.cjs'), sandbox: true, contextIsolation: true}
  });
  control.webContents.setWindowOpenHandler(() => ({action: 'deny'}));
  app.on('window-all-closed', () => app.quit());
  ipcMain.handle('spaces:action', (event, action, id, values) => {
    if (event.sender !== control.webContents || !Object.hasOwn(actions, action) ||
        (action !== 'state' && !profiles.includes(id))) throw new Error('Invalid launcher command');
    return serialize(async () => ({value: await actions[action](id, values), state: state()}));
  });
  await control.loadFile(join(__dirname, 'spaces.html'));
  if (process.env.SPACE_VERIFY === 'yes') {
    serveWorker({
      armFocus() {
        focusSamples = {};
        return true;
      },
      sampleFocus() { return focusSamples; },
      endFocus() { focusSamples = undefined; },
      async click({button, preferences}) {
        return control.webContents.executeJavaScript('window.clickSimulatorButton(' +
          JSON.stringify(button) + ',' + JSON.stringify(preferences ?? null) + ')');
      },
      async window({id, command, text, mailAction, message}) {
        return serialize(() => {
          const worker = workers.get(id);
          if (!worker) throw new Error('SPACE_STOPPED');
          return worker.request(command, {text, mailAction, message});
        });
      },
      async project({id, operation, candidate}) {
        return serialize(() => actions.project(id, {operation, candidate}));
      },
      quit: () => app.quit()
    });
  } else {
    serveWorker({ quit: () => app.quit() });
  }
  process.send({value: {pid: process.pid, address, systemLanguage: app.getLocale(),
    systemZone: new Intl.DateTimeFormat().resolvedOptions().timeZone}});
}

if (app.requestSingleInstanceLock()) {
  app.on('second-instance', () => control?.focus());
  app.whenReady().then(main).catch(error => {
    if (process.connected) process.send({error: error.message});
    app.quit();
  });
} else {
  process.send({error: '这个资料根目录已有一个模拟启动器'});
  app.quit();
}
