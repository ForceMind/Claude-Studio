const fs = require('node:fs/promises');
const path = require('node:path');
const {setTimeout: delay} = require('node:timers/promises');

const {STUDIO_LAB_ROOT: root, STUDIO_LAB_ACCOUNT: account} = process.env;
const port = Number(process.env.STUDIO_LAB_PROXY);
const target = Number(process.env.STUDIO_LAB_TARGET);
if (!root || !['A', 'B'].includes(account) || ![port,target].every(p => Number.isInteger(p) && p >= 49152 && p <= 65535)) {
  throw new Error('Invalid lab window configuration');
}

async function driveWindow() {
  const {launchWorker} = require('./space-process.cjs');
  const electron = path.join(__dirname, 'node_modules', 'electron', 'dist', 'electron.exe');
  await fs.access(electron);
  const data = path.join(root, account + '-desktop');
  await fs.mkdir(data);
  const env = {...process.env, TZ: account === 'A' ? 'Asia/Shanghai' : 'America/Los_Angeles'};
  delete env.ELECTRON_RUN_AS_NODE;
  const worker = await launchWorker(electron, [
    '--user-data-dir=' + data, '--proxy-server=http://127.0.0.1:' + port, '--proxy-bypass-list=<-loopback>', __filename
  ], env);
  const exit = await worker.stop(8000);
  console.log(JSON.stringify({...worker.initial, exit}));
}

async function waitForPhase(phase) {
  const until = Date.now() + 15000;
  while (Date.now() < until) {
    if (Number(await fs.readFile(path.join(root,'phase'), 'utf8')) >= phase) return;
    await delay(100);
  }
  throw new Error('Timed out waiting for simulator phase');
}

async function runWindow() {
  const {app, BrowserWindow} = require('electron');
  process.on('disconnect', () => app.quit());
  process.on('message', ({action}) => { if (action === 'quit') app.quit(); });
  await app.whenReady();
  const window = new BrowserWindow({width:420, height:390, x: account === 'A' ? 0 : 440,
    title:'第四轮模拟 ' + account, webPreferences:{sandbox:true, contextIsolation:true, nodeIntegration:false}});
  window.webContents.setWindowOpenHandler(() => ({action:'deny'}));
  await window.loadFile(path.join(__dirname,'window.html'), {query:{profile:account, zone:process.env.TZ}});
  const session = window.webContents.session;
  async function request(stage) {
    const url = 'http://127.0.0.1:' + target + '/studio-probe?' + stage;
    const route = await session.resolveProxy(url);
    if (route !== 'PROXY 127.0.0.1:' + port) throw new Error('Unexpected simulated window proxy route');
    let online = false;
    try {
      const response = await session.fetch(url, {cache:'no-store', redirect:'error', signal:AbortSignal.timeout(2200)});
      online = response.status === 200 && await response.text() === 'studio-probe';
    } catch {}
    await window.webContents.executeJavaScript('document.getElementById("proxy").textContent = ' +
      JSON.stringify(online ? '通过临时代理连接' : '临时代理不可用'));
    return online;
  }
  async function mark(stage) {
    await fs.writeFile(path.join(root,account + '-window-' + stage), '');
  }
  const result = {profile:account, visible:window.isVisible(), healthy:await request('healthy')};
  await mark('ready');
  await waitForPhase(1);
  result.refusing = await request('refusing');
  await mark('failed');
  await waitForPhase(2);
  result.stopped = await request('stopped');
  await mark('stopped');
  await waitForPhase(3);
  result.recovered = await request('recovered');
  process.send({value:result}, () => app.quit());
}

const electronProcess = Boolean(process.versions.electron);
(electronProcess ? runWindow() : driveWindow()).catch(error => {
  if (electronProcess) {
    process.send?.({error:error.message});
    require('electron').app.quit();
  } else {
    console.error(error.message);
    process.exitCode = 1;
  }
});
