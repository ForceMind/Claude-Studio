const { app, BrowserWindow, net, screen } = require('electron');
const { join } = require('node:path');
const fs = require('node:fs/promises');
const { execFile } = require('node:child_process');
const { on } = require('node:events');
const { promisify } = require('node:util');

// Only the simulator launcher supplies these values. Never use a normal app profile.
const { MOCK_PROFILE: profile, MOCK_DIR: directory, MOCK_ZONE: zone, MOCK_URL: url } = process.env;
if (!['A', 'B'].includes(profile) || !directory || !process.send) {
  throw new Error('Start the simulator with node run.cjs');
}
app.setPath('userData', directory);
let window;
process.on('disconnect', () => app.quit());
process.on('message', (message) => {
  if (message === 'quit' || message?.action === 'quit') {
    app.quit();
  }
});
app.on('window-all-closed', () => app.quit());

// The only Node worker this simulator launches has no network permission.
async function directWorkerProbe(destination) {
  const code = [
    "const http = require('node:http');",
    "try { http.get(process.argv[1], r => {r.resume(); console.log('DIRECT:' + r.statusCode);})",
    ".on('error', e => console.log(e.code)); } catch(e) {console.log(e.code);}"
  ].join('\n');
  const { stdout } = await promisify(execFile)(process.env.MOCK_NODE, ['--permission', '-e', code, destination], {
    env: {SystemRoot: process.env.SystemRoot, PATH: process.env.PATH}, timeout: 5000, windowsHide: true
  });
  return stdout.trim();
}

async function observeProxyLoss(session, clocks) {
  const request = async (stage, timeout) => {
    const address = url + '/' + stage;
    if (await session.resolveProxy(address) !== 'PROXY ' + process.env.MOCK_PEER) {
      throw new Error('Unexpected route for ' + stage);
    }
    return session.fetch(address, {
      cache: 'no-store', redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(timeout)
    });
  };
  const response = await request('stream', 45000);
  if (response.status !== 200) throw new Error('Active stream did not open');
  const reader = response.body.getReader();
  const expected = new URL(url).pathname.slice(1).padEnd(4096, '.');
  let prefix = '';
  while (prefix.length < expected.length) {
    const part = await reader.read();
    if (part.done) throw new Error('Proxy stream closed before the test');
    prefix += Buffer.from(part.value).toString('utf8');
  }
  if (prefix !== expected) throw new Error('Proxy stream identity mismatch');
  const disconnected = reader.read().then(r => r.done ? 'closed' : 'unexpected-data',
    err => err.name === 'TimeoutError' || err.name === 'AbortError' ? 'timeout' : 'interrupted');
  const afterDrop = new Promise(resolve => {
    const handle = msg => {if (msg === 'check-drop') {process.off('message', handle); resolve();}};
    process.on('message', handle);
  });
  process.send({phase:'stream', profile, pid:process.pid, visible:window.isVisible(), clocks,
    handle:window.getNativeWindowHandle().toString('hex')});
  await afterDrop;
  let failure = '';
  try {const fresh = await request('after', 5000); await fresh.body?.cancel();}
  catch (err) {failure = err.message;}
  const childResult = await directWorkerProbe(url + '/child');
  const stream = await disconnected;
  await window.webContents.executeJavaScript('document.getElementById("proxy").textContent = ' +
    JSON.stringify(failure ? '代理不可用，窗口离线' : '代理已关闭，请求仍然成功'));
  process.send({phase:'drop', profile, pid:process.pid, stream, failure, childResult});
}

function recoveryProbe(session, address, marker, holdStream) {
  return new Promise(resolve => {
    const request = net.request({ session, url: address, redirect: 'error', credentials: 'omit', cache: 'no-store' });
    const expected = holdStream ? marker.padEnd(4096, '.') : marker;
    let lastDataAt;
    let finishStream;
    const streamEnd = new Promise(settle => { finishStream = settle; });
    const end = state => finishStream({ state, lastDataAt, endedAt: new Date().toISOString() });
    const timer = setTimeout(() => {
      finish({ error: 'Proxy probe timed out', timedOut: true });
      request.abort();
    }, 5000);
    function finish(probe, stream) {
      clearTimeout(timer);
      resolve({ probe, stream });
    }

    request.on('response', response => {
      const status = response.statusCode;
      const streaming = holdStream && status === 200;
      let body = '';
      response.on('data', chunk => {
        if (lastDataAt) {
          end('unexpected-data');
          return;
        }
        body += chunk.toString('utf8');
        if (streaming && body.length >= expected.length) {
          lastDataAt = new Date().toISOString();
          finish({ status, markerMatched: body === expected }, { request, ended: streamEnd });
        }
      });
      response.on('end', () => {
        end('closed');
        finish({ status, markerMatched: !streaming && body === expected });
      });
      response.on('error', err => {
        end('interrupted');
        finish({ error: err.message });
      });
    });
    request.on('error', err => {
      end('interrupted');
      finish({ error: err.message });
    });
    request.on('abort', () => end('interrupted'));
    request.end();
  });
}

async function recoverProxy(session) {
  const expectedMarker = new URL(url).pathname.slice(1);
  const profileMarker = join(app.getPath('userData'), 'recovery-marker');
  let activeStream;
  await fs.writeFile(profileMarker, expectedMarker);
  const commands = on(process, 'message');
  const identity = {
    profile, pid: process.pid, handle: window.getNativeWindowHandle().toString('hex')
  };
  process.send({ ...identity, phase: 'ready', visible: window.isVisible() });
  try {
    for await (const [message] of commands) {
      if (message === 'quit') return;
      const { phase, port, holdStream, configure } = message;
      let previousStream;
      if (phase === 'close-p-stream') {
        if (!activeStream) throw new Error('The old proxy stream was not open');
        const ui = await window.webContents.executeJavaScript(
          'document.getElementById("proxy").textContent = "正在切换代理，窗口离线"');
        activeStream.request.abort();
        previousStream = await activeStream.ended;
        activeStream = undefined;
        await session.closeAllConnections();
        process.send({ ...identity, phase, visible: window.isVisible(), previousStream, ui });
        continue;
      }
      if (configure) {
        await session.setProxy({
          mode: 'fixed_servers', proxyRules: 'http://127.0.0.1:' + port, proxyBypassRules: '<-loopback>'
        });
      }

      const address = url + '/' + phase;
      const route = await session.resolveProxy(address);
      if (route !== 'PROXY 127.0.0.1:' + port) throw new Error('Unexpected route for ' + phase + ': ' + route);
      const { probe, stream } = await recoveryProbe(session, address, expectedMarker, holdStream);
      if (stream) activeStream = stream;
      if (phase === 'p-stopped' && activeStream) {
        previousStream = await activeStream.ended;
        activeStream = undefined;
      }
      const online = probe.status === 200 && probe.markerMatched && !probe.error;
      const label = '127.0.0.1:' + port + (online ? ' · 在线' : ' · 代理不可用，窗口离线');
      const ui = await window.webContents.executeJavaScript('document.getElementById("proxy").textContent = ' + JSON.stringify(label));
      const clocks = await window.webContents.executeJavaScript('window.readClocks()');
      process.send({
        ...identity, phase, visible: window.isVisible(), route, probe, previousStream, ui, clocks,
        profileMarkerMatches: await fs.readFile(profileMarker, 'utf8') === expectedMarker
      });
    }
  } finally {
    await commands.return();
  }
}

app.whenReady().then(async () => {
  const area = screen.getPrimaryDisplay().workArea;
  const width = Math.min(480, Math.floor(area.width / 2));
  window = new BrowserWindow({
    width, height: Math.min(process.env.SPACE_ROOT ? 520 : 370, area.height),
    x: area.x + (profile === 'A' ? 0 : width), y: area.y + 12,
    title: '环境模拟 · ' + profile, autoHideMenuBar: true,
    webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false,
      ...(process.env.SPACE_ROOT ? {preload: join(__dirname, 'mail-preload.cjs')} : {}) }
  });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  if (process.env.SPACE_ROOT) {
    const session = window.webContents.session;
    if (process.env.SPACE_LANGUAGE) session.setUserAgent(session.getUserAgent(), process.env.SPACE_LANGUAGE);
    window.on('close', () => session.flushStorageData());
  }
  await window.loadFile(join(__dirname, 'window.html'), {
    query: { profile, zone: zone || '', ...(process.env.SPACE_ROOT ? {space: 'yes'} : {}) }
  });
  if (process.env.SPACE_ROOT) {
    await require('./space-window.cjs').serveSpaceWindow(window, profile);
    return;
  }
  const session = window.webContents.session;
  if (process.env.MOCK_RECOVER === 'yes') { await recoverProxy(session); return; }
  const clocks = await window.webContents.executeJavaScript('window.readClocks()');
  if (process.env.MOCK_DROP === 'yes') {await observeProxyLoss(session, clocks); return;}
  const proxy = await session.resolveProxy(url);
  let status = 0, body = '', error = '', proxyPeer = false;
  const log = join(directory, 'probe-netlog.json');
  await session.netLog.startLogging(log);
  try {
    const response = await session.fetch(url, {
      redirect: 'error', cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout(12000)
    });
    status = response.status;
    // Only the local test proxy serves the echo; external response content is never stored.
    if (process.env.MOCK_FIXTURE === 'yes') body = await response.text();
  } catch (err) { error = err.message; }
  finally {
    await session.netLog.stopLogging();
    try {
      const trace = JSON.parse(await fs.readFile(log, 'utf8'));
      const connectType = trace.constants.logEventTypes.TCP_CONNECT_ATTEMPT;
      const attempts = trace.events.filter(e => e.type === connectType);
      const peerSockets = new Set(attempts.filter(e => e.params?.address === process.env.MOCK_PEER).map(e => e.source.id));
      proxyPeer = attempts.some(e => peerSockets.has(e.source.id) &&
        e.phase === trace.constants.logEventPhase.PHASE_END && !e.params?.net_error);
    } finally { await fs.unlink(log); }
  }
  await window.webContents.executeJavaScript(
    'document.getElementById("proxy").textContent = ' + JSON.stringify(error.includes('ERR_PROXY_CONNECTION_FAILED') ?
      '代理不可用，窗口离线' : proxy + ' · ' + (status || error))
  );
  process.send({ profile, pid: process.pid, handle: window.getNativeWindowHandle().toString('hex'),
    visible: window.isVisible(), clocks, proxy, proxyPeer, status, body, error });
}).catch(err => {
  process.send?.({ profile, failure: err.message });
  app.quit();
});
