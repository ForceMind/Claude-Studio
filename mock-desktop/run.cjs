// Standalone two-window simulator. Neither path lookup nor process control touches Claude.
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { existsSync } = require('node:fs');
const fs = require('node:fs/promises');
const http = require('node:http');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const electron = require('electron');
const { dropFixture, recoveryFixture } = require('./drop-fixture.cjs');
const { verifyRecovery } = require('./recovery.cjs');

const profiles = [
  { name: 'A', zone: 'Asia/Shanghai', offsets: [-480, -480], displayed: ['20:00', '20:00'] },
  { name: 'B', zone: 'America/Los_Angeles', offsets: [480, 420], displayed: ['04:00', '05:00'] }
];
const switches = process.argv.slice(2);
const portArg = switches.find(s => s.startsWith('--proxy-port='));
const port = portArg === undefined ? null : Number(portArg.split('=')[1]);
const drop = switches.includes('--verify-drop');
const recover = switches.includes('--verify-recover');
if ((drop && recover) || ((drop || recover) && port !== null) ||
    switches.some(s => !['--verify', '--verify-drop', '--verify-recover', portArg].includes(s)) ||
    (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535))) {
  throw new Error('Usage: node run.cjs [--verify] [--proxy-port=10810], --verify-drop, or --verify-recover');
}
const verify = switches.includes('--verify') || drop || recover;
if (drop && !process.allowedNodeEnvironmentFlags.has('--allow-net')) {
  throw new Error('The child-process network-denial check requires a Node runtime with --permission and --allow-net.');
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function nextMessage(child) {
  return new Promise(resolve => {
    const done = result => {clearTimeout(timer); child.off('message', done); child.off('exit', exited);
      child.off('error', failed); resolve(result);};
    const failed = err => done({failure: err.message});
    const exited = () => done({failure: 'Window exited before reporting'});
    const timer = setTimeout(() => done({failure:'No window observation within 30 seconds'}), 30000);
    child.once('message', done); child.once('exit', exited); child.once('error', failed);
    if (child.exitCode !== null || child.signalCode !== null) exited();
  });
}

async function main() {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'profile-window-sim-'));
  const nonce = randomUUID();
  const echoes = new Set();
  const jobs = [];
  let fixture;
  let dropTest;
  let recovery;
  let report = recover ? { simulator: require('electron/package.json').version, mode: 'proxy recovery and switch', phases: [] } : undefined;
  let interrupted = false;
  const stop = () => { for (const { child } of jobs) if (child.connected) child.send('quit', () => {}); };
  const interrupt = () => { interrupted = true; stop(); };
  process.on('SIGINT', interrupt);
  try {
    let proxyPort = port;
    if (drop) {
      dropTest = await dropFixture(nonce);
      proxyPort = dropTest.port;
    } else if (recover) {
      recovery = await recoveryFixture(nonce);
      report.ports = recovery.ports;
      proxyPort = recovery.ports.P;
    } else if (port === null) {
      // The .invalid destination cannot be reached directly. This proxy only answers
      // the two exact probe URLs and never forwards traffic to the network.
      fixture = http.createServer((req, res) => {
        const item = profiles.find(p => req.url === 'http://profile-probe.invalid/' + nonce + '/' + p.name);
        if (!item || req.method !== 'GET') {res.writeHead(403).end(); return;}
        echoes.add(item.name);
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }).end(nonce + '/' + item.name);
      });
      fixture.listen(0, '127.0.0.1');
      await once(fixture, 'listening');
      proxyPort = fixture.address().port;
    }
    for (const p of profiles) {
      if (interrupted) throw new Error('Verification interrupted');
      const dir = path.join(root, p.name);
      await fs.mkdir(dir);
      const url = drop || recover ? (dropTest || recovery).origin + '/' + nonce + '/' + p.name :
        port === null ? 'http://profile-probe.invalid/' + nonce + '/' + p.name : 'https://example.com/';
      const env = { ...process.env, TZ: p.zone, MOCK_PROFILE: p.name, MOCK_ZONE: p.zone, MOCK_DIR: dir,
        MOCK_URL: url, MOCK_PEER: '127.0.0.1:' + proxyPort, MOCK_FIXTURE: port === null ? 'yes' : 'no',
        MOCK_NODE: process.execPath, MOCK_DROP: drop ? 'yes' : 'no', MOCK_RECOVER: recover ? 'yes' : 'no' };
      delete env.ELECTRON_RUN_AS_NODE;
      // Also route loopback target traffic through the proxy; Chromium otherwise exempts it.
      const proxyArgs = recover ? [] : ['--proxy-server=http://127.0.0.1:' + proxyPort, '--proxy-bypass-list=<-loopback>'];
      const child = spawn(electron, ['--user-data-dir=' + dir, ...proxyArgs, __dirname], {
        env, stdio: ['ignore', 'ignore', 'inherit', 'ipc']
      });
      const closed = new Promise(resolve => child.once('close', resolve));
      const reading = nextMessage(child);
      jobs.push({ child, closed, reading });
    }
    const results = await Promise.all(jobs.map(job => job.reading));
    const simultaneous = results.every((r, i) => r.visible && r.pid === jobs[i].child.pid &&
      jobs[i].child.exitCode === null && jobs[i].child.signalCode === null) &&
      new Set(results.map(r => r.handle)).size === 2;
    if (recover) {
      report.simultaneous = simultaneous;
      if (!simultaneous || !results.every((r, i) => r.phase === 'ready' && r.profile === profiles[i].name)) {
        throw new Error('Both simulator windows must be ready: ' + JSON.stringify(results));
      }
      const observe = async command => {
        if (interrupted) throw new Error('Verification interrupted');
        const readings = jobs.map(j => nextMessage(j.child));
        for (const { child } of jobs) {
          if (child.connected) child.send(command, () => {});
        }
        const windows = await Promise.all(readings);
        if (!windows.every((r, i) => r.phase === command.phase && r.visible &&
            r.profile === results[i].profile && r.pid === results[i].pid && r.handle === results[i].handle)) {
          throw new Error('Window observations failed for ' + command.phase + ': ' + JSON.stringify(windows));
        }
        return windows;
      };
      await verifyRecovery({ fixture: recovery, profiles, observe, report });
      if (interrupted) throw new Error('Verification interrupted');
      report.passed = true;
      return;
    }
    if (drop) {
      if (!simultaneous || !results.every((r,i) => r.profile === profiles[i].name && r.phase === 'stream')) {
        throw new Error('Both windows must have live streams before closing the proxy: ' +
          JSON.stringify({results, targetHits:dropTest.counts}));
      }
      await dropTest.stopProxy();
      const reachable = await dropTest.checkControl();
      const readings = jobs.map(j => nextMessage(j.child));
      for (const j of jobs) j.child.send('check-drop');
      const after = await Promise.all(readings);
      const observations = after.map((r, i) => {
        const profile = profiles[i].name, counts = dropTest.counts[profile];
        const passed = r.profile === profile && r.phase === 'drop' && r.pid === jobs[i].child.pid &&
          ['interrupted','closed'].includes(r.stream) && r.failure.includes('ERR_PROXY_CONNECTION_FAILED') &&
          r.childResult === 'ERR_ACCESS_DENIED' && counts.stream === 1 && !counts.after && !counts.child;
        return {profile, streamEnd:r.stream, newRequest:r.failure, workerRequest:r.childResult,
          targetHits:{...counts}, passed};
      });
      report = {simulator:require('electron/package.json').version, mode:'proxy stopped', simultaneous,
        controlDirectReachable:reachable, observations};
      console.log(JSON.stringify(report, null, 2));
      if (!reachable || !observations.every(r => r.passed)) process.exitCode = 1;
      return;
    }
    const observations = results.map((r, i) => {
      const p = profiles[i];
      if (r.failure || !r.clocks) return {profile: p.name, error: r.failure || 'Missing renderer evidence'};
      const selectedProxy = r.proxy === 'PROXY 127.0.0.1:' + proxyPort;
      return { profile: p.name, pid: r.pid, requested: p.zone, nativeZone: r.clocks.nativeZone,
        nativeOffsets: r.clocks.offsets, nativeMatched: r.clocks.nativeZone === p.zone && same(r.clocks.offsets, p.offsets),
        display: r.clocks.displayed, displayMatched: same(r.clocks.displayed, p.displayed),
        proxy: r.proxy, tcpPeerObserved: r.proxyPeer, status: r.status, proxyMatched: selectedProxy && r.proxyPeer && r.status === 200 &&
          (port !== null || (r.body === nonce + '/' + p.name && echoes.has(p.name))),
        ...(r.error ? {error: r.error} : {}) };
    });
    report = { simulator: require('electron/package.json').version, simultaneous,
      mode: port === null ? 'local echo proxy' : 'specified proxy (session route + HTTPS response)',
      observations };
    console.log(JSON.stringify(report, null, 2));
    if (!simultaneous || !observations.every(r => r.nativeMatched && r.displayMatched && r.proxyMatched)) process.exitCode = 1;
    if (!verify && simultaneous) await Promise.all(jobs.map(job => job.closed));
  } catch (err) {
    if (recover) {
      report.passed = false;
      report.error = err.message;
    }
    throw err;
  } finally {
    stop();
    const shutdown = jobs.map(async ({ child, closed }) => {
      const timer = setTimeout(() => child.kill(), 3000);
      try { await closed; } finally { clearTimeout(timer); }
    });
    if (dropTest) shutdown.push(dropTest.close());
    if (recovery) shutdown.push(recovery.close());
    if (fixture?.listening) {
      const closed = once(fixture, 'close');
      fixture.close();
      fixture.closeAllConnections();
      shutdown.push(closed);
    }
    const cleanupErrors = (await Promise.allSettled(shutdown))
      .filter(result => result.status === 'rejected').map(result => result.reason.message);
    if (recovery) {
      report.listenersClosed = recovery.listenersClosed();
      report.targetHits = recovery.hits;
      report.directTargetHits = recovery.hits.filter(hit => hit.via === 'direct').length;
    }
    // Only this run's mkdtemp directory holds the simulated profiles.
    try {
      if (path.dirname(root) === path.resolve(tmpdir()) && path.basename(root).startsWith('profile-window-sim-')) {
        await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      }
    } catch (err) {
      cleanupErrors.push(err.message);
    } finally {
      process.removeListener('SIGINT', interrupt);
    }
    if (verify && report) {
      report.finished = new Date().toISOString();
      report.windowsClosed = jobs.every(j => j.child.exitCode !== null || j.child.signalCode !== null);
      report.tempProfilesRemoved = !existsSync(root);
      const results = path.resolve(__dirname, '..', '.prototype', 'mock-results');
      await fs.mkdir(results, {recursive: true});
      if (cleanupErrors.length) report.cleanupErrors = cleanupErrors;
      if (recover && report.passed && (interrupted || cleanupErrors.length || report.directTargetHits ||
          !report.windowsClosed || !report.tempProfilesRemoved || !report.listenersClosed)) {
        report.passed = false;
        report.error = interrupted ? 'Verification interrupted' : 'Final traffic or cleanup checks failed';
        process.exitCode = 1;
      }
      const output = path.join(results, recover ? 'proxy-recovery.json' :
        drop ? 'proxy-drop.json' : port === null ? 'local.json' : 'proxy-' + port + '.json');
      await fs.writeFile(output, JSON.stringify(report, null, 2) + '\n');
      console.log(output);
    }
    if (cleanupErrors.length) throw new Error('Could not clean up the simulator: ' + cleanupErrors.join(', '));
  }
}
main().catch(err => { console.error(err.message); process.exitCode = 2; });
