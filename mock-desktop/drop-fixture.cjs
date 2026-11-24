const http = require('node:http');
const { once } = require('node:events');

async function listen(server, port = 0) {
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  return 'http://127.0.0.1:' + server.address().port;
}

function readControl(origin, nonce) {
  return new Promise((resolve, reject) => {
    http.get(origin + '/' + nonce + '/control', {agent: false, signal: AbortSignal.timeout(3000)}, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', part => { body += part; });
      res.on('end', () => resolve(res.statusCode === 200 && body === nonce));
      res.on('error', reject);
    }).on('error', reject);
  });
}

function forward(url, res, headers = {}) {
  const upstream = http.get(url, {agent: false, headers}, reply => {
    res.writeHead(reply.statusCode, {
      'Cache-Control': 'no-store', 'Content-Type': 'text/plain', 'X-Content-Type-Options': 'nosniff'
    });
    reply.on('error', () => res.destroy());
    reply.pipe(res);
  });
  upstream.on('error', () => res.destroy());
  res.on('close', () => upstream.destroy());
}

async function close(server) {
  if (!server?.listening) return;
  const ended = once(server, 'close');
  server.close();
  server.closeAllConnections();
  await ended;
}

// Both endpoints stay on loopback. The proxy can forward only these run-specific URLs.
async function dropFixture(nonce) {
  const counts = Object.fromEntries(['A', 'B'].map(p => [p, { stream: 0, after: 0, child: 0 }]));
  let controls = 0;
  const target = http.createServer((req, res) => {
    if (req.url === '/' + nonce + '/control') {controls++; res.end(nonce); return;}
    const [empty, id, profile, stage, rest] = req.url.split('/');
    if (empty || id !== nonce || rest !== undefined || !Object.hasOwn(counts, profile) ||
        !Object.hasOwn(counts[profile], stage)) {res.writeHead(404).end(); return;}
    counts[profile][stage]++;
    res.writeHead(200, { 'Cache-Control': 'no-store', 'Content-Type': 'text/plain' });
    if (stage === 'stream') res.write((nonce + '/' + profile).padEnd(4096, '.')); // leave body open after the first block
    else res.end(nonce);
  });
  const origin = await listen(target);
  const proxy = http.createServer((req, res) => {
    const path = ['A', 'B'].map(p => '/' + nonce + '/' + p + '/stream').find(p => origin + p === req.url);
    if (!path || req.method !== 'GET') {res.writeHead(403).end(); return;}
    forward(origin + path, res);
  });
  try {
    await listen(proxy);
    return {
      origin, port: proxy.address().port, counts, stopProxy: () => close(proxy),
      checkControl: async () => {
        // A distinct URL demonstrates that the same target remains directly reachable.
        const count = controls;
        return await readControl(origin, nonce) && controls === count + 1;
      },
      close: async () => {try {await close(proxy);} finally {await close(target);}}
    };
  } catch (err) {await close(target); throw err;}
}

async function recoveryFixture(nonce) {
  const requests = [];
  const hits = [];
  const streams = [];
  const proxies = {
    P: { mode: 'healthy', port: 0 },
    Q: { mode: 'silent', port: 0 }
  };
  let controls = 0;

  function matchPath(pathname) {
    const [empty, id, profile, stage, rest] = pathname.split('/');
    if (!empty && id === nonce && ['A', 'B'].includes(profile) && stage && rest === undefined) {
      return { profile, stage };
    }
  }

  const target = http.createServer((req, res) => {
    if (req.url === '/' + nonce + '/control') {
      controls++;
      res.end(nonce);
      return;
    }
    const probe = matchPath(req.url);
    if (!probe || req.method !== 'GET') {
      res.writeHead(404).end();
      return;
    }
    const entry = { ...probe, via: req.headers['x-fixture-proxy'] || 'direct' };
    hits.push(entry);
    const marker = nonce + '/' + probe.profile;
    res.writeHead(200, { 'Cache-Control': 'no-store', 'Content-Type': 'text/plain' });
    if (probe.stage.endsWith('-stream')) {
      streams.push({ entry, res });
      res.on('close', () => { entry.closedAt = new Date().toISOString(); });
      entry.lastSentAt = new Date().toISOString();
      res.write(marker.padEnd(4096, '.'));
    } else {
      res.end(marker);
    }
  });

  const origin = await listen(target);

  async function startProxy(name, mode) {
    const proxy = proxies[name];
    proxy.mode = mode;
    proxy.server = http.createServer((req, res) => {
      // Forward only the synthetic run's exact loopback URLs.
      const probe = req.url.startsWith(origin + '/') && matchPath(req.url.slice(origin.length));
      if (!probe || req.method !== 'GET') {
        res.writeHead(403).end();
        return;
      }
      requests.push({ ...probe, via: name, mode: proxy.mode });
      if (proxy.mode === 'reject') {
        res.writeHead(503).end();
      } else if (proxy.mode === 'healthy') {
        forward(req.url, res, {'x-fixture-proxy': name});
      }
      // 'silent' accepts the connection and intentionally leaves the request unanswered.
    });
    await listen(proxy.server, proxy.port);
    proxy.port = proxy.server.address().port;
  }

  const servers = () => [proxies.P.server, proxies.Q.server, target];
  const closeAll = async () => {
    const results = await Promise.allSettled(servers().map(close));
    const failed = results.find(result => result.status === 'rejected');
    if (failed) throw failed.reason;
  };
  try {
    await startProxy('P', 'healthy');
    await startProxy('Q', 'silent');
  } catch (err) {
    await closeAll();
    throw err;
  }
  return {
    origin, requests, hits,
    ports: { P: proxies.P.port, Q: proxies.Q.port },
    oldProxyListening: () => proxies.P.server.listening,
    stopP: () => close(proxies.P.server),
    restartPRejecting: () => startProxy('P', 'reject'),
    recover: name => { proxies[name].mode = 'healthy'; },
    checkControl: async () => {
      const before = controls;
      return await readControl(origin, nonce) && controls === before + 1;
    },
    waitForStreamEnds: async stage => {
      await Promise.all(streams.filter(({entry}) => entry.stage === stage && !entry.closedAt)
        .map(({res}) => once(res, 'close', {signal: AbortSignal.timeout(3000)})));
    },
    close: closeAll,
    listenersClosed: () => servers().every(server => !server?.listening)
  };
}

module.exports = { dropFixture, recoveryFixture };
