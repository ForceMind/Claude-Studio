const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const readline = require('node:readline');

const [prefix, logPath, certificate, key, wrongCertificate, wrongKey] = process.argv.slice(2);
if (!/^studio-[a-f0-9]{16}$/.test(prefix)) throw new Error('Invalid N3 target prefix');

const connections = new Set();
const opened = [];
let eventCount = 0;
function event(kind, fields = {}) {
  if (++eventCount > 6000) throw new Error('N3 target event limit exceeded');
  fs.appendFileSync(logPath, `${JSON.stringify({ kind, pid: process.pid, utc: new Date().toISOString(), ...fields })}\n`, 'utf8');
}

function track(server) {
  server.on('connection', socket => {
    if (connections.size >= 32) return socket.destroy();
    connections.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => connections.delete(socket));
  });
  return new Promise((resolve, reject) => {
    opened.push(server);
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function handle(req, res) {
  const protocol = req.socket.encrypted ? 'tls' : 'http';
  const match = /^\/(n3|hold)\/([a-f0-9]{16})$/.exec(req.url);
  const peer = req.socket.remotePort;
  const host = req.headers.host;
  const shape = new RegExp(`^${prefix}-a-window-(baseline|healthy|stopped|outage|recovered|cold|crash|silent|fake)[1-9]?\\.test(?::9443)?$`);
  if (req.method !== 'GET' || !shape.test(host)) {
    res.writeHead(400, { 'Content-Length': 0 }).end();
    return;
  }
  if (!match) {
    if (/^\/studio-probe\?[a-z0-9]+$/.test(req.url)) {
      event('legacy-marker', { protocol, peer, host });
      res.writeHead(200, { 'Content-Length': Buffer.byteLength(prefix) }).end(prefix);
    } else res.writeHead(400, { 'Content-Length': 0 }).end();
    return;
  }
  const [, action, marker] = match;
  event('target', { protocol, action, marker, peer, host });
  if (action === 'n3') {
    const body = `target:${marker}`;
    res.writeHead(200, { 'Content-Length': Buffer.byteLength(body) }).end(body);
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
  res.flushHeaders();
  let sequence = 0;
  const timer = setInterval(() => {
    if (res.destroyed || sequence >= 120) {
      clearInterval(timer);
      res.end();
      return;
    }
    const line = `${marker}:${++sequence}`;
    event('stream-mark', { protocol, marker, sequence, peer });
    res.write(`${line}\n`);
  }, 65);
  res.once('close', () => clearInterval(timer));
}

function tlsServer(cert, privateKey) {
  const server = https.createServer({ cert: fs.readFileSync(cert), key: fs.readFileSync(privateKey) }, handle);
  server.on('tlsClientError', (error, socket) => event('tls-error', { code: error.code, peer: socket.remotePort }));
  return server;
}

function halfServer() {
  return net.createServer({ allowHalfOpen: true }, socket => {
    const peer = socket.remotePort;
    let marker = '';
    socket.setEncoding('ascii');
    socket.on('data', data => {
      marker += data;
      if (marker.length > 16) socket.destroy();
    });
    socket.on('end', () => {
      if (!/^[a-f0-9]{16}$/.test(marker)) return socket.destroy();
      event('half', { protocol: 'tcp', marker, peer });
      socket.end(`half:${marker}`);
    });
  });
}

function stop() {
  for (const socket of connections) socket.destroy();
  for (const server of opened) server.close();
}

async function main() {
  const [httpPort, tlsPort, halfPort, wrongCertificatePort] = await Promise.all([
    track(http.createServer(handle)), track(tlsServer(certificate, key)), track(halfServer()),
    track(tlsServer(wrongCertificate, wrongKey)),
  ]);
  console.log(JSON.stringify({ kind: 'ready', pid: process.pid, http: httpPort, tls: tlsPort, half: halfPort,
    wrongCertificate: wrongCertificatePort }));
  const control = readline.createInterface({ input: process.stdin, terminal: false });
  control.on('line', command => {
    if (command === 'exit') control.close();
    else throw new Error('Unexpected target control');
  });
  control.once('close', stop);
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 2;
  stop();
});
