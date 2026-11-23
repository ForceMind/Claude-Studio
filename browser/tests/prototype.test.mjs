import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { lookup } from 'node:dns/promises';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { defaults, checkProfile, checkPort, loadSettings, saveSettings, profilePath } from '../settings.mjs';
import { startRelay } from '../relay.mjs';

async function listen(server, port = 0) {
  server.listen({ host: '127.0.0.1', port });
  await once(server, 'listening');
  return server.address().port;
}

async function connect(port) {
  const stream = net.connect(port, '127.0.0.1');
  await once(stream, 'connect');
  stream.on('error', () => {});
  return stream;
}

async function echo(stream, text) {
  const reply = once(stream, 'data');
  stream.write(text);
  assert.equal((await reply)[0].toString(), text);
}

async function until(predicate) {
  for (let i = 0; i < 120; i++) {
    if (predicate()) return;
    await delay(25);
  }
  throw new Error('等待转发状态变化超时。');
}

test('账户资料分离、设置持久化、端口和邮箱输入校验', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'claude-browser-test-'));
  try {
    const settings = await loadSettings(root);
    assert.deepEqual(settings, defaults);
    const b = structuredClone(settings.profiles.B);
    settings.port = 49211;
    settings.profiles.A = checkProfile({ language: 'ja-JP', zone: 'Asia/Tokyo', mail: 'https://mail.test/' });
    await saveSettings(root, settings);
    const restored = await loadSettings(root);
    assert.deepEqual(restored, settings);
    assert.deepEqual(restored.profiles.B, b);
    assert.notEqual(profilePath(root, 'A'), profilePath(root, 'B'));
    assert.throws(() => profilePath(root, '../B'));
    assert.throws(() => checkPort(0));
    assert.throws(() => checkProfile({ ...b, mail: 'https://mail.test/?token=secret' }));
    assert.throws(() => checkProfile({ ...b, zone: 'Mars/Dawn' }));
    assert.equal(checkPort(restored.port), 49211);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('合成上游停听切断已有流，拒绝新的转发，恢复后仍走同一端口；宿主对照保持可用', { timeout: 10000 }, async () => {
  // Both endpoints are disposable loopback fixtures. The listener is closed while accepted sockets stay alive.
  const fixtures = new Set();
  const clients = new Set();
  const seen = [];
  const makeEndpoint = (record) => net.createServer(socket => {
    fixtures.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => fixtures.delete(socket));
    socket.on('data', chunk => { if (record) seen.push(chunk.toString()); socket.write(chunk); });
  });
  const host = makeEndpoint(false);
  const upstream = makeEndpoint(true);
  let a, b, replacement;
  try {
    const hostPort = await listen(host);
    const port = await listen(upstream);
    const existingHost = await connect(hostPort);
    clients.add(existingHost);
    a = await startRelay(port, () => {}, 40);
    b = await startRelay(port, () => {}, 40);
    const socketA = await connect(a.port);
    const socketB = await connect(b.port);
    clients.add(socketA); clients.add(socketB);
    const connectHeader = 'CONNECT account-a.invalid:443 HTTP/1.1\r\nHost: account-a.invalid:443\r\n\r\n';
    await echo(socketA, connectHeader);
    await echo(socketB, 'GET http://account-b.invalid/mail HTTP/1.1\r\n\r\n');
    assert.equal(seen[0], connectHeader);
    const closedB = once(socketB, 'close');
    b.close();
    await closedB;
    await echo(socketA, 'A still connected');
    const closedA = once(socketA, 'close');
    upstream.close();
    await until(() => !a.online);
    await closedA;
    const offline = await connect(a.port);
    clients.add(offline);
    const denied = new Promise(resolve => offline.once('close', resolve));
    offline.write('offline marker');
    await denied;
    assert.equal(seen.some(chunk => chunk.includes('offline marker')), false);
    await assert.rejects(startRelay(port), /未监听/);
    assert.ok((await lookup('localhost')).address);
    await echo(existingHost, 'host established');
    const newHost = await connect(hostPort);
    clients.add(newHost);
    await echo(newHost, 'host new');
    replacement = makeEndpoint(true);
    await listen(replacement, port);
    await until(() => a.online);
    const recovered = await connect(a.port);
    clients.add(recovered);
    await echo(recovered, 'after restart');
  } finally {
    a?.close(); b?.close();
    for (const socket of [...clients, ...fixtures]) socket.destroy();
    for (const server of [host, upstream, replacement]) if (server?.listening) server.close();
  }
});

test('HTTP 正向代理请求与 CONNECT 隧道经上游到达合成目标', { timeout: 6000 }, async () => {
  const markers = [];
  const destinations = [];
  const target = http.createServer((req, res) => {
    markers.push(req.url);
    res.end('target:' + req.url);
  });
  const targetPort = await listen(target);
  const proxy = http.createServer((req, res) => {
    destinations.push(req.url);
    if (req.url !== 'http://fixture.invalid/plain') { res.writeHead(400).end(); return; }
    http.get({ host: '127.0.0.1', port: targetPort, path: '/plain', agent: false }, result => result.pipe(res))
      .on('error', () => res.destroy());
  });
  proxy.on('connect', (req, client, head) => {
    destinations.push(req.url);
    if (req.url !== 'fixture.invalid:443') { client.destroy(); return; }
    const upstream = net.connect(targetPort, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      client.pipe(upstream).pipe(client);
    });
    client.on('error', () => upstream.destroy());
    upstream.on('error', () => client.destroy());
    client.on('close', () => upstream.destroy());
  });
  let relay, tunnel;
  try {
    relay = await startRelay(await listen(proxy));
    const plain = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: relay.port, path: 'http://fixture.invalid/plain', agent: false }, res => {
        let body = ''; res.on('data', chunk => body += chunk); res.on('end', () => resolve(body));
      }).on('error', reject);
    });
    assert.equal(plain, 'target:/plain');
    tunnel = await connect(relay.port);
    const ready = once(tunnel, 'data');
    tunnel.write('CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n');
    assert.match((await ready)[0].toString(), /200 Connection Established/);
    const chunks = [];
    tunnel.on('data', chunk => chunks.push(chunk));
    const end = once(tunnel, 'end');
    tunnel.write('GET /through-tunnel HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n');
    await end;
    assert.match(Buffer.concat(chunks).toString(), /target:\/through-tunnel/);
    assert.deepEqual(markers, ['/plain', '/through-tunnel']);
    assert.deepEqual(destinations, ['http://fixture.invalid/plain', 'fixture.invalid:443']);
  } finally {
    tunnel?.destroy(); relay?.close(); proxy.close(); target.close();
  }
});
