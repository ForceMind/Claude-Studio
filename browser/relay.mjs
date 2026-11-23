import net from 'node:net';
import { checkPort } from './settings.mjs';

const loopback = '127.0.0.1';

function acceptsConnections(port, timeout) {
  return new Promise(resolve => {
    const probe = net.connect({ host: loopback, port });
    const finish = result => { probe.destroy(); resolve(result); };
    probe.setTimeout(timeout, () => finish(false));
    probe.once('error', () => finish(false));
    probe.once('connect', () => finish(true));
  });
}

// Forward opaque bytes to one numeric loopback endpoint. Never resolve or dial a web destination.
/** @param {(online: boolean) => void} [changed] */
export async function startRelay(port, changed = () => {}, interval = 1000) {
  checkPort(port);
  if (!await acceptsConnections(port, 800)) throw new Error('本地代理端口未监听。');
  const sockets = new Set();
  let online = true;
  let closed = false;
  let checking = false;
  const server = net.createServer(client => {
    client.on('error', () => client.destroy());
    if (closed || !online) { client.destroy(); return; }
    const upstream = net.connect({ host: loopback, port });
    sockets.add(client);
    sockets.add(upstream);
    const release = () => {
      sockets.delete(client);
      sockets.delete(upstream);
      client.destroy();
      upstream.destroy();
    };
    client.once('close', release);
    upstream.once('close', release);
    upstream.on('error', release);
    upstream.setTimeout(2000, release);
    upstream.once('connect', () => {
      upstream.setTimeout(0);
      client.pipe(upstream).pipe(client);
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: loopback, port: 0, exclusive: true }, resolve);
  });
  // A stopped upstream could free its port between the probe and bind.
  if (server.address().port === port) {
    server.close();
    throw new Error('临时转发端口与上游端口冲突，请重试。');
  }
  const timer = setInterval(async () => {
    if (checking || closed) return;
    checking = true;
    const reachable = await acceptsConnections(port, 800);
    checking = false;
    if (closed || online === reachable) return;
    online = reachable;
    if (!online) for (const stream of sockets) stream.destroy();
    changed(online);
  }, interval);
  return {
    port: server.address().port,
    get online() { return online; },
    close() {
      if (closed) return;
      closed = true;
      clearInterval(timer);
      server.close();
      for (const stream of sockets) stream.destroy();
    }
  };
}
