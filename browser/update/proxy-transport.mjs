import { startRelay } from '../relay.mjs';

export function createUpdateTransport({ session, readPort, onOnline = () => {}, connect = startRelay }) {
  let current;
  let setup = Promise.resolve();
  let closed = false;

  session.webRequest.onBeforeSendHeaders({ urls: ['https://*/*'] }, (details, callback) => {
    const requestHeaders = { ...details.requestHeaders };
    for (const name of Object.keys(requestHeaders)) {
      if (['cookie', 'authorization', 'referer', 'origin'].includes(name.toLowerCase())) delete requestHeaders[name];
    }
    callback({ requestHeaders });
  });

  function invalidate() {
    const old = current;
    current = undefined;
    old?.lifetime.abort();
    old?.relay?.close();
  }

  function route(port) {
    invalidate();
    const slot = { port, lifetime: new AbortController(), connection: new AbortController() };
    current = slot;
    slot.pending = setup.then(async () => {
      const signal = slot.lifetime.signal;
      signal.throwIfAborted();
      try {
        const relay = await connect(port, online => {
          if (current !== slot) return;
          if (online) onOnline();
          else {
            slot.connection.abort();
            slot.connection = new AbortController();
          }
        });
        slot.relay = relay;
        signal.throwIfAborted();
        await session.setProxy({ mode: 'fixed_servers', proxyRules: 'http://127.0.0.1:' + relay.port,
          proxyBypassRules: '<-loopback>' });
        await session.closeAllConnections();
        signal.throwIfAborted();
        return slot;
      } catch (error) {
        slot.relay?.close();
        if (current === slot) invalidate();
        throw error;
      }
    });
    setup = slot.pending.catch(() => {});
    return slot;
  }

  return {
    async request(url, signal) {
      if (closed || new URL(url).protocol !== 'https:') throw new Error('更新连接未启用。');
      signal.throwIfAborted();
      const port = readPort();
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        invalidate();
        throw new Error('请先配置本地 HTTP 代理。');
      }
      const slot = await (current?.port === port ? current : route(port)).pending;
      const control = AbortSignal.any([signal, slot.lifetime.signal, slot.connection.signal]);
      control.throwIfAborted();
      if (!slot.relay.online || await session.resolveProxy(url) !== 'PROXY 127.0.0.1:' + slot.relay.port) {
        throw new Error('更新专用代理不可用。');
      }
      control.throwIfAborted();
      return session.fetch(url, { method: 'GET', credentials: 'omit', cache: 'no-store',
        redirect: 'error', referrerPolicy: 'no-referrer', signal: control });
    },
    invalidate,
    close() {
      closed = true;
      invalidate();
    }
  };
}
