const { spawn } = require('node:child_process');

async function launchWorker(executable, args, env) {
  const child = spawn(executable, args, {env, stdio: ['ignore', 'ignore', 'inherit', 'ipc']});
  let receive;
  const wait = send => new Promise((resolve, reject) => {
    const timer = setTimeout(() => receive(new Error('Simulator process did not respond within 20 seconds')), 20000);
    receive = (error, value) => {
      clearTimeout(timer);
      receive = undefined;
      if (error) reject(error);
      else resolve(value);
    };
    send?.();
  });
  const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({code, signal})));
  child.on('message', ({value, error}) => receive?.(error && new Error(error), value));
  child.on('error', error => receive?.(error));
  child.once('exit', (code, signal) => receive?.(new Error('Simulator process exited: ' + (signal || code))));
  async function stop(timeout = 3000) {
    if (child.connected) child.send({action: 'quit'}, () => {});
    const timer = setTimeout(() => {
      if (child.pid && child.exitCode === null && child.signalCode === null) child.kill();
    }, timeout);
    try { return await closed; } finally { clearTimeout(timer); }
  }
  try {
    const initial = await wait();
    return {
      pid: child.pid, initial, closed, stop,
      async request(action, values = {}) {
        if (!child.connected || receive) throw new Error('Simulator process is unavailable');
        return wait(() => child.send({action, ...values}, error => { if (error) receive?.(error); }));
      }
    };
  } catch (error) {
    await stop();
    throw error;
  }
}

function serveWorker(actions) {
  process.on('message', async ({action, ...values}) => {
    try {
      if (action === 'quit' && !Object.hasOwn(actions, action)) return;
      const value = await actions[action](values);
      if (process.connected && action !== 'quit') process.send({value});
    } catch (error) {
      if (process.connected) process.send({error: error.message});
    }
  });
}

module.exports = { launchWorker, serveWorker };
