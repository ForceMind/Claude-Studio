const { BrowserWindow, ipcMain } = require('electron');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const { join } = require('node:path');
const { validateCallback } = require('./mock-callback.cjs');

async function readOptional(file) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function save(file, value) {
  await fs.writeFile(file + '.tmp', JSON.stringify(value));
  await fs.rename(file + '.tmp', file);
}

async function attachMail(desktop, root, profile) {
  const recipient = profile.toLowerCase() + '@example.invalid';
  const directory = join(root, 'mail');
  await fs.mkdir(directory, {recursive: true});
  const inbox = join(directory, 'latest.json');
  const sessionFile = join(root, 'desktop', 'simulated-login.json');
  let identity = (await readOptional(sessionFile))?.identity;
  if (identity !== recipient) identity = null;
  let pending;
  let mailbox;
  let queue = Promise.resolve();
  function serialize(operation) {
    const result = queue.then(operation);
    queue = result.catch(() => {});
    return result;
  }
  async function display() {
    const label = identity || (pending ? '等待邮箱确认' : '未登录');
    await desktop.webContents.executeJavaScript('document.getElementById("login-state").textContent = ' + JSON.stringify(label));
  }
  async function openMail() {
    if (!mailbox || mailbox.isDestroyed()) {
      mailbox = new BrowserWindow({parent: desktop, width: 420, height: 250,
        title: '模拟邮箱 ' + profile, autoHideMenuBar: true,
        webPreferences: {partition: 'persist:mock-mail-' + profile, preload: join(__dirname, 'mail-preload.cjs'),
          sandbox: true, contextIsolation: true, nodeIntegration: false}});
      mailbox.webContents.setWindowOpenHandler(() => ({action: 'deny'}));
      await mailbox.loadFile(join(__dirname, 'mailbox.html'));
    }
    const message = await readOptional(inbox);
    await mailbox.webContents.executeJavaScript('window.showMessage(' + JSON.stringify({recipient, message}) + ')');
    mailbox.show();
    return {recipient};
  }

  ipcMain.handle('mock:mail', (event, action, payload) => {
    const fromDesktop = event.sender === desktop.webContents;
    const fromMailbox = mailbox && !mailbox.isDestroyed() && event.sender === mailbox.webContents;
    if (event.senderFrame !== event.sender.mainFrame) throw new Error('INVALID_SENDER');
    const perform = async () => {
      if (fromDesktop && action === 'login') {
        const next = {recipient, ticket: randomUUID(), expires: Date.now() + 300000};
        await save(inbox, next);
        pending = next;
        await display();
        if (mailbox && !mailbox.isDestroyed()) await openMail();
        return {recipient};
      }
      if (fromDesktop && action === 'mailbox') return openMail();
      if (fromMailbox && action === 'complete') {
        try { validateCallback(pending, payload, recipient); }
        catch (error) {
          if (error.message === 'EXPIRED_CALLBACK') { pending = undefined; await display(); }
          throw error;
        }
        await save(sessionFile, {identity: recipient});
        identity = recipient;
        pending = undefined;
        await display();
        return {identity};
      }
      throw new Error('INVALID_SENDER');
    };
    return serialize(perform);
  });
  desktop.once('closed', () => { if (mailbox && !mailbox.isDestroyed()) mailbox.destroy(); });
  await display();
  // The verifier drives the same buttons and mailbox IPC as the manual demo.
  async function verify({mailAction: action, message}) {
    if (process.env.SPACE_VERIFY !== 'yes') throw new Error('Verification only');
    if (action === 'state') return desktop.webContents.executeJavaScript('document.getElementById("login-state").textContent');
    if (action === 'login' || action === 'mailbox') {
      return desktop.webContents.executeJavaScript('document.getElementById(' + JSON.stringify(action) + ').click(); window.mailResult');
    }
    if (!mailbox || mailbox.isDestroyed()) throw new Error('MAILBOX_CLOSED');
    if (action === 'inbox') return mailbox.webContents.executeJavaScript('window.currentMessage');
    if (action === 'complete') return mailbox.webContents.executeJavaScript('document.getElementById("confirm").click(); window.mailResult');
    if (action === 'deliver') return mailbox.webContents.executeJavaScript('window.mockMail("complete", ' + JSON.stringify(message) + ')');
    throw new Error('Unknown mail action');
  }
  return {openMail: () => serialize(openMail), verify};
}

module.exports = {attachMail};
