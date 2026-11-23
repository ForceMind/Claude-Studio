'use strict';

const profiles = {
  A: { language: 'zh-CN', zone: 'Asia/Shanghai' },
  B: { language: 'en-US', zone: 'America/Los_Angeles' }
};
const exampleIP = '192.0.2.24';
const checked = new Set();
const controls = [...document.querySelectorAll('[data-account]')];
const toolbar = document.getElementById('toolbar-account');
const workspace = document.getElementById('workspace-title');
const exit = document.getElementById('demo-exit');
const language = document.getElementById('demo-language');
const zone = document.getElementById('demo-zone');
const check = document.getElementById('demo-check');
const announcement = document.getElementById('demo-announcement');
let account = 'A';

function render() {
  const profile = profiles[account];
  const hasResult = checked.has(account);
  for (const button of controls) {
    button.setAttribute('aria-pressed', String(button.dataset.account === account));
  }
  toolbar.textContent = '账户 ' + account;
  workspace.textContent = '账户 ' + account + ' 的空间';
  exit.textContent = hasResult ? exampleIP : '尚未检测';
  language.textContent = profile.language;
  zone.textContent = profile.zone;
  check.textContent = hasResult ? '再次演示检测' : '演示检测';
  announcement.textContent = '账户 ' + account + '，网页语言 ' + profile.language +
    '，时区 ' + profile.zone + '，示例出口 ' + exit.textContent;
}

for (const button of controls) {
  button.addEventListener('click', () => {
    account = button.dataset.account;
    render();
  });
}

check.addEventListener('click', () => {
  checked.add(account);
  render();
});
