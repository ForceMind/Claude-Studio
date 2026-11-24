'use strict';
const params = new URLSearchParams(location.search);
const zone = params.get('zone') || new Intl.DateTimeFormat().resolvedOptions().timeZone;
function readClocks() {
  const dates = ['2026-01-15T12:00:00Z', '2026-07-15T12:00:00Z'].map(value => new Date(value));
  const format = new Intl.DateTimeFormat('en-GB', { timeZone: zone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  return {
    nativeZone: new Intl.DateTimeFormat().resolvedOptions().timeZone,
    offsets: dates.map(date => date.getTimezoneOffset()),
    selected: zone, displayed: dates.map(date => format.format(date))
  };
}
const clocks = readClocks();
document.getElementById('title').textContent = '环境模拟 · ' + params.get('profile');
document.getElementById('native').textContent = clocks.nativeZone;
document.getElementById('selected').textContent = zone;
document.getElementById('sample').textContent = '1 月 15 日 ' + clocks.displayed[0] + ' / 7 月 15 日 ' + clocks.displayed[1];
if (params.get('space') === 'yes') {
  const input = document.getElementById('space-note');
  input.value = localStorage.getItem('mock-note') ?? '';
  input.addEventListener('input', () => localStorage.setItem('mock-note', input.value));
  document.getElementById('space-data').hidden = false;
  document.getElementById('space-language').textContent = '窗口首选语言　' + navigator.language;
  for (const action of ['login', 'mailbox']) {
    document.getElementById(action).addEventListener('click', () => {
      window.mailResult = window.mockMail(action);
      window.mailResult.catch(error => { document.getElementById('login-state').textContent = error.message; });
    });
  }
}
