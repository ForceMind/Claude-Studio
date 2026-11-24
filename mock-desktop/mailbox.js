'use strict';
const confirmButton = document.getElementById('confirm');
const statusLine = document.getElementById('status');
window.showMessage = ({recipient, message}) => {
  window.currentMessage = message;
  document.getElementById('recipient').textContent = recipient;
  statusLine.textContent = message ? '有一封模拟登录确认邮件' : '暂无邮件';
  confirmButton.disabled = !message;
};
confirmButton.addEventListener('click', () => {
  window.mailResult = window.mockMail('complete', window.currentMessage);
  window.mailResult.then(result => {
    statusLine.textContent = '已确认 ' + result.identity;
    confirmButton.disabled = true;
  }, error => { statusLine.textContent = error.message; });
});
