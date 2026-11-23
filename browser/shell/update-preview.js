const result = document.getElementById('result');
const detail = document.getElementById('detail');
const timestamp = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', dateStyle: 'short', timeStyle: 'medium'
});
const triggers = { startup: '启动检查', noon: '中午检查', both: '启动与中午检查' };
const messages = {
  checking: '正在验证版本信息…',
  current: '当前已是最新预览版本。',
  unreachable: '暂时无法连接测试源，稍后重试。',
  invalid: '测试清单验证失败。'
};

function show(status) {
  result.textContent = status.kind === 'available' ? '发现测试版本 ' + status.version : messages[status.kind];
  const time = status.checkedAt === undefined ? '' : ' · ' + timestamp.format(status.checkedAt) + ' 北京时间';
  detail.textContent = triggers[status.trigger] + time;
}

let received = false;
window.updatePreview.subscribe(status => {
  received = true;
  show(status);
});
window.updatePreview.read().then(state => {
  document.getElementById('version').textContent = state.version;
  document.getElementById('source').textContent = state.source;
  if (!received && state.status) show(state.status);
}).catch(() => { result.textContent = '无法读取更新检查状态。'; });
