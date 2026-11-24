'use strict';
const feedback = document.getElementById('feedback');
const panels = {};
let lastClick;

function render(state, updateSettings) {
  for (const [id, panel] of Object.entries(panels)) {
    const {running, language, zone} = state[id];
    panel.querySelector('output').textContent = running ? '运行中' : '已停止';
    if (updateSettings) {
      panel.querySelector('[name=language]').value = language;
      panel.querySelector('[name=zone]').value = zone;
    }
  }
}

for (const id of ['A', 'B']) {
  const panel = document.getElementById('space').content.firstElementChild.cloneNode(true);
  panels[id] = panel;
  panel.querySelector('h2').textContent = '空间 ' + id;
  for (const button of panel.querySelectorAll('button')) {
    const action = button.dataset.action;
    button.id = id + '-' + action;
    button.addEventListener('click', () => {
      feedback.textContent = '处理中';
      const settings = {
        language: panel.querySelector('[name=language]').value,
        zone: panel.querySelector('[name=zone]').value,
        operation: panel.querySelector('[name=operation]').value
      };
      lastClick = window.spaceLauncher.action(action, id, settings).then(result => {
        render(result.state, false);
        feedback.textContent = action === 'save' ? '已保存，下次打开时生效' : '';
        if (action === 'project') {
          feedback.textContent = result.value.text ?? ((result.value.mode === 'ro' ? '只读 · ' : '读写 · ') + result.value.directory);
        }
        return result;
      });
      lastClick.catch(error => { feedback.textContent = error.message; });
    });
  }
  document.querySelector('main').append(panel);
}

const ready = window.spaceLauncher.action('state').then(({state}) => render(state, true));
ready.catch(error => { feedback.textContent = error.message; });

window.clickSimulatorButton = async (id, preferences) => {
  await ready;
  const button = document.getElementById(id);
  if (preferences) {
    for (const name of ['language', 'zone', 'operation']) {
      if (Object.hasOwn(preferences, name)) {
        button.closest('section').querySelector('[name=' + name + ']').value = preferences[name];
      }
    }
  }
  button.click();
  return lastClick;
};
