const { deepStrictEqual, ok, strictEqual } = require('node:assert/strict');
const { setTimeout: delay } = require('node:timers/promises');

const data = ({desktop, mail, code}) => ({desktop, mail, code});
const identity = ({pid, handle}) => ({pid, handle});
const settings = {
  A: {language: 'zh-CN', zone: 'Asia/Shanghai', offsets: [-480, -480]},
  B: {language: 'en-US', zone: 'America/Los_Angeles', offsets: [480, 420]}
};
const primaryLanguage = value => value.split(',')[0].split(';')[0].trim().toLowerCase();
const canonicalLocale = value => Intl.getCanonicalLocales(value)[0];

function checkLocale(reading, expected, marker, hostZone) {
  const language = canonicalLocale(expected.language);
  strictEqual(canonicalLocale(reading.language), language);
  strictEqual(canonicalLocale(reading.languages[0]), language);
  strictEqual(primaryLanguage(reading.network.acceptLanguage), language.toLowerCase());
  strictEqual(canonicalLocale(reading.intlLocale), language);
  strictEqual(reading.code.locale, language);
  strictEqual(reading.code.marker, marker);
  strictEqual(reading.clocks.nativeZone, expected.zone);
  deepStrictEqual(reading.clocks.offsets, expected.offsets);
  strictEqual(reading.code.zone, expected.zone);
  deepStrictEqual(reading.code.offsets, expected.offsets);
  strictEqual(reading.windowsZone, hostZone);
}

async function verifySpaces({start, report, hostPreferences, foregroundWindow, interactive}) {
  report.hostBefore = await hostPreferences();
  let launcher = await start();
  const click = async (id, action, preferences) =>
    launcher.request('click', {button: id + '-' + action, preferences});
  const read = (id, command = 'read', text) => launcher.request('window', {id, command, text});
  for (const id of ['A', 'B']) await click(id, 'save', settings[id]);
  const firstA = (await click('A', 'open')).value;
  const firstB = (await click('B', 'open')).value;
  ok(firstA.visible && firstB.visible && firstA.pid !== firstB.pid && firstA.handle !== firstB.handle,
    'A and B must be separate windows');

  const markedA = await read('A', 'write', '空间 A 的测试资料');
  const markedB = await read('B', 'write', '空间 B 的测试资料');
  const original = {A: data(markedA), B: data(markedB)};
  strictEqual(original.A.desktop, '空间 A 的测试资料');
  strictEqual(original.B.desktop, '空间 B 的测试资料');
  for (const key of ['desktop', 'mail', 'code']) ok(original.A[key] !== original.B[key], 'Spaces share ' + key);
  report.lifecycle = {launcherPid: launcher.pid, initial: {A: identity(firstA), B: identity(firstB)}, focus: {}};
  const simulatorPids = [launcher.pid, firstA.pid, firstB.pid];
  const focusErrors = [];
  if (interactive) {
    await launcher.request('armFocus');
    console.log('就绪：请在启动器分别点击空间 A 和空间 B 的「打开或聚焦」');
    const deadline = Date.now() + 300000;
    while (Date.now() < deadline) {
      const samples = await launcher.request('sampleFocus');
      report.lifecycle.focus = samples;
      if (samples.A && samples.B) break;
      await delay(500);
    }
    await launcher.request('endFocus');
  } else {
    const foreground = await foregroundWindow();
    const order = foreground.pid === firstA.pid ? ['B', 'A'] : ['A', 'B'];
    for (const id of order) {
      const before = await foregroundWindow();
      const {value} = await click(id, 'open');
      const after = await foregroundWindow();
      report.lifecycle.focus[id] = {...identity(value), before, after};
    }
  }
  for (const [id, originalWindow] of [['A', firstA], ['B', firstB]]) {
    const sample = report.lifecycle.focus[id];
    if (!sample) {
      focusErrors.push(id);
      continue;
    }
    deepStrictEqual(identity(sample), identity(originalWindow));
    const {before, after} = sample;
    const validSource = interactive ? before.pid === launcher.pid : simulatorPids.includes(before.pid);
    if (!validSource || before.pid === sample.pid || after.pid !== sample.pid || after.handle !== sample.handle) {
      focusErrors.push(id);
    }
  }

  const stopA = await click('A', 'stop');
  ok(!stopA.state.A.running && stopA.state.B.running);
  strictEqual(stopA.value.pid, firstA.pid);
  const remainingB = await read('B');
  deepStrictEqual(identity(remainingB), identity(firstB));
  deepStrictEqual(data(remainingB), original.B);
  const bProbe = await read('B', 'probe');
  strictEqual(bProbe.profile, 'B');
  report.lifecycle.stopA = {AStopped: true, BStillVisible: remainingB.visible, BStillOnline: true};
  ok(remainingB.visible);
  deepStrictEqual(data((await click('A', 'open')).value), original.A);
  const originalLauncher = launcher.pid;
  deepStrictEqual(await launcher.stop(), {code: 0, signal: null});

  launcher = await start();
  ok(launcher.pid !== originalLauncher, 'Launcher did not restart');
  const reopened = {};
  for (const id of ['A', 'B']) {
    const {value, state} = await click(id, 'open');
    strictEqual(state[id].language, settings[id].language);
    strictEqual(state[id].zone, settings[id].zone);
    deepStrictEqual(data(value), original[id]);
    reopened[id] = {...identity(value), desktopRetained: true, mailRetained: true, codeRetained: true};
  }
  report.lifecycle.reopened = { launcherPids: [originalLauncher, launcher.pid], profiles: reopened };
  const stopB = await click('B', 'stop');
  ok(stopB.state.A.running && !stopB.state.B.running);
  strictEqual(stopB.value.pid, reopened.B.pid);
  const remainingA = await read('A');
  deepStrictEqual(identity(remainingA), identity(reopened.A));
  deepStrictEqual(data(remainingA), original.A);
  ok(remainingA.visible);
  strictEqual((await read('A', 'probe')).profile, 'A');
  deepStrictEqual(data((await click('B', 'open')).value), original.B);
  report.lifecycle.stopB = {BStopped: true, AStillVisible: true, AStillOnline: true};
  report.lifecycle.foregroundVerified = !focusErrors.length;
  console.log('A/B 资料独立、单独停止及启动器重开通过' + (focusErrors.length ? '，前台聚焦待核对' : '，前台聚焦通过'));

  report.preferences = { custom: {} };
  for (const id of ['A', 'B']) {
    const observation = await read(id, 'preferences');
    report.preferences.custom[id] = observation;
    strictEqual(observation.network.profile, id);
    checkLocale(observation, settings[id], original[id].code, report.hostBefore.windowsZone);
  }
  const bBefore = await read('B');
  await click('A', 'save', {language: '', zone: ''});
  await click('A', 'stop');
  const {value: aSystem, state} = await click('A', 'open');
  deepStrictEqual(data(aSystem), original.A);
  strictEqual(state.A.language, '');
  strictEqual(state.A.zone, '');
  deepStrictEqual(identity(await read('B')), identity(bBefore));
  const aSystemPrefs = await read('A', 'preferences');
  const bAfter = await read('B', 'preferences');
  report.preferences.systemA = aSystemPrefs;
  report.preferences.BAfterAChanged = bAfter;
  report.hostAfter = await hostPreferences();
  deepStrictEqual(report.hostAfter, report.hostBefore);
  const zone = launcher.initial.systemZone;
  const offsets = ['2026-01-15T12:00:00Z', '2026-07-15T12:00:00Z'].map(value => {
    const part = new Intl.DateTimeFormat('en', {timeZone: zone, timeZoneName: 'longOffset'})
      .formatToParts(new Date(value)).find(item => item.type === 'timeZoneName').value;
    const [, sign, hour, minute] = part.match(/GMT([+-])(\d{2}):(\d{2})/) || [];
    return sign ? (sign === '+' ? -1 : 1) * (Number(hour) * 60 + Number(minute)) : 0;
  });
  checkLocale(aSystemPrefs, {language: launcher.initial.systemLanguage, zone, offsets},
    original.A.code, report.hostBefore.windowsZone);
  deepStrictEqual(bAfter, report.preferences.custom.B);
  console.log('A/B 语言、时区、代理请求头及 A 跟随系统通过');
  ok(!focusErrors.length, 'Could not verify native foreground transfer for: ' + focusErrors.join(', '));
}

module.exports = { verifySpaces };
