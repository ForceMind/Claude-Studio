const { deepStrictEqual, ok } = require('node:assert/strict');

async function verifyRecovery({ fixture, profiles, observe, report }) {
  const { ports, requests, hits } = fixture;
  const phases = report.phases;

  async function checkPhase({ phase, proxy, expected, holdStream, configure, endsStream }) {
    const port = ports[proxy];
    const beforeRequests = requests.length;
    const beforeHits = hits.length;
    const windows = await observe({ phase, port, holdStream, configure });
    const record = {
      phase, port, expected, windows, traffic: requests.slice(beforeRequests), targetHits: hits.slice(beforeHits)
    };
    phases.push(record);
    record.controlDirectReachable = await fixture.checkControl();
    ok(record.controlDirectReachable, phase + ' control could not reach the target');
    if (endsStream) await fixture.waitForStreamEnds(endsStream);
    deepStrictEqual(record.traffic.map(item => item.via + '/' + item.profile + '/' + item.mode + '/' + item.stage).sort(),
      expected === 'stopped' ? [] : profiles.map(({name}) =>
        proxy + '/' + name + '/' + expected + '/' + phase).sort(), phase + ' proxy requests');
    deepStrictEqual(record.targetHits.map(item => item.via + '/' + item.profile + '/' + item.stage).sort(),
      expected !== 'healthy' ? [] : profiles.map(({name}) => proxy + '/' + name + '/' + phase).sort(), phase + ' target hits');

    for (const [i, result] of windows.entries()) {
      const { name, zone, offsets, displayed } = profiles[i];
      const { probe, clocks, previousStream } = result;
      ok(result.profileMarkerMatches, name + ' profile marker changed');
      ok(result.route === 'PROXY 127.0.0.1:' + port, name + ' route changed');
      deepStrictEqual(clocks, { nativeZone: zone, offsets, selected: zone, displayed }, name + ' clocks');
      if (endsStream) {
        ok(['closed', 'interrupted'].includes(previousStream?.state), name + ' old stream was not interrupted');
        const ended = hits.find(hit => hit.profile === name && hit.stage === endsStream);
        ok(ended?.closedAt, name + ' old stream was still open at the target');
      }

      if (expected === 'healthy') {
        ok(probe.status === 200 && probe.markerMatched && !probe.error, name + ' healthy proxy did not forward');
      } else if (expected === 'stopped') {
        ok(probe.error?.includes('ERR_PROXY_CONNECTION_FAILED') && !probe.timedOut, name + ' failure was not a refused proxy connection');
      } else if (expected === 'reject') {
        ok(probe.status === 503 && !probe.markerMatched && !probe.error, name + ' rejecting proxy returned an unexpected result');
      } else {
        ok(probe.timedOut && !probe.status, name + ' request did not time out at the silent proxy');
      }
      const state = expected === 'healthy' ? ' · 在线' : ' · 代理不可用，窗口离线';
      ok(result.ui === '127.0.0.1:' + port + state, name + ' window status mismatch');
    }
    record.passed = true;
    console.log(phase + ' · 127.0.0.1:' + port + ' · A/B 通过');
  }

  await checkPhase({ phase: 'initial-p-stream', proxy: 'P', expected: 'healthy', holdStream: true, configure: true });
  await fixture.stopP();
  await checkPhase({ phase: 'p-stopped', proxy: 'P', expected: 'stopped', endsStream: 'initial-p-stream' });
  await fixture.restartPRejecting();
  await checkPhase({ phase: 'p-rejecting', proxy: 'P', expected: 'reject' });
  fixture.recover('P');
  await checkPhase({ phase: 'recovered-p-stream', proxy: 'P', expected: 'healthy', holdStream: true });
  const switchStarted = requests.length;
  report.switchPreparation = await observe({ phase: 'close-p-stream' });
  await fixture.waitForStreamEnds('recovered-p-stream');
  for (const window of report.switchPreparation) {
    ok(['closed', 'interrupted'].includes(window.previousStream?.state), window.profile + ' old stream was not interrupted');
    ok(hits.some(hit => hit.stage === 'recovered-p-stream' && hit.profile === window.profile && hit.closedAt),
      window.profile + ' old stream was still open at the target');
    ok(window.ui === '正在切换代理，窗口离线', window.profile + ' was not marked offline during the switch');
  }
  await checkPhase({ phase: 'switch-to-q', proxy: 'Q', expected: 'silent', configure: true });
  report.oldProxyStillListening = fixture.oldProxyListening();
  ok(report.oldProxyStillListening, 'The previous proxy stopped listening during the switch');
  fixture.recover('Q');
  await checkPhase({ phase: 'recovered-q', proxy: 'Q', expected: 'healthy' });
  report.directTargetHits = hits.filter(hit => hit.via === 'direct').length;
  report.oldProxyRequestsAfterSwitch = requests.slice(switchStarted).filter(request => request.via === 'P').length;
  ok(report.directTargetHits === 0, 'The target received direct traffic from the simulator');
  ok(report.oldProxyRequestsAfterSwitch === 0, 'The previous proxy received traffic during or after the switch');
}

module.exports = { verifyRecovery };
