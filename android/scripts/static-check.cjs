'use strict';
// Read-only, non-browser checks. These do not compile Kotlin or simulate Android WebView.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
let checks = 0;
function check(name, run) { run(); checks++; process.stdout.write(`PASS ${name}\n`); }
const main = read('app/src/main/java/dev/claudestudio/browser/MainActivity.kt');
const gate = read('app/src/main/java/dev/claudestudio/browser/ProxyGate.kt');
const gradle = read('app/build.gradle.kts');
const manifest = read('app/src/main/AndroidManifest.xml');
check('both channels and closed production gates', () => {
  for (const flavor of ['website', 'play']) {
    assert.ok(gradle.includes(`create("${flavor}")`));
    assert.ok(read(`app/src/${flavor}/java/dev/claudestudio/browser/ChannelUpdateClient.kt`).includes('UpdateClient'));
  }
  assert.match(gradle, /"PLAY_UPDATE_ENABLED", "false"/);
  assert.match(gradle, /Release disabled/);
  assert.doesNotMatch(manifest, /REQUEST_INSTALL_PACKAGES|SCHEDULE_EXACT_ALARM|FOREGROUND_SERVICE/);
});
check('capability and navigation gates are explicit', () => {
  assert.match(main, /isFeatureSupported\(WebViewFeature.MULTI_PROFILE\)/);
  assert.match(gate, /isFeatureSupported\(WebViewFeature.PROXY_OVERRIDE\)/);
  assert.match(main, /check\(canOpen\(account\)\)/);
  assert.match(main, /blockNetworkLoads = true/);
  assert.doesNotMatch(main, /CookieManager\.getInstance|loadDataWithBaseURL|addJavascriptInterface/);
});
check('profile assignment precedes settings and popup transport uses same factory', () => {
  assert.ok(main.indexOf('WebViewCompat.setProfile(web, profileName(account))') < main.indexOf('web.settings.apply'));
  assert.match(main, /addTab\(account, true, false\)/);
  assert.match(main, /transport.webView = child/);
  assert.match(main, /resultMsg.sendToTarget\(\)/);
});
check('WebViews and popup callbacks are scoped by account and tab', () => {
  assert.match(main, /mutableMapOf<Pair<String, String>, WebView>/);
  assert.match(main, /views.getOrPut\(account to tab.id\)/);
  assert.match(main, /views\[account to selected.id\]/);
  assert.match(main, /it.popup && views\[account to it.id\] === window/);
  assert.match(main, /sessions.selected\[account\] == closed.id/);
});
check('cleanup is profile-scoped and blocks navigation until the completion callback', () => {
  assert.match(main, /isFeatureSupported\(WebViewFeature.DELETE_BROWSING_DATA\)/);
  assert.match(main, /sessions.hasCurrentAccount\(account\) && !sessions.loginCleanup.isPending\(account\)/);
  assert.match(main, /views.keys.filter \{ it.first == account \}/);
  assert.match(main, /closedTabs.clear\(account\)/);
  assert.match(main, /WebStorageCompat.deleteBrowsingData\(profile.webStorage\)/);
  assert.match(main, /cleanup.finish\(account, token\)/);
  assert.doesNotMatch(main, /WebStorage.getInstance|clearCache\(|\.pauseTimers\(/);
});
check('account removal confirms its target and commits roster and pending intent together', () => {
  const store = read('app/src/main/java/dev/claudestudio/browser/SessionStore.kt');
  assert.match(main, /\.setNegativeButton\("取消", null\)[\s\S]+\.setPositiveButton[\s\S]+startCleanup\(account, action\)/);
  assert.match(main, /remove.isEnabled = !running && sessions.mayRemove\(selected\)/);
  assert.match(main, /sessions.accountOrder.forEach \{ store.getOrCreateProfile\(profileName\(it\)\) \}/);
  assert.match(store, /putString\(LAYOUT, retained.encode\(\)\).remove\(REMOVE\).commit\(\)/);
});
check('proxy has no direct or bypass fallback', () => {
  assert.match(gate, /addProxyRule\("http:\/\/\$host:\$port"\)/);
  assert.match(gate, /removeImplicitRules\(\)/);
  assert.doesNotMatch(gate, /\.addDirect\(|\.addBypassRule\(|clearProxyOverride\(/);
  assert.ok(gate.indexOf('setProxyOverride') < gate.indexOf('ready = true'));
});
check('persistent layout and profile cookie flush are explicit', () => {
  const store = read('app/src/main/java/dev/claudestudio/browser/SessionStore.kt');
  assert.match(store, /when \(schema\) \{[\s\S]+1 ->[\s\S]+2 -> requireNotNull/);
  assert.match(store, /getSharedPreferences\("sessions-v1"/);
  assert.match(store, /\.commit\(\)/);
  assert.match(main, /getProfile\(profileName\(it\)\)\?\.cookieManager\?\.flush\(\)/);
  assert.match(manifest, /android:allowBackup="false"/);
});
check('update callbacks expire and checks do not call installation', () => {
  assert.match(main, /postDelayed\(it, 15_000\)/);
  assert.match(main, /generation == checkGeneration/);
  const reconcile = main.slice(main.indexOf('private fun reconcile()'), main.indexOf('private fun addTab('));
  assert.doesNotMatch(reconcile, /confirmInstall|startUpdateFlow|DownloadManager|ACTION_INSTALL_PACKAGE/);
  assert.match(read('app/src/website/java/dev/claudestudio/browser/ChannelUpdateClient.kt'), /UpdateResult.Blocked/);
  const play = read('app/src/play/java/dev/claudestudio/browser/ChannelUpdateClient.kt');
  assert.ok(play.indexOf('if (!BuildConfig.PLAY_UPDATE_ENABLED)') < play.indexOf('manager.appUpdateInfo'));
});
for (const name of ['demo', 'popup']) {
  check(`${name} asset script parses without a browser`, () => {
    const html = read(`app/src/main/assets/${name}.html`);
    const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    assert.equal(scripts.length, 1);
    new vm.Script(scripts[0][1], { filename: `${name}.html` });
    assert.match(html, /connect-src 'none'; worker-src 'none'; frame-src 'none'; form-action 'none'/);
    assert.doesNotMatch(html, /<\s*(iframe|img|link|video|audio)\b|fetch\(|XMLHttpRequest|serviceWorker/);
    for (const url of html.match(/https?:\/\/[^'"\s<>]+/g) || []) {
      assert.match(url, /^https:\/\/appassets\.androidplatform\.net\/assets\/(demo|popup)\.html$/);
    }
  });
}
process.stdout.write(`${checks} static checks passed. Kotlin compilation, JUnit and WebView/device behavior NOT executed.\n`);
