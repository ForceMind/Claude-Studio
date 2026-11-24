import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { acceptLanguage, address, home, languagesFor, linkedTabMode, restorableURL, webURL } from '../shell/model.ts';
import { insertLinkedTab, loadState, makeTab, saveState } from '../shell/state.ts';
import { cacheablePageURL, ClosedPages } from '../shell/closed-pages.ts';
import { visibleTabs } from '../shell/tab-layout.ts';

test('地址栏仅接受 HTTP(S)，恢复文件过滤认证地址、查询参数和片段', () => {
  assert.equal(address(' example.test:8443/page '), 'https://example.test:8443/page');
  assert.equal(address('http://fixture.test/'), 'http://fixture.test/');
  for (const url of ['file:///C:/secret', 'javascript:alert(1)', 'mailto:user@test', 'https://u:p@example.test/']) {
    assert.equal(address(url), undefined);
    assert.equal(webURL(url), undefined);
  }
  assert.equal(restorableURL('https://accounts.example.test/continue?state=secret'), undefined);
  assert.equal(restorableURL('https://mail.example.test/oauth/callback?code=secret'), undefined);
  assert.equal(restorableURL('https://mail.example.test/inbox?token=secret#key'), 'https://mail.example.test/inbox');
});

test('账户语言偏好生成独立有序语言列表和 HTTP 请求头', () => {
  const a = languagesFor('zh-CN', ['en-US']);
  const b = languagesFor('system', ['en-US', 'en', 'fr-CA']);
  assert.deepEqual(a, ['zh-CN', 'zh']);
  assert.deepEqual(b, ['en-US', 'en', 'fr-CA', 'fr']);
  assert.equal(acceptLanguage(a), 'zh-CN,zh;q=0.9');
  assert.equal(acceptLanguage(b), 'en-US,en;q=0.9,fr-CA;q=0.8,fr;q=0.7');
});

test('A/B 的选中标签和最近关闭标签独立恢复，磁盘省略认证地址', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'claude-shell-test-'));
  try {
    const state = loadState(root);
    const { A, B } = state.workspaces;
    assert.equal(A.tabs[0].url, home);
    assert.notEqual(A.active, B.active);
    const claude = makeTab('https://claude.ai/chat/one?access_token=private#draft');
    const mail = makeTab('https://mail.example.test/inbox', 'mail');
    const login = makeTab('https://login.example.test/continue?code=private');
    A.tabs.unshift({ ...claude, pinned: true });
    A.active = claude.id;
    B.closed.push(mail);
    B.tabs.push(login);
    B.active = login.id;
    state.bounds = { x: 10, y: 25, width: 1000, height: 700, maximized: true };

    saveState(root, state);
    assert.doesNotMatch(readFileSync(path.join(root, 'window-state.json'), 'utf8'), /private|login\.example/);
    const restored = loadState(root);
    assert.equal(restored.workspaces.A.active, claude.id);
    assert.equal(restored.workspaces.A.tabs[0].url, 'https://claude.ai/chat/one');
    assert.equal(restored.workspaces.A.tabs[0].pinned, true);
    assert.deepEqual(restored.workspaces.B.closed, [mail]);
    assert.equal(restored.workspaces.B.tabs.find(tab => tab.id === login.id)?.url, home);
    assert.deepEqual(restored.bounds, state.bounds);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Chromium 的新标签进入前台或后台，明确的新窗口保持独立', () => {
  assert.equal(linkedTabMode('foreground-tab'), 'foreground');
  assert.equal(linkedTabMode('background-tab'), 'background');
  for (const disposition of ['new-window', 'other', 'default']) {
    assert.equal(linkedTabMode(disposition), undefined);
  }
});

test('网页链接插在来源之后，并保留固定标签组及后台焦点', () => {
  const firstPinned = { ...makeTab(), pinned: true };
  const secondPinned = { ...makeTab(), pinned: true };
  const mail = makeTab('https://mail.example.test/inbox', 'mail');
  const anotherTab = makeTab('https://other.example.test/');
  const workspace = { tabs: [firstPinned, secondPinned, mail, anotherTab], active: mail.id, closed: [] };
  const target = makeTab('https://claude.ai/');
  insertLinkedTab(workspace, target, mail.id);
  assert.deepEqual(workspace.tabs, [firstPinned, secondPinned, mail, target, anotherTab]);
  assert.equal(workspace.active, mail.id);
  const fromPinned = makeTab('https://claude.ai/');
  insertLinkedTab(workspace, fromPinned, firstPinned.id);
  assert.deepEqual(workspace.tabs, [firstPinned, secondPinned, fromPinned, mail, target, anotherTab]);
});


test('窄窗按净宽度收纳标签，保留固定顺序和当前标签', () => {
  const tabs = [{ id: 'pinned', pinned: true }, ...['source', 'hidden', 'active'].map(id => ({ id, pinned: false }))];
  assert.deepEqual(visibleTabs(tabs, 'active', 645), tabs);
  assert.deepEqual(visibleTabs(tabs, 'active', 325).map(tab => tab.id), ['pinned', 'active']);
  assert.deepEqual(visibleTabs(tabs, 'active', 150).map(tab => tab.id), ['active']);
});

test('短时恢复只认原账号，到期和超容量时释放网页实例', () => {
  const disposed = [];
  let time = 0;
  const retained = new ClosedPages(id => disposed.push(id), () => time, () => () => {});
  for (const id of ['one', 'two', 'three', 'four', 'five', 'six']) retained.remember(id, 'A');
  assert.deepEqual(disposed, ['one']);
  assert.equal(retained.take('six', 'B'), false);
  assert.equal(retained.take('six', 'A'), true);
  time = 10 * 60_000;
  assert.equal(retained.take('five', 'A'), false);
  assert.deepEqual(disposed, ['one', 'five']);
  for (const route of ['/kyc', '/chat?code=temporary', '/register', '/redirect#token=private']) {
    assert.equal(cacheablePageURL('https://example.test' + route), false);
  }
  assert.equal(cacheablePageURL('https://example.test/chat/normal'), true);
});
