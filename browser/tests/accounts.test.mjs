import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { addProfile, loadSettings, maxProfiles, moveProfile, saveSettings } from '../settings.mjs';
import { loadState, makeTab, saveState } from '../shell/state.ts';

test('首次使用默认美国英语，升级保留 A/B 偏好并为新增账号恢复独立标签', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'claude-profile-test-'));
  try {
    const first = await loadSettings(root);
    assert.equal(first.profiles.A.language, 'en-US');
    assert.equal(first.profiles.B.language, 'en-US');
    const old = {
      port: 10810,
      profiles: {
        A: { language: 'zh-CN', zone: 'Asia/Shanghai', mail: '' },
        B: { language: 'en-GB', zone: 'Europe/London', mail: 'https://mail.example.test/' }
      }
    };
    await saveSettings(root, old);
    assert.deepEqual(await loadSettings(root), old);
    const saved = loadState(root);
    const oldA = makeTab('https://claude.ai/chat/one');
    const oldB = makeTab('https://mail.example.test/');
    saved.workspaces.A = { active: oldA.id, tabs: [oldA], closed: [] };
    saved.workspaces.B = { active: oldB.id, tabs: [oldB], closed: [] };
    saveState(root, saved);

    const profile = { name: '  工作  ', language: 'en-US', zone: 'system', mail: 'https://mail.google.com/mail/' };
    const firstAddition = addProfile(old, profile);
    const secondAddition = addProfile(firstAddition.settings, profile);
    assert.match(firstAddition.id, /^[\da-f-]{36}$/);
    assert.notEqual(firstAddition.id, secondAddition.id);
    assert.deepEqual(Object.keys(old.profiles), ['A', 'B']);
    await saveSettings(root, secondAddition.settings);

    const settings = await loadSettings(root);
    assert.equal(settings.profiles[firstAddition.id].name, '工作');
    assert.equal(settings.profiles[firstAddition.id].language, 'en-US');
    assert.deepEqual(settings.profiles.A, old.profiles.A);
    assert.deepEqual(settings.profiles.B, old.profiles.B);
    const upgraded = loadState(root, Object.keys(settings.profiles));
    assert.equal(upgraded.workspaces.A.active, oldA.id);
    assert.equal(upgraded.workspaces.B.active, oldB.id);
    const firstNewTab = upgraded.workspaces[firstAddition.id].active;
    assert.notEqual(firstNewTab, upgraded.workspaces[secondAddition.id].active);
    saveState(root, upgraded);
    assert.equal(loadState(root, Object.keys(settings.profiles)).workspaces[firstAddition.id].active, firstNewTab);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('拒绝无效账号名称与账号标识，限制配置数量', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'claude-profile-validation-'));
  try {
    const settings = await loadSettings(root);
    const profile = { language: 'en-US', zone: 'system', mail: '' };
    assert.throws(() => addProfile(settings, profile), /账号名称/);
    assert.throws(() => addProfile(settings, { ...profile, name: 'x\nz' }), /账号名称/);
    const filled = Object.fromEntries(Array.from({ length: maxProfiles }, (_, index) => [index, profile]));
    assert.throws(() => addProfile({ ...settings, profiles: filled }, { ...profile, name: '测试' }), /最多支持/);

    await writeFile(path.join(root, 'settings.json'),
      JSON.stringify({ ...settings, profiles: { ...settings.profiles, ['__proto__']: profile } }));
    await assert.rejects(loadSettings(root), /账号标识无效/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('账号排序保存后同序重读并保留原标识与标签', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'claude-profile-order-'));
  try {
    const old = await loadSettings(root);
    const { id, settings } = addProfile(old, { name: '辅助', language: 'en-US', zone: 'system', mail: '' });
    const reordered = moveProfile(settings, id, -1);
    assert.deepEqual(Object.keys(reordered.profiles), ['A', id, 'B']);
    assert.deepEqual(reordered.profiles.B, settings.profiles.B);
    assert.equal(moveProfile(reordered, 'A', -1), reordered);
    assert.throws(() => moveProfile(reordered, 'A', 2), /排序/);
    await saveSettings(root, reordered);
    assert.deepEqual(Object.keys((await loadSettings(root)).profiles), ['A', id, 'B']);
    const tab = makeTab('https://example.test/synthetic');
    const stored = loadState(root, Object.keys(reordered.profiles));
    stored.workspaces.B = { tabs: [tab], active: tab.id, closed: [] };
    saveState(root, stored);
    const read = await loadSettings(root);
    assert.deepEqual(Object.keys(read.profiles), Object.keys(reordered.profiles));
    assert.equal(loadState(root, Object.keys(read.profiles)).workspaces.B.active, tab.id);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('从异常保存文件恢复标签时，跨账号的重复标签标识不会复用其他账号窗口', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'claude-profile-tabs-'));
  try {
    const stored = loadState(root);
    const same = makeTab('https://claude.ai/chat/only-a');
    stored.workspaces.A = { active: same.id, tabs: [same], closed: [] };
    stored.workspaces.B = { active: same.id, tabs: [same], closed: [] };
    saveState(root, stored);
    const restored = loadState(root);
    assert.equal(restored.workspaces.A.active, same.id);
    assert.notEqual(restored.workspaces.B.active, same.id);
    assert.deepEqual(restored.workspaces.B.tabs.map(tab => tab.url), ['https://claude.ai/']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
