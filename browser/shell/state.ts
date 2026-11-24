import { randomUUID } from 'node:crypto';
import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { home, maxTabs, restorableURL, starterAccounts } from './model.ts';
import type { Account, Bounds, Saved, Tab, Workspace } from './model.ts';

type ObjectData = Record<string, unknown>;
const object = (value: unknown): value is ObjectData =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const defaultBounds: Bounds = { width: 1250, height: 875, maximized: false };

export function makeTab(url = home, destination?: Tab['destination']): Tab {
  return { id: randomUUID(), url, pinned: false, destination };
}

export function insertLinkedTab(workspace: Workspace, tab: Tab, openerId: string): void {
  const opener = workspace.tabs.findIndex(item => item.id === openerId && !item.pinned);
  const after = opener >= 0 ? opener : workspace.tabs.findLastIndex(item => item.pinned);
  workspace.tabs.splice(after + 1, 0, tab);
}

export function initialWorkspace(): Workspace {
  const tab = makeTab(home, 'claude');
  return { tabs: [tab], active: tab.id, closed: [] };
}

function decodeWorkspace(value: unknown, ids: Set<string>): Workspace {
  if (!object(value) || !Array.isArray(value.tabs) || !Array.isArray(value.closed)) return initialWorkspace();
  function decodeTab(raw: unknown): Tab[] {
    if (!object(raw) || typeof raw.id !== 'string' || !/^[\da-f-]{36}$/i.test(raw.id) || ids.has(raw.id)) return [];
    const destination = raw.destination === 'mail' || raw.destination === 'claude' ? raw.destination : undefined;
    const url = restorableURL(raw.url);
    if (!url && destination === 'mail') return [];
    ids.add(raw.id);
    return [{ id: raw.id, url: url || home, pinned: raw.pinned === true, destination }];
  }
  const tabs = value.tabs.slice(0, maxTabs).flatMap(decodeTab);
  if (!tabs.length) tabs.push(...initialWorkspace().tabs);
  const closed = value.closed.slice(0, 12).flatMap(decodeTab);
  const active = tabs.find(tab => tab.id === value.active)?.id || tabs[0].id;
  return { tabs, active, closed };
}

function decodeBounds(value: unknown): Bounds {
  if (!object(value)) return { ...defaultBounds };
  const read = (key: string, min: number, max: number): number | undefined => {
    const field = value[key];
    return typeof field === 'number' && Number.isInteger(field) && field >= min && field <= max ? field : undefined;
  };
  return {
    x: read('x', -32000, 32000), y: read('y', -32000, 32000),
    width: read('width', 780, 16000) ?? defaultBounds.width,
    height: read('height', 540, 16000) ?? defaultBounds.height,
    maximized: value.maximized === true
  };
}

export function loadState(root: string, accounts: readonly Account[] = starterAccounts): Saved {
  try {
    const data: unknown = JSON.parse(readFileSync(path.join(root, 'window-state.json'), 'utf8'));
    if (!object(data) || data.version !== 1 || !object(data.workspaces)) throw new Error('标签恢复文件格式无效。');
    const workspaces = data.workspaces;
    const tabIds = new Set<string>();
    return { version: 1, workspaces: Object.fromEntries(accounts.map(id => [id, decodeWorkspace(workspaces[id], tabIds)])),
      bounds: decodeBounds(data.bounds) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    const workspaces = Object.fromEntries(accounts.map(id => [id, initialWorkspace()]));
    return { version: 1, workspaces, bounds: { ...defaultBounds } };
  }
}

export function saveState(root: string, state: Saved): void {
  const stateToSave = structuredClone(state);
  for (const workspace of Object.values(stateToSave.workspaces)) {
    for (const tab of [...workspace.tabs, ...workspace.closed]) tab.url = restorableURL(tab.url) || '';
  }
  const file = path.join(root, 'window-state.json');
  const temp = path.join(root, randomUUID() + '.tmp');
  try {
    writeFileSync(temp, JSON.stringify(stateToSave), { flag: 'wx', flush: true });
    renameSync(temp, file);
  } finally {
    rmSync(temp, { force: true });
  }
}
