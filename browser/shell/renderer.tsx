import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import type { FormEvent, MouseEvent, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import {
  languageOptions, timeZoneOptions, mailboxOptions, preferenceGroups,
  chineseLanguage, chineseZone, chineseMailbox, effectiveMailbox
} from '../preferences.mjs';
import { environmentWidth, home, profileName, webURL } from './model';
import type { Account, AccountEnvironment, Bridge, Command, ShellState } from './model';
import { visibleTabs } from './tab-layout';
import './renderer.css';

declare global {
  interface Window { claudeBrowser: Bridge; }
}

const claudeOrigin = new URL(home).origin;

const paths = {
  back: 'M10 4.5 4.5 10l5.5 5.5M4.5 10h11',
  forward: 'm10 4.5 5.5 5.5-5.5 5.5M15.5 10h-11',
  reload: 'M16 8a6.25 6.25 0 1 0-.5 5M16 4v4h-4',
  stop: 'M7 5.5h6A1.5 1.5 0 0 1 14.5 7v6a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 13V7A1.5 1.5 0 0 1 7 5.5Z',
  plus: 'M10 4.5v11m-5.5-5.5h11',
  close: 'm5.5 5.5 9 9m0-9-9 9',
  sidebar: 'M5 4.5h10a1.5 1.5 0 0 1 1.5 1.5v8a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 14V6A1.5 1.5 0 0 1 5 4.5Zm7 0v11',
  menu: 'M4 5.5h12M4 10h12M4 14.5h12',
  tabs: 'M7.25 4H15a1 1 0 0 1 1 1v7.75a1 1 0 0 1-1 1H7.25a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1ZM4 7v8a1 1 0 0 0 1 1h8',
  globe: 'M16.5 10a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0ZM3.5 10h13M10 3.5c3.25 3.4 3.25 9.6 0 13m0-13c-3.25 3.4-3.25 9.6 0 13',
  mail: 'M5 5h10a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 15 15H5a1.5 1.5 0 0 1-1.5-1.5v-7A1.5 1.5 0 0 1 5 5Zm-1 1.75 6 4.4 6-4.4',
  pin: 'M7 4h6m-5 0v3l-2.5 3v1H14.5v-1L12 7V4m-2 7v5'
};
type IconName = keyof typeof paths;

function Icon({ name }: { name: IconName }) {
  return <svg viewBox="0 0 20 20" width="17" height="17" aria-hidden="true">
    <path d={paths[name]} fill="none" stroke="currentColor" strokeWidth="1.55"
      strokeLinecap="round" strokeLinejoin="round"/>
  </svg>;
}

function AppIcon({ label = '' }: { label?: string }) {
  return <img className="app-icon" src="./icon.png" alt={label} draggable={false}/>;
}

function Tool({ icon, label, disabled, onClick }: {
  icon: IconName; label: string; disabled?: boolean; onClick: (event: MouseEvent<HTMLButtonElement>) => void;
}) {
  return <button type="button" className="tool" aria-label={label} title={label}
    disabled={disabled} onClick={onClick}><Icon name={icon}/></button>;
}

const customPreference = '__custom__';

function PreferenceField({ label, value, presets, discouraged, customLabel, placeholder, inputType = 'text', disabled,
  change }: {
  label: string;
  value: string;
  presets: { value: string; label: string }[];
  discouraged: (value: string) => boolean;
  customLabel: string;
  placeholder: string;
  inputType?: 'text' | 'url';
  disabled: boolean;
  change: (value: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const selectId = useId();
  const { regular, last } = preferenceGroups(presets, editing ? '' : value, discouraged);
  return <div className="preference-field">
    <label htmlFor={selectId}>{label}</label>
    <select id={selectId} value={editing ? customPreference : value} disabled={disabled} onChange={event => {
      const next = event.target.value;
      setEditing(next === customPreference);
      change(next === customPreference ? '' : next);
    }}>
      {regular.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
      <option value={customPreference}>{customLabel}</option>
      {last.length > 0 && <optgroup label="中文相关选项">
        {last.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
      </optgroup>}
    </select>
    {editing && <input required type={inputType} value={value} placeholder={placeholder} aria-label={customLabel}
      disabled={disabled} onChange={event => change(event.target.value)}/>}
  </div>;
}

function SettingsPanel({ state, send }: { state: ShellState; send: (command: Command) => Promise<boolean> }) {
  const adding = state.panel === 'add-account';
  const [id, setId] = useState<Account>(state.account);
  const [zones] = useState(() => timeZoneOptions());
  const [form, setForm] = useState(() => {
    if (adding) return { name: '', language: 'en-US', zone: 'system', mail: effectiveMailbox('') };
    const profile = state.settings.profiles[state.account];
    return { ...profile, name: profileName(state.account, profile), mail: effectiveMailbox(profile.mail) };
  });
  const [port, setPort] = useState(state.settings.port?.toString() ?? '');
  const [saving, setSaving] = useState(false);
  const [managing, setManaging] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [proxyHint, setProxyHint] = useState('');
  const profileIds = Object.keys(state.settings.profiles);
  const position = profileIds.indexOf(id);
  const choose = (next: Account) => {
    if (next === id) return;
    const profile = state.settings.profiles[next];
    setId(next);
    setForm({ ...profile, name: profileName(next, profile), mail: effectiveMailbox(profile.mail) });
  };

  async function detect() {
    setDetecting(true);
    setProxyHint('');
    try {
      const detected = await window.claudeBrowser.detectProxy();
      if (detected === null) setProxyHint('Windows 没有单一的本机 HTTP 代理端口，请手动填写。');
      else {
        setPort(String(detected));
        setProxyHint('已从 Windows 代理设置识别端口，保存后生效。');
      }
    } catch {
      setProxyHint('暂时无法读取 Windows 代理设置，请手动填写。');
    } finally {
      setDetecting(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (saving || detecting || managing) return;
    setSaving(true);
    try {
      const profile = {
        name: form.name.trim(), language: form.language.trim(), zone: form.zone.trim(), mail: form.mail.trim()
      };
      await send(adding ? { type: 'create-account', profile } : { type: 'save', id, port: Number(port), profile });
    } finally {
      setSaving(false);
    }
  }

  async function manage(command: Command) {
    setManaging(true);
    try { await send(command); }
    finally { setManaging(false); }
  }

  return <form className="settings-card" onSubmit={submit}>
    <div className="card-heading">
      <h1>{adding ? '添加账号空间' : '账户与代理设置'}</h1>
      <Tool icon="close" disabled={saving || managing} label="关闭设置" onClick={() => void send({ type: 'settings', open: false })}/>
    </div>
    {!adding && <>
      <div className="proxy-field">
        <label htmlFor="proxy-port">共用本地代理端口</label>
        <div className="proxy-input-row">
          <input id="proxy-port" autoFocus type="number" min="1" max="65535" step="1" placeholder="HTTP 或 mixed 端口"
            required value={port} onChange={e => { setPort(e.target.value); setProxyHint(''); }} disabled={saving || detecting || managing}/>
          <button className="secondary" type="button" disabled={saving || detecting || managing} onClick={() => void detect()}>
            {detecting ? '识别中…' : '自动识别'}
          </button>
        </div>
        {proxyHint && <p className="hint" role="status">{proxyHint}</p>}
      </div>
      <div className="profile-picker">
        <label>要编辑的账号
          <select value={id} disabled={saving || managing} onChange={event => choose(event.target.value)}>
            {Object.entries(state.settings.profiles).map(([option, profile]) =>
              <option key={option} value={option}>{profileName(option, profile)}</option>)}
          </select>
        </label>
        <button className="secondary" type="button" disabled={saving || managing} onClick={() => void send({ type: 'add-account' })}>
          添加账号
        </button>
      </div>
      <div className="profile-actions" role="group" aria-label="管理当前选中的账号">
        <button className="secondary" type="button" disabled={saving || detecting || managing || position <= 0}
          onClick={() => void manage({ type: 'account-order', id, direction: -1 })}>上移</button>
        <button className="secondary" type="button" disabled={saving || detecting || managing || position >= profileIds.length - 1}
          onClick={() => void manage({ type: 'account-order', id, direction: 1 })}>下移</button>
        <button className="secondary" type="button" disabled={saving || detecting || managing}
          onClick={() => void manage({ type: 'account-clear', id })}>清除本机登录</button>
        <button className="secondary" type="button" disabled={saving || detecting || managing || profileIds.length <= 1}
          onClick={() => void manage({ type: 'account-remove', id })}>移除账号</button>
      </div>
    </>}
    <label>账号名称
      <input autoFocus={adding} required maxLength={40} value={form.name} placeholder="例如：个人、工作"
        disabled={saving} onChange={e => setForm({ ...form, name: e.target.value })}/>
    </label>
    <div className="field-pair">
      <PreferenceField key={id + '-language'} label="网页语言" presets={languageOptions}
        discouraged={chineseLanguage} value={form.language} change={language => setForm({ ...form, language })}
        customLabel="自定义语言代码" placeholder="例如 en-CA" disabled={saving}/>
      <PreferenceField key={id + '-zone'} label="时区" presets={zones} discouraged={chineseZone}
        value={form.zone} change={zone => setForm({ ...form, zone })}
        customLabel="自定义 IANA 时区" placeholder="例如 America/Toronto" disabled={saving}/>
    </div>
    <p className="hint">时区选项显示当前 UTC 偏移，网页按当地规则切换夏令时。</p>
    <PreferenceField key={id + '-mail'} label="邮箱" presets={mailboxOptions} discouraged={chineseMailbox}
      value={form.mail} change={mail => setForm({ ...form, mail })} customLabel="自定义 HTTPS 邮箱主页"
      placeholder="https://" inputType="url" disabled={saving}/>
    {!adding && <p className="hint">更改语言或时区会重新打开该账户的网页。更改代理端口会重新连接所有账号。</p>}
    <div className="form-actions">
      <button type="button" className="secondary" disabled={saving || managing}
        onClick={() => void send({ type: 'settings', open: false })}>取消</button>
      <button type="submit" className="primary" disabled={saving || detecting || managing}>
        {saving ? '保存中' : adding ? '添加账号' : '保存设置'}
      </button>
    </div>
  </form>;
}

function accountBadge(id: Account, name: string): string {
  return id === 'A' || id === 'B' ? id : (Array.from(name)[0] ?? '').toLocaleUpperCase();
}

const statusText: Record<ShellState['status'], string> = {
  unset: '未设置代理', connecting: '正在连接代理', offline: '代理离线', online: '代理端口可连接'
};

const exitTime = new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'medium' });
const exitText = { unmeasured: '尚未检测', checking: '正在检测…', failed: '检测失败，可重试' };

function EnvironmentCard({ state, environment, send }: {
  state: ShellState;
  environment: AccountEnvironment;
  send: (command: Command) => Promise<boolean>;
}) {
  const { exit } = environment;
  const checking = exit.state === 'checking';
  const accountList = useRef<HTMLDivElement>(null);

  useEffect(() => {
    accountList.current?.querySelector('[aria-pressed="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [state.account]);

  return <aside id="account-environment" className="environment" style={{ width: environmentWidth }}
    aria-labelledby="environment-title">
    <div className="environment-heading">
      <h2 id="environment-title">账户环境</h2>
      <Tool icon="close" label="关闭环境卡" onClick={() => void send({ type: 'environment', open: false })}/>
    </div>
    <div className="environment-accounts" ref={accountList} role="group" aria-label="切换账户">
      {Object.entries(state.settings.profiles).map(([id, profile]) => {
        const name = profileName(id, profile);
        return <button key={id} type="button" aria-pressed={state.account === id}
          onClick={() => void send({ type: 'account', id })} title={name}>
          <span className="account-mark" data-account={id}>{accountBadge(id, name)}</span>
          <span className="account-name">{name}</span>
        </button>;
      })}
    </div>
    <button className="secondary environment-add" type="button" onClick={() => void send({ type: 'add-account' })}>
      <Icon name="plus"/>添加账号
    </button>

    <dl className="environment-fields">
      <div>
        <dt>代理状态</dt>
        <dd>
          <span className="proxy-status" data-status={state.status}>{statusText[state.status]}</span>
          {state.settings.port && <small>127.0.0.1:{state.settings.port}</small>}
        </dd>
      </div>
      <div>
        <dt>实际出口</dt>
        <dd aria-live="polite" aria-atomic="true">
          {exit.state === 'checked' ? <>
            <code className="exit-address">{exit.address}</code>
            <small>检测于 {exitTime.format(exit.checkedAt)}（本机时间）</small>
          </> : exitText[exit.state]}
        </dd>
      </div>
      <div>
        <dt>网页语言</dt>
        <dd>{environment.language}</dd>
      </div>
      <div>
        <dt>时区</dt>
        <dd>{environment.zone}</dd>
      </div>
    </dl>
    <p className="environment-source">
      {environment.source === 'page' ? '语言和时区来自当前网页读数。' : '网页读数暂不可用，显示账户设置。'}
    </p>
    <div className="environment-actions">
      <button type="button" className="primary" disabled={checking || state.status !== 'online'}
        onClick={() => void send({ type: 'check-exit', id: state.account })}>
        {checking ? '检测中…' : exit.state === 'checked' ? '重新检测' : '检测出口'}
      </button>
      <button type="button" className="secondary"
        onClick={() => void send({ type: 'settings', open: true })}>账户设置</button>
    </div>
    <p className="environment-source">检测时通过当前账户代理向 ipify 查询出口 IP。</p>
  </aside>;
}

function App() {
  const [state, setState] = useState<ShellState>();
  const [issue, setIssue] = useState('');
  const addressRef = useRef<HTMLInputElement>(null);
  const edit = useRef(false);
  const drag = useRef<string | undefined>(undefined);
  const tabRail = useRef<HTMLDivElement>(null);
  const [railWidth, setRailWidth] = useState(0);
  const [draftURL, setDraftURL] = useState('');
  const active = state?.tabs.find(tab => tab.id === state.active);
  const url = active?.url ?? '';
  const hasActive = Boolean(active);

  useEffect(() => {
    let alive = true;
    let received = false;
    const bridge = window.claudeBrowser;
    if (!bridge) {
      setIssue('应用界面未能连接到浏览器主进程。');
      return;
    }
    const unsubscribe = bridge.subscribe(value => { received = true; setState(value); });
    const addressShortcut = bridge.onAddress(() => {
      addressRef.current?.focus();
      addressRef.current?.select();
    });
    void bridge.read().then(value => { if (alive && !received) setState(value); }, () => {
      if (alive) setIssue('应用界面未能读取账户状态。');
    });
    return () => { alive = false; unsubscribe(); addressShortcut(); };
  }, []);

  useEffect(() => {
    if (!edit.current) setDraftURL(url);
  }, [url]);

  useLayoutEffect(() => {
    const element = tabRail.current;
    if (!element) return;
    const measure = () => setRailWidth(element.clientWidth);
    const observer = new ResizeObserver(measure);
    measure();
    observer.observe(element);
    return () => observer.disconnect();
  }, [hasActive]);

  async function send(command: Command): Promise<boolean> {
    setIssue('');
    try {
      const result = await window.claudeBrowser.send(command);
      if (result) setIssue(result);
      return !result;
    } catch {
      setIssue('应用界面未能完成操作。');
      return false;
    }
  }

  function menu(name: 'app' | 'accounts' | 'tabs', event: MouseEvent<HTMLButtonElement>) {
    const bounds = event.currentTarget.getBoundingClientRect();
    void send({ type: 'menu', menu: name, x: bounds.left, y: bounds.bottom });
  }

  function submitAddress(event: FormEvent) {
    event.preventDefault();
    void send({ type: 'navigate', url: draftURL }).then(ok => {
      if (ok && addressRef.current === document.activeElement) addressRef.current?.blur();
    });
  }

  if (!state || !active) return <div className="boot" role="status">{issue || '正在打开 Claude Browser…'}</div>;
  const shownTabs = visibleTabs(state.tabs, active.id, railWidth);
  const hiddenCount = state.tabs.length - shownTabs.length;

  const currentName = profileName(state.account, state.settings.profiles[state.account]);
  const badge = accountBadge(state.account, currentName);
  const message = issue || state.notice;
  let stage: ReactNode;
  if (state.panel) {
    stage = <SettingsPanel key={state.account + ':' + state.panel} state={state} send={send}/>;
  } else if (state.status === 'unset') {
    stage = <div className="page-state">
      <span className="account-mark" data-account={state.account}>{badge}</span>
      <h1>设置本地代理</h1>
      <p>输入本机 HTTP 或 mixed 代理端口，即可打开「{currentName}」的网页。</p>
      <button className="primary" onClick={() => void send({ type: 'settings', open: true })}>打开设置</button>
    </div>;
  } else if (active.error) {
    stage = <div className="page-state">
      <h1>无法打开网页</h1>
      <p role="status">{active.error}</p>
      <div className="form-actions">
        <button className="secondary" onClick={() => void send({ type: 'settings', open: true })}>账户设置</button>
        <button className="primary" onClick={() => void send({ type: 'retry' })}>重试</button>
      </div>
    </div>;
  } else {
    stage = <div className="page-state" role="status">
      <span className="spinner"/>
      <p>{state.status === 'connecting' ? '正在连接本地代理…' : '正在打开网页…'}</p>
    </div>;
  }

  return <>
    <header className={state.fullscreen ? 'chrome fullscreen' : 'chrome'}>
      <div className="titlebar">
        <span className="brand"><AppIcon label="Claude Browser"/></span>
        <div className="tab-rail" ref={tabRail}>
          <div className="tabs" role="tablist" aria-label={currentName + ' 的标签页'}>
          {shownTabs.map(tab => {
            const title = tab.title || (tab.destination === 'mail' ? '邮箱' : tab.destination === 'claude' ?
              'Claude' : webURL(tab.url)?.host || '新标签页');
            return <div key={tab.id} className={'tab' + (tab.id === active.id ? ' active' : '') + (tab.pinned ? ' pinned' : '')}
              draggable onContextMenu={event => {
                event.preventDefault();
                void send({ type: 'tab-menu', id: tab.id });
              }}
              onDragStart={event => {
                drag.current = tab.id;
                event.dataTransfer.effectAllowed = 'move';
                event.dataTransfer.setData('application/x-claude-tab', tab.id);
              }}
              onDragEnd={() => { drag.current = undefined; }}
              onDragOver={event => { if (drag.current) event.preventDefault(); }}
              onDrop={event => {
                const from = drag.current;
                if (!from) return;
                event.preventDefault();
                drag.current = undefined;
                void send({ type: 'move', id: from, target: tab.id });
              }}
              onAuxClick={event => {
                if (event.button === 1) void send({ type: 'close', id: tab.id });
              }}>
              <button type="button" className="tab-label" role="tab" aria-selected={tab.id === active.id} title={title}
                onClick={() => void send({ type: 'select', id: tab.id })}>
                {tab.loading ? <span className="spinner"/> : webURL(tab.url)?.origin === claudeOrigin ?
                  <AppIcon/> : <Icon name={tab.destination === 'mail' ? 'mail' : 'globe'}/>}
                <span className="tab-title">{title}</span>
                {tab.pinned && <span className="pin-mark" role="img" aria-label="已固定"><Icon name="pin"/></span>}
              </button>
              <Tool icon="close" label={'关闭 ' + title} onClick={() => void send({ type: 'close', id: tab.id })}/>
            </div>;
          })}
          </div>
          {hiddenCount > 0 && <Tool icon="tabs" label={'查看全部标签，' + hiddenCount + ' 个已收纳'}
            onClick={event => menu('tabs', event)}/>}
        </div>
        <Tool icon="plus" label="新建标签页（Ctrl+T）"
          onClick={() => void send({ type: 'new' })}/>
        <div className="drag-space"/>
      </div>
      <nav className="toolbar" aria-label="网页导航">
        <Tool icon="back" label="后退" disabled={!active.back} onClick={() => void send({ type: 'back' })}/>
        <Tool icon="forward" label="前进" disabled={!active.forward} onClick={() => void send({ type: 'forward' })}/>
        <Tool icon={active.loading ? 'stop' : 'reload'} label={active.loading ? '停止' : '重新加载'}
          onClick={() => void send({ type: active.loading ? 'stop' : 'reload' })}/>
        <form className="address" onSubmit={submitAddress}>
          <Icon name="globe"/>
          <input ref={addressRef} aria-label="网页地址" placeholder="输入网页地址" spellCheck={false} autoComplete="off"
            value={draftURL} onChange={e => setDraftURL(e.target.value)}
            onFocus={() => { edit.current = true; }}
            onBlur={() => { edit.current = false; setDraftURL(url); }}
            onKeyDown={event => { if (event.key === 'Escape') addressRef.current?.blur(); }}/>
        </form>
        <button className="destination" onClick={() => void send({ type: 'open', destination: 'claude' })}>
          <AppIcon/>Claude
        </button>
        <button className="destination" onClick={() => void send({ type: 'open', destination: 'mail' })}>
          <Icon name="mail"/>邮箱
        </button>
        <div className="divider"/>
        <button className="account" aria-expanded={!!state.environment} aria-controls="account-environment"
          aria-label={'账户环境 · ' + currentName} title={currentName + ' · ' + statusText[state.status]}
          onClick={() => void send({ type: 'environment', open: !state.environment })}>
          <span className="account-mark" data-account={state.account}>{badge}</span>
          <span className="account-name">{currentName}</span><Icon name="sidebar"/>
        </button>
        <Tool icon="menu" label="窗口菜单" onClick={event => menu('app', event)}/>
      </nav>
      {message && <div className="notice" role="alert">{message}</div>}
    </header>
    <main className="stage">
      <div className="stage-page">{stage}</div>
      {state.environment && <EnvironmentCard state={state} environment={state.environment} send={send}/>}
    </main>
  </>;
}

createRoot(document.getElementById('root')!).render(<App/>);
