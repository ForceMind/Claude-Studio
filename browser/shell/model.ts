export const starterAccounts = ['A', 'B'] as const;
export type Account = string;
export type Profile = { language: string; zone: string; mail: string; name?: string };
export type SettingsPanelKind = 'settings' | 'add-account' | null;

export function profileName(id: Account, profile: Profile): string {
  return profile.name ?? '账户 ' + id;
}
export type Settings = { port: number | null; profiles: Record<Account, Profile> };
export const home = 'https://claude.ai/';
export const maxTabs = 48;
export const environmentWidth = 320;
export type Destination = 'claude' | 'mail';
export type Tab = { id: string; url: string; pinned: boolean; destination?: Destination };
export type Workspace = { tabs: Tab[]; active: string; closed: Tab[] };
export type Bounds = { x?: number; y?: number; width: number; height: number; maximized: boolean };
export type Saved = { version: 1; workspaces: Record<Account, Workspace>; bounds: Bounds };
export type Page = {
  title?: string; url?: string; loading?: boolean; error?: string; back?: boolean; forward?: boolean;
};
export type PageEnvironment = { language: string; zone: string };
export type ExitState =
  | { state: 'unmeasured' | 'checking' | 'failed' }
  | { state: 'checked'; address: string; checkedAt: number };
export type AccountEnvironment = PageEnvironment & {
  source: 'page' | 'settings';
  exit: ExitState;
};
export type ShellState = {
  account: Account; tabs: (Tab & Page)[]; active: string; canRestore: boolean; settings: Settings;
  status: 'unset' | 'connecting' | 'offline' | 'online';
  panel: SettingsPanelKind; fullscreen: boolean; notice?: string; environment?: AccountEnvironment;
};

export type Command =
  | { type: 'account'; id: Account }
  | { type: 'account-order'; id: Account; direction: -1 | 1 }
  | { type: 'account-clear' | 'account-remove'; id: Account }
  | { type: 'add-account' }
  | { type: 'create-account'; profile: Profile }
  | { type: 'settings' | 'environment'; open: boolean }
  | { type: 'check-exit'; id: Account }
  | { type: 'save'; id: Account; port: number; profile: Profile }
  | { type: 'open'; destination: Destination }
  | { type: 'new' | 'restore' | 'back' | 'forward' | 'reload' | 'force-reload' | 'stop' | 'fullscreen' | 'retry' }
  | { type: 'select' | 'close' | 'pin' | 'tab-menu'; id: string }
  | { type: 'move'; id: string; target: string }
  | { type: 'navigate'; url: string }
  | { type: 'menu'; menu: 'app' | 'accounts' | 'tabs'; x: number; y: number };

export type Bridge = {
  read(): Promise<ShellState>;
  detectProxy(): Promise<number | null>;
  send(command: Command): Promise<string | undefined>;
  subscribe(listener: (state: ShellState) => void): () => void;
  onAddress(listener: () => void): () => void;
};

export function webURL(input: unknown): URL | undefined {
  if (typeof input !== 'string' || input.length > 8192) return;
  try {
    const url = new URL(input);
    if ((url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password) return url;
  } catch {
    // An invalid address has no navigation target.
  }
}

export function linkedTabMode(disposition: string): 'foreground' | 'background' | undefined {
  if (disposition === 'foreground-tab') return 'foreground';
  if (disposition === 'background-tab') return 'background';
}

export function address(input: string): string | undefined {
  const value = input.trim();
  if (!value || /\s/.test(value)) return;
  if (/^[a-z][a-z0-9+.-]*:/i.test(value) && !/^[^/:]+:\d+(?:[/?#]|$)/.test(value))
    return webURL(value)?.href;
  return webURL('https://' + value)?.href;
}

export function restorableURL(input: unknown): string | undefined {
  const url = webURL(input);
  if (!url) return;
  if (/^(accounts|auth\d*|idmsa|login|oauth|sso)\./i.test(url.hostname) ||
      /(?:^|\/)(?:auth|authenticate|authorization|authorize|callback|signin|sign-in|login|logout|oauth2?|saml|sso|verify)(?:\/|$)/i.test(url.pathname))
    return;
  url.search = '';
  url.hash = '';
  return url.href;
}

export function languagesFor(language: string, system: string[]): string[] {
  const configured = language === 'system' ? system : [language];
  const values = configured.flatMap(value => {
    const [canonical] = Intl.getCanonicalLocales(value);
    return [canonical, new Intl.Locale(canonical).language];
  });
  return [...new Set(values)].slice(0, 10);
}

export function acceptLanguage(languages: string[]): string {
  return languages.map((language, index) => index ? language + ';q=' + (1 - index / 10).toFixed(1) : language).join(',');
}
