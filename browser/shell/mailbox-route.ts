import { home, webURL } from './model.ts';

const claudeOrigin = new URL(home).origin;

export const mailboxSpaceKey = (id: string): string => 'mailbox:' + id;
export const isMailboxSpace = (key: string): boolean => key.startsWith('mailbox:');
export const partitionForSpace = (key: string): string => isMailboxSpace(key) ?
  'persist:mailbox-' + key.slice('mailbox:'.length) : 'persist:account-' + key;

export function isClaudeSite(input: string): boolean {
  try {
    return /(?:^|\.)claude\.ai\.?$/i.test(new URL(input).hostname);
  } catch {
    return false;
  }
}

export function transferableClaudeURL(input: string): string | undefined {
  const url = webURL(input);
  return url?.origin === claudeOrigin ? url.href : undefined;
}

export function restorableHandoffURL(input: string): string | undefined {
  const url = webURL(input);
  if (url?.origin !== claudeOrigin || url.search || url.hash) return;
  if (url.pathname === '/' || url.pathname === '/new' ||
      /^\/chat\/[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}\/?$/i.test(url.pathname)) return url.href;
}
