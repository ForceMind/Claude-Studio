import type { Tab } from './model';

const tabGap = 4;
const tabPadding = 4;
const overflow = 31 + 4; // Toolbar button and gap.

export function visibleTabs<T extends Pick<Tab, 'id' | 'pinned'>>(tabs: readonly T[], active: string, width: number): T[] {
  const size = (tab: T) => tab.pinned ? 126 : 156;
  const full = tabs.reduce((total, tab) => total + size(tab) + tabGap, tabPadding - tabGap);
  if (full <= width) return [...tabs];
  const selected = tabs.find(tab => tab.id === active);
  if (!selected) return [];
  let free = width - overflow - tabPadding - size(selected);
  return tabs.filter(tab => {
    if (tab.id === active) return true;
    const required = size(tab) + tabGap;
    if (required > free) return false;
    free -= required;
    return true;
  });
}
