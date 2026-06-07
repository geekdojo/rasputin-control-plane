'use client';

import { createContext, useContext } from 'react';

// Lets child pages trigger a refresh of the firewall state chip in the
// layout after they mutate an intent (create / update / delete). The layout
// provides the actual refresh function; pages just call it.
//
// Default is a no-op so a page rendered outside the firewall subtree doesn't
// crash — the contract is "if there's no provider, refreshes are silent."
export const FirewallStateContext = createContext<{ refresh: () => void }>({
  refresh: () => {},
});

export function useFirewallStateRefresh(): () => void {
  return useContext(FirewallStateContext).refresh;
}
