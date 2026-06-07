'use client';

import { createContext, useContext } from 'react';

// Same shape as FirewallStateContext (see that file). The mesh layout owns
// the state envelope and exposes a refresh fn so child pages (devices, keys,
// routes) can trigger a chip update after an intent mutation.
export const MeshStateContext = createContext<{ refresh: () => void }>({
  refresh: () => {},
});

export function useMeshStateRefresh(): () => void {
  return useContext(MeshStateContext).refresh;
}
