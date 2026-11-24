'use client';

// The /login page's repair link (geekdojo/geekdojo-brain#321): shown while
// sign-in isn't ready, or when the console was reached by its address. A
// component of its own so the DOM tests render it without the page's router.

import { DIM } from './kit';
import { MONO } from './ui-theme';
import { REPAIR_LINK_SENTENCE, repairLinkShown } from '../lib/repair';

export function RepairLink({ ready, hostname }: { ready: boolean; hostname: string }) {
  if (!repairLinkShown(ready, hostname)) return null;
  return (
    <a href="/repair" style={{ color: DIM, fontSize: 10, fontFamily: MONO, letterSpacing: '0.04em' }}>
      {REPAIR_LINK_SENTENCE}
    </a>
  );
}
