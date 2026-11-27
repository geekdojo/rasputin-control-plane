'use client';

// /login/bridge — CHOOSE A PASSWORD (geekdojo/geekdojo-brain#1005): the
// move's bridge, after a passkey from before the update was accepted.

import { HAIR, PANEL } from '../../../components/kit';
import { MONO } from '../../../components/ui-theme';
import { ChooseAPassword } from '../../../components/profile/ChooseAPassword';

export default function BridgePage() {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'var(--rasp-bg)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: MONO,
        padding: 24,
      }}
    >
      <div
        style={{
          width: 420,
          maxWidth: '100%',
          background: PANEL,
          border: `1px solid ${HAIR}`,
          padding: '28px 26px',
        }}
      >
        <ChooseAPassword />
      </div>
    </div>
  );
}
