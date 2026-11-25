'use client';

// The two ways into the move's bridge (geekdojo/geekdojo-brain#1005, ui.md
// §5.4): /login's offer, for a browser with no session, and the pre-update
// session's prompt, mounted on /settings until #319's Profile exists. Each
// runs the passkey ceremony and then opens CHOOSE A PASSWORD; neither signs
// anyone out.

import { useEffect, useState } from 'react';
import { Btn, DIM, FG } from '../kit';
import { MONO } from '../ui-theme';
import { getMe } from '../../lib/auth';
import {
  BRIDGE_CHOOSER,
  BRIDGE_OFFER,
  getBridge,
  PRE_UPDATE_PROMPT,
  runBridgeCeremony,
  SIGN_IN_PATH,
  type BridgeRefusal,
} from '../../lib/bridge';

/** Navigates the whole page: the export is static, and next may be an api route. */
export function go(path: string): void {
  window.location.assign(path);
}

/** A refusal's sentence, verbatim, with SIGN IN when the account already has a password. */
export function RefusalLine({ refusal }: { refusal: BridgeRefusal }) {
  return (
    <div role="alert" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <p style={{ color: '#f87171', fontSize: 11, lineHeight: 1.6, margin: 0, fontFamily: MONO }}>{refusal.error}</p>
      {refusal.code === 'has_password' && (
        <a href={SIGN_IN_PATH} style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.12em' }}>
          SIGN IN
        </a>
      )}
    </div>
  );
}

/** Runs the ceremony on click; on success opens CHOOSE A PASSWORD. */
function useCeremony() {
  const [busy, setBusy] = useState(false);
  const [refusal, setRefusal] = useState<BridgeRefusal | null>(null);
  const run = async () => {
    setBusy(true);
    setRefusal(null);
    const r = await runBridgeCeremony();
    setBusy(false);
    if (r.ok) go(BRIDGE_CHOOSER);
    else setRefusal(r.refusal);
  };
  return { busy, refusal, run };
}

/** /login's offer, shown only while GET /api/auth/bridge says offered. */
export function BridgeOffer() {
  const [offered, setOffered] = useState(false);
  const { busy, refusal, run } = useCeremony();
  useEffect(() => {
    getBridge()
      .then((s) => setOffered(s.offered === true))
      .catch(() => setOffered(false));
  }, []);
  if (!offered) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <Btn onClick={run} disabled={busy}>
        {BRIDGE_OFFER}
      </Btn>
      {refusal && <RefusalLine refusal={refusal} />}
    </div>
  );
}

/** The pre-update session's prompt, shown only while me.preUpdate.needsPassword. */
export function PreUpdateSignIn() {
  const [needs, setNeeds] = useState(false);
  const { busy, refusal, run } = useCeremony();
  useEffect(() => {
    getMe()
      .then((me) => setNeeds(me?.preUpdate?.needsPassword === true))
      .catch(() => setNeeds(false));
  }, []);
  if (!needs) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 24, maxWidth: 560 }}>
      <p style={{ color: FG, fontSize: 12, lineHeight: 1.6, margin: 0, fontFamily: MONO }}>{PRE_UPDATE_PROMPT}</p>
      <div>
        <Btn onClick={run} disabled={busy}>
          SET YOUR PASSWORD
        </Btn>
      </div>
      {refusal && <RefusalLine refusal={refusal} />}
      {busy && <p style={{ color: DIM, fontSize: 10, margin: 0, fontFamily: MONO }}>WAITING FOR YOUR PASSKEY…</p>}
    </div>
  );
}
