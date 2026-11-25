'use client';

// /repair — the break-glass repair page (geekdojo/geekdojo-brain#321).
//
// Without a repair session it lists the ways to make a repair code on this
// control plane (GET /api/repair/ways) and takes the code. With one it
// renders only what GET /api/repair/state lists: the sign-in service's state
// in plain words, RESTART, the reset of one administrator's sign-in (one
// button per listed account), the re-run of the accounts' move while the api
// lists it, the session's jobs and END REPAIR SESSION. The reset and the
// move each ask the api first, which answers with what they do and a token;
// CONFIRM sends the token back (and the reset's temporary password). It
// always says what happens next (ui.md §6), and once sign-in is running it
// offers SIGN IN NORMALLY, which ends the session and opens the console's own
// sign-in. While a listed job hasn't finished it re-reads the state.

import { useEffect, useState } from 'react';
import { Btn, CopyButton, DIM, FG, HAIR, Input, PANEL } from '../../components/kit';
import { MONO } from '../../components/ui-theme';
import {
  bringBackAccounts,
  endRepairSession,
  getRepairState,
  getRepairWays,
  redeemRepairCode,
  RepairError,
  resetSignIn,
  restartSignIn,
  type RepairAction,
  type RepairState,
  type RepairWays,
  whatHappensNext,
} from '../../lib/repair';

/** How often the page re-reads the state while a job it lists is running. */
const REREAD_MS = 2000;

const label = { color: DIM, fontSize: 10, letterSpacing: '0.14em', margin: 0 } as const;
const text = { color: FG, fontSize: 11, lineHeight: 1.6, margin: 0 } as const;
const warn = { color: '#facc15', fontSize: 11, lineHeight: 1.6, margin: 0 } as const;

/** A confirmation the api asked for: the reset of one account, or the move. */
type Confirming =
  | { kind: 'reset'; accountId: string; token: string; sentence: string }
  | { kind: 'move'; token: string; sentence: string };

/** The confirmation e asks for, or null when e is any other failure. */
function confirmingOf(e: unknown, kind: 'reset' | 'move', accountId: string): Confirming | null {
  if (!(e instanceof RepairError) || !e.confirm) return null;
  const token = e.body.stateToken ?? '';
  return kind === 'reset' ? { kind, accountId, token, sentence: e.message } : { kind, token, sentence: e.message };
}

export default function RepairPage() {
  // undefined: not read yet; null: no session.
  const [state, setState] = useState<RepairState | null | undefined>(undefined);
  const [ways, setWays] = useState<RepairWays | null>(null);
  const [code, setCode] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<Confirming | null>(null);
  const [password, setPassword] = useState('');

  // tick asks for a fresh read of the state.
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let current = true;
    getRepairState()
      .then(async (s) => {
        const w = s === null ? await getRepairWays() : null;
        if (!current) return;
        setState(s);
        setWays(w);
      })
      .catch((e) => current && setErr(e instanceof Error ? e.message : String(e)));
    return () => {
      current = false;
    };
  }, [tick]);

  // Re-read while a listed job hasn't finished (F-321-14: no live stream
  // reaches a repair session).
  useEffect(() => {
    if (!state || state.jobs.every((j) => j.finished)) return;
    const t = setTimeout(() => setTick((n) => n + 1), REREAD_MS);
    return () => clearTimeout(t);
  }, [state]);

  async function act(fn: () => Promise<void>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      setTick((n) => n + 1);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  /**
   * ask runs a reset or move call whose 409 is the api asking to confirm:
   * that opens (or refreshes) the confirmation; any other failure shows.
   */
  async function ask(kind: 'reset' | 'move', accountId: string, fn: () => Promise<void>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      setConfirming(null);
      setTick((n) => n + 1);
    } catch (e) {
      const c = confirmingOf(e, kind, accountId);
      if (c) setConfirming(c);
      else setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function renderAction(a: RepairAction) {
    if (a.id === 'reset') {
      if (!a.enabled || !a.targets?.length) {
        return (
          <div key={a.id} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <Btn variant="primary" disabled>
              {a.label}
            </Btn>
            {a.reason && <p style={label}>{a.reason}</p>}
          </div>
        );
      }
      return a.targets.map((t) => (
        <div key={`reset-${t.id}`} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <code style={{ color: FG, fontSize: 11 }}>{t.name}</code>
          <Btn variant="primary" disabled={busy} onClick={() => void ask('reset', t.id, () => resetSignIn(t.id))}>
            {a.label}
          </Btn>
        </div>
      ));
    }
    const run =
      a.id === 'restart'
        ? () => void act(restartSignIn)
        : a.id === 'move'
          ? () => void ask('move', '', () => bringBackAccounts())
          : () => void act(() => Promise.reject(new Error('This action is not known to this page.')));
    return (
      <div key={a.id} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <Btn variant="primary" disabled={busy || !a.enabled} onClick={run}>
          {a.label}
        </Btn>
        {!a.enabled && a.reason && <p style={label}>{a.reason}</p>}
      </div>
    );
  }

  function confirm(c: Confirming) {
    if (c.kind === 'move') {
      void ask('move', '', () => bringBackAccounts(c.token));
      return;
    }
    const pw = password;
    setPassword('');
    void ask('reset', c.accountId, () => resetSignIn(c.accountId, c.token, pw));
  }

  const signInAt = state?.signInAt ?? ways?.signInAt ?? '';

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
          width: 520,
          maxWidth: '100%',
          background: PANEL,
          border: `1px solid ${HAIR}`,
          padding: '28px 26px',
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
        }}
      >
        <span style={{ color: FG, fontSize: 13, letterSpacing: '0.18em' }}>REPAIR SIGN-IN</span>

        {state === undefined && !err && <p style={label}>CONNECTING…</p>}

        {state === null && ways && (
          <>
            <p style={text}>
              A repair code opens a repair session, which can only bring sign-in back. Make one on the control plane:
            </p>
            {ways.ways.map((w) => (
              <div key={w.id} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <p style={text}>{w.text}</p>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <code style={{ color: FG, fontSize: 11, wordBreak: 'break-all' }}>{w.command}</code>
                  <CopyButton value={w.command} ariaLabel={`Copy the ${w.id} command`} />
                </div>
              </div>
            ))}
            <form
              style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  await redeemRepairCode(code);
                  setCode('');
                });
              }}
            >
              <label htmlFor="repair-code" style={label}>
                REPAIR CODE
              </label>
              <Input
                id="repair-code"
                autoComplete="off"
                spellCheck={false}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="XXXXX-XXXXX-XXXXX-XXXXX"
              />
              <Btn type="submit" variant="primary" disabled={busy || code.trim() === ''}>
                OPEN REPAIR SESSION
              </Btn>
            </form>
          </>
        )}

        {state && (
          <>
            <p style={state.ready ? text : warn}>{state.sentence}</p>
            {state.actions.map(renderAction)}
            {confirming && (
              <form
                style={{ display: 'flex', flexDirection: 'column', gap: 8, borderTop: `1px solid ${HAIR}`, paddingTop: 12 }}
                onSubmit={(e) => {
                  e.preventDefault();
                  confirm(confirming);
                }}
              >
                <p style={text}>{confirming.sentence}</p>
                {confirming.kind === 'reset' && (
                  <>
                    <label htmlFor="repair-temp-password" style={label}>
                      TEMPORARY PASSWORD
                    </label>
                    <Input
                      id="repair-temp-password"
                      type="password"
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </>
                )}
                <div style={{ display: 'flex', gap: 8 }}>
                  <Btn type="submit" variant="primary" disabled={busy || (confirming.kind === 'reset' && password === '')}>
                    CONFIRM
                  </Btn>
                  <Btn
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      setPassword('');
                      setConfirming(null);
                    }}
                  >
                    CANCEL
                  </Btn>
                </div>
              </form>
            )}
            {state.jobs.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <p style={label}>JOBS</p>
                {state.jobs.map((j) => (
                  <p key={j.id} style={text}>
                    {j.kind} — {j.status}
                    {j.error ? `: ${j.error}` : ''}
                  </p>
                ))}
              </div>
            )}
            {state.ready && (
              <Btn
                variant="primary"
                disabled={busy}
                onClick={() =>
                  void act(async () => {
                    await endRepairSession();
                    window.location.assign(new URL('/login', state.signInAt).href);
                  })
                }
              >
                SIGN IN NORMALLY
              </Btn>
            )}
            <Btn disabled={busy} onClick={() => void act(endRepairSession)}>
              END REPAIR SESSION
            </Btn>
          </>
        )}

        {err && <p style={warn}>{err}</p>}

        {signInAt && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <p style={label}>WHAT HAPPENS NEXT</p>
            <p style={text}>{whatHappensNext(signInAt)}</p>
          </div>
        )}
      </div>
    </div>
  );
}
