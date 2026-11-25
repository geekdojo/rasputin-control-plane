'use client';

// CHOOSE A PASSWORD (geekdojo/geekdojo-brain#1005, ui.md §5.4): the one
// screen where a moved account's first password is typed on the console's
// origin, under the browser's bridge grant. The password field is
// write-only at the api; SHOW only switches the field's type on this page.

import { useEffect, useState, type FormEvent } from 'react';
import { Btn, DIM, FG, Input } from '../kit';
import { MONO } from '../ui-theme';
import { getBridge, setFirstPassword, type BridgeRefusal, type BridgeState } from '../../lib/bridge';
import { go, RefusalLine } from './PreUpdateSignIn';

export const CHOOSE_TITLE = 'CHOOSE A PASSWORD';
export const CHOOSE_OPENING = "Rasputin's sign-in changed. Choose a password and add your email, then sign in with them.";
export const PASSWORD_RULE = 'At least 15 characters. Three or four words work well.';
export const EMAIL_NOTE = 'Rasputin never sends you email.';
export const NO_GRANT = 'This step has expired. Start again from the sign-in page.';

/** The sentence naming the home door, where the person goes next. */
export function nextAddress(origin: string): string {
  return `Sign-in now has its own page, at ${origin}. You'll go there next; it's part of this Rasputin.`;
}

/** Which field a refusal belongs beside: the email's, the password's, or neither. */
export function refusalField(code: string): 'email' | 'password' | null {
  if (code.startsWith('email_')) return 'email';
  if (code.startsWith('password_')) return 'password';
  return null;
}

const label = { color: DIM, fontSize: 10, letterSpacing: '0.12em', fontFamily: MONO } as const;
const hint = { color: DIM, fontSize: 10, lineHeight: 1.6, margin: 0, fontFamily: MONO } as const;
const bad = { color: '#f87171', fontSize: 11, lineHeight: 1.6, margin: 0, fontFamily: MONO } as const;

export function ChooseAPassword() {
  const [state, setState] = useState<BridgeState | null>(null);
  const [failed, setFailed] = useState(false);
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refusal, setRefusal] = useState<BridgeRefusal | null>(null);

  useEffect(() => {
    getBridge()
      .then(setState)
      .catch(() => setFailed(true));
  }, []);

  if (!state && !failed) return null;
  if (failed || !state?.name) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <p style={bad}>{NO_GRANT}</p>
        <a href="/login" style={{ color: FG, fontSize: 11, fontFamily: MONO }}>
          BACK TO SIGN-IN
        </a>
      </div>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setRefusal(null);
    const r = await setFirstPassword(password, email);
    setBusy(false);
    if (r.ok) go(r.next);
    else setRefusal(r.refusal);
  };
  const where = refusal ? refusalField(refusal.code) : null;

  return (
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <h1 style={{ color: FG, fontSize: 13, letterSpacing: '0.18em', margin: 0, fontWeight: 400 }}>{CHOOSE_TITLE}</h1>
      <p style={{ color: FG, fontSize: 11, lineHeight: 1.6, margin: 0 }}>{CHOOSE_OPENING}</p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <label htmlFor="bridge-name" style={label}>
          SIGN-IN NAME
        </label>
        <Input id="bridge-name" value={state.name} readOnly aria-readonly="true" />
        {state.previousName && <p style={hint}>Before the update it was {state.previousName}.</p>}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <label htmlFor="bridge-password" style={label}>
          PASSWORD
        </label>
        <div style={{ display: 'flex', gap: 8 }}>
          <Input
            id="bridge-password"
            name="password"
            type={show ? 'text' : 'password'}
            autoComplete="new-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ flex: 1 }}
          />
          <Btn type="button" onClick={() => setShow((s) => !s)} aria-pressed={show}>
            {show ? 'HIDE' : 'SHOW'}
          </Btn>
        </div>
        <p style={hint}>{PASSWORD_RULE}</p>
        {refusal && where === 'password' && <p style={bad}>{refusal.error}</p>}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <label htmlFor="bridge-email" style={label}>
          EMAIL
        </label>
        <Input
          id="bridge-email"
          name="email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <p style={hint}>{EMAIL_NOTE}</p>
        {refusal && where === 'email' && <p style={bad}>{refusal.error}</p>}
      </div>

      {state.signInOrigin && <p style={{ ...hint, color: FG }}>{nextAddress(state.signInOrigin)}</p>}

      {refusal && where === null && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <RefusalLine refusal={refusal} />
          {refusal.code !== 'has_password' && (
            <a href="/login" style={{ color: FG, fontSize: 11, fontFamily: MONO }}>
              BACK TO SIGN-IN
            </a>
          )}
        </div>
      )}

      <Btn type="submit" variant="primary" disabled={busy}>
        SAVE AND CONTINUE TO SIGN IN
      </Btn>
    </form>
  );
}
