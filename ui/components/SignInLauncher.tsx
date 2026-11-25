'use client';

// The console's sign-in launcher (geekdojo/geekdojo-brain#989, Identity 4.7).
// It holds no credential field: SIGN IN goes to /api/auth/signin, which sends
// the browser to the cluster's sign-in page and back. What it shows besides
// that one link is a sentence for why the last sign-in came back (the
// ?signin= value the api sends the browser to), a sentence while sign-in is
// not ready, the way to create an account (/api/auth/signup, which opens the
// cluster's sign-up page; geekdojo/geekdojo-brain#990): CREATE THE FIRST
// ACCOUNT at first run and CREATE ACCOUNT after, and at first run the way to
// restore from a backup.
//
// It is a component of its own, apart from app/login/page.tsx, so the page's
// router and fetches stay out of what the DOM tests render.

import { DIM, FG, HAIR, HAIR_SOFT, PANEL } from './kit';
import { ACCENT, MONO } from './ui-theme';

/** The reasons the api sends a sign-in back to the launcher for. */
export type SignInReturn =
  | 'failed'
  | 'expired'
  | 'unavailable'
  | 'wrong-host'
  | 'reset-done'
  | 'reset-incomplete'
  | 'reset-failed'
  | 'action-failed';

/** One sentence for each reason. */
export const SIGN_IN_SENTENCES: Record<SignInReturn, string> = {
  failed: 'The sign-in did not complete. Sign in again.',
  expired: 'That sign-in took too long, or was started in another window. Sign in again.',
  unavailable: 'Sign-in is not available right now. Try again once Rasputin has finished starting.',
  'wrong-host': "Sign in from this cluster's own address, the name ending in .local, not an IP address or another name.",
  // A password reset's return (geekdojo/geekdojo-brain#992).
  'reset-done': 'Your password is changed. Sign in with it and your second step.',
  'reset-incomplete':
    "Your password is changed, but Rasputin couldn't end your other sign-ins. Ask an administrator to sign you out everywhere.",
  'reset-failed':
    "Rasputin couldn't confirm the password reset. If you chose a new password, sign in with it. Otherwise start the reset again.",
  // A fresh-sign-in action that ran and failed, or could not start.
  'action-failed': "Rasputin couldn't finish the change you signed in again for. Try it again.",
};

/** The create-account link's label: the first account at first run. */
export function createAccountLabel(firstRun: boolean): string {
  return firstRun ? 'CREATE THE FIRST ACCOUNT' : 'CREATE ACCOUNT';
}

/** The sentence shown while sign-in is not ready. */
export const NOT_READY_SENTENCE = 'Sign-in is not ready yet. Rasputin is still setting up its sign-in service.';

/** The ?signin= value, or null for none or one the launcher does not know. */
export function signInReturn(search: string): SignInReturn | null {
  const v = new URLSearchParams(search).get('signin');
  return v !== null && v in SIGN_IN_SENTENCES ? (v as SignInReturn) : null;
}

export function SignInLauncher({
  ready,
  firstRun,
  returned,
}: {
  ready: boolean;
  firstRun: boolean;
  returned: SignInReturn | null;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {returned && (
        <p role="status" style={{ color: '#facc15', fontSize: 11, lineHeight: 1.6, margin: 0 }}>
          {SIGN_IN_SENTENCES[returned]}
        </p>
      )}
      {ready ? (
        <a
          href="/api/auth/signin"
          style={{
            display: 'block',
            textAlign: 'center',
            padding: '10px 14px',
            border: `1px solid ${ACCENT}`,
            background: PANEL,
            color: FG,
            fontFamily: MONO,
            fontSize: 11,
            letterSpacing: '0.12em',
            textDecoration: 'none',
          }}
        >
          SIGN IN
        </a>
      ) : (
        <p style={{ color: DIM, fontSize: 11, lineHeight: 1.6, margin: 0 }}>{NOT_READY_SENTENCE}</p>
      )}
      {ready && (
        <a
          href="/api/auth/signup"
          style={{
            display: 'block',
            textAlign: 'center',
            padding: '10px 14px',
            border: `1px solid ${HAIR}`,
            color: FG,
            fontFamily: MONO,
            fontSize: 11,
            letterSpacing: '0.12em',
            textDecoration: 'none',
          }}
        >
          {createAccountLabel(firstRun)}
        </a>
      )}
      {firstRun && (
        <div style={{ borderTop: `1px solid ${HAIR_SOFT}`, paddingTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <p style={{ color: DIM, fontSize: 11, lineHeight: 1.6, margin: 0 }}>
            Bringing this cluster back from a backup disk? Restore it instead of setting up fresh.
          </p>
          <a href="/restore" style={{ color: FG, fontSize: 11, letterSpacing: '0.1em', border: `1px solid ${HAIR}`, padding: '8px 12px', textDecoration: 'none' }}>
            RESTORE FROM BACKUP →
          </a>
        </div>
      )}
    </div>
  );
}
