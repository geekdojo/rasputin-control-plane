'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getSetupState } from '../../lib/api';
import {
  getStatus,
  loginWithPasskey,
  registerPasskey,
  type AuthStatus,
} from '../../lib/auth';

// postAuthDestination returns "/setup" if the wizard isn't complete,
// otherwise "/". Used after both registration and sign-in. Failures fall
// through to "/" — the auth layout's setup banner will still nudge them.
async function postAuthDestination(): Promise<string> {
  try {
    const s = await getSetupState();
    return s.completed ? '/' : '/setup';
  } catch {
    return '/';
  }
}

export default function LoginPage() {
  const router = useRouter();
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getStatus()
      .then(async (s) => {
        setStatus(s);
        if (s.user) router.replace(await postAuthDestination());
      })
      .catch((e) => setErr(String(e)));
  }, [router]);

  async function handleLogin() {
    setBusy(true);
    setErr(null);
    try {
      await loginWithPasskey();
      router.replace(await postAuthDestination());
    } catch (e) {
      setErr(humanError(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleRegister() {
    setBusy(true);
    setErr(null);
    try {
      await registerPasskey(name, displayName || name);
      // First registration always lands on /setup so the operator
      // doesn't miss the rest of the wizard.
      router.replace('/setup');
    } catch (e) {
      setErr(humanError(e));
    } finally {
      setBusy(false);
    }
  }

  if (!status) {
    return (
      <main>
        <p className="hint">Loading…</p>
      </main>
    );
  }

  return (
    <main>
      <header>
        <h1>Rasputin</h1>
        <p className="sub">
          {status.hasUsers
            ? 'Sign in with your passkey'
            : 'Welcome — set up the first user'}
        </p>
      </header>

      <section className="auth-form">
        {!status.hasUsers ? (
          <>
            <label>
              <span>
                User name <small>letters · digits · - _ .</small>
              </span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="bryce"
                autoFocus
                disabled={busy}
              />
            </label>
            <label>
              <span>
                Display name <small>optional</small>
              </span>
              <input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Bryce"
                disabled={busy}
              />
            </label>
            <button
              className="primary"
              onClick={handleRegister}
              disabled={busy || !name}
            >
              {busy ? 'Registering…' : 'Register passkey'}
            </button>
          </>
        ) : (
          <>
            <p>Use your passkey to continue.</p>
            <button className="primary" onClick={handleLogin} disabled={busy}>
              {busy ? 'Authenticating…' : 'Sign in with passkey'}
            </button>
          </>
        )}
        {err && <pre className="err">{err}</pre>}
      </section>
    </main>
  );
}

function humanError(e: unknown): string {
  const s = String(e);
  // WebAuthn API errors are noisy; strip the wrapper and report the cause.
  if (s.includes('NotAllowedError')) return 'Cancelled or denied by the authenticator.';
  if (s.includes('InvalidStateError')) return 'A credential already exists on this device for this account.';
  return s;
}
