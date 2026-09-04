'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getSetupState, listRestoreCandidates } from '../../lib/api';
import { getStatus, loginWithPasskey, registerPasskey, type AuthStatus } from '../../lib/auth';
import { Btn, DIM, FG, HAIR, HAIR_SOFT, Input, LinkBtn, PANEL } from '../../components/kit';
import { MONO } from '../../components/ui-theme';

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
  // Restore-before-first-boot (design/storage.md §4.5, #291): on a box with
  // no operator, a backup disk beside it is offered as the other way in.
  // Best-effort — the register form must never wait on a disk scan.
  const [restorable, setRestorable] = useState(0);

  useEffect(() => {
    getStatus()
      .then(async (s) => {
        setStatus(s);
        if (s.user) router.replace(await postAuthDestination());
        if (!s.hasUsers) {
          listRestoreCandidates()
            .then((r) => setRestorable(r.candidates.filter((c) => c.restorable).length))
            .catch(() => setRestorable(0));
        }
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
      router.replace('/setup');
    } catch (e) {
      setErr(humanError(e));
    } finally {
      setBusy(false);
    }
  }

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
          width: 360,
          maxWidth: '100%',
          background: PANEL,
          border: `1px solid ${HAIR}`,
          padding: '28px 26px',
          display: 'flex',
          flexDirection: 'column',
          gap: 18,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#4ade80', boxShadow: '0 0 6px #4ade80' }} />
          <span style={{ color: FG, fontSize: 13, letterSpacing: '0.18em' }}>RASPUTIN</span>
        </div>

        {!status ? (
          err ? (
            <>
              <p style={{ color: '#facc15', fontSize: 11, lineHeight: 1.6, margin: 0 }}>
                Couldn&apos;t reach the api. Is rasputin-api running on localhost:8080?
              </p>
              <ErrLine>{err}</ErrLine>
            </>
          ) : (
            <p style={{ color: DIM, fontSize: 11, letterSpacing: '0.08em', margin: 0 }}>CONNECTING…</p>
          )
        ) : (
          <>
            <p style={{ color: DIM, fontSize: 11, lineHeight: 1.6, margin: 0 }}>
              {status.hasUsers ? 'Sign in with your passkey.' : 'Welcome — set up the first operator.'}
            </p>

            {!status.hasUsers ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleRegister();
                }}
                style={{ display: 'flex', flexDirection: 'column', gap: 18 }}
              >
                <Field htmlFor="register-name" label="USER NAME" hint="letters · digits · - _ .">
                  {/* eslint-disable-next-line jsx-a11y/no-autofocus -- first field
                      of the only form on a dedicated single-purpose page; nothing
                      above it to skip past, so the focus jump surprises nobody. */}
                  <Input id="register-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="operator" autoFocus disabled={busy} />
                </Field>
                <Field htmlFor="register-display-name" label="DISPLAY NAME" hint="optional">
                  <Input id="register-display-name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Operator" disabled={busy} />
                </Field>
                <Btn variant="primary" type="submit" disabled={busy || !name}>
                  {busy ? 'REGISTERING…' : 'REGISTER PASSKEY'}
                </Btn>
                {restorable > 0 && (
                  <div style={{ borderTop: `1px solid ${HAIR_SOFT}`, paddingTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <p style={{ color: DIM, fontSize: 11, lineHeight: 1.6, margin: 0 }}>
                      A backup disk with {restorable === 1 ? 'a Rasputin backup set' : `${restorable} Rasputin backup sets`} is
                      attached. Restore this cluster&apos;s identity from it instead of setting up fresh.
                    </p>
                    <LinkBtn href="/restore">RESTORE FROM BACKUP →</LinkBtn>
                  </div>
                )}
              </form>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleLogin();
                }}
              >
                <Btn variant="primary" type="submit" disabled={busy}>
                  {busy ? 'AUTHENTICATING…' : 'SIGN IN WITH PASSKEY'}
                </Btn>
              </form>
            )}

            {err && <ErrLine>{err}</ErrLine>}
          </>
        )}
      </div>
    </div>
  );
}

function Field({ htmlFor, label, hint, children }: { htmlFor: string; label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label htmlFor={htmlFor} style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
      <span style={{ color: DIM, fontSize: 9, letterSpacing: '0.1em' }}>
        {label}
        {hint && <span style={{ color: 'rgba(138,155,181,0.5)', marginLeft: 8 }}>{hint}</span>}
      </span>
      {children}
    </label>
  );
}

function ErrLine({ children }: { children: React.ReactNode }) {
  return (
    <pre style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{children}</pre>
  );
}

function humanError(e: unknown): string {
  const s = String(e);
  if (s.includes('NotAllowedError')) return 'Cancelled or denied by the authenticator.';
  if (s.includes('InvalidStateError')) return 'A credential already exists on this device for this account.';
  return s;
}
