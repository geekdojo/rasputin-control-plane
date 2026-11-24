'use client';

// /login — the launcher. The console signs people in only through the
// cluster's sign-in page (geekdojo/geekdojo-brain#989): this page holds no
// credential field, and a signed-in person is routed on.

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getSetupState } from '../../lib/api';
import { getStatus, type AuthStatus } from '../../lib/auth';
import { DIM, FG, HAIR, PANEL } from '../../components/kit';
import { MONO } from '../../components/ui-theme';
import { SignInLauncher, signInReturn, type SignInReturn } from '../../components/SignInLauncher';

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
  // Read once on the client. The launcher, which shows it, renders only
  // after the status fetch, so the prerendered page never holds it.
  const [returned] = useState<SignInReturn | null>(() =>
    typeof window === 'undefined' ? null : signInReturn(window.location.search),
  );
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getStatus()
      .then(async (s) => {
        setStatus(s);
        if (s.user) router.replace(await postAuthDestination());
      })
      .catch((e) => setErr(String(e)));
  }, [router]);

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
                Couldn&apos;t reach the console&apos;s server. Is rasputin-api running?
              </p>
              <pre style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{err}</pre>
            </>
          ) : (
            <p style={{ color: DIM, fontSize: 11, letterSpacing: '0.08em', margin: 0 }}>CONNECTING…</p>
          )
        ) : (
          <SignInLauncher ready={status.ready} firstRun={status.firstRun} returned={returned} />
        )}
      </div>
    </div>
  );
}
