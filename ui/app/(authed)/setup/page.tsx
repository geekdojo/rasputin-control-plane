'use client';

import { Check, Circle, Rocket } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { completeSetup, getJob, getSetupState, setInstallName, setupEnrollSelf } from '../../../lib/api';
import type { SetupState, SetupStep } from '../../../lib/types';
import { Badge, Btn, DIM, FG, HAIR, Input, PageBody, PageHeader, PageShell, PANEL } from '../../../components/kit';
import { ACCENT, MONO } from '../../../components/ui-theme';

export default function SetupPage() {
  const router = useRouter();
  const [state, setState] = useState<SetupState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    refresh();
  }, []);

  async function refresh() {
    try {
      setState(await getSetupState());
    } catch (e) {
      setErr(String(e));
    }
  }

  async function handleSaveName(name: string) {
    setBusy('install_name');
    setErr(null);
    try {
      setState(await setInstallName(name));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleEnroll() {
    setBusy('remote_access');
    setErr(null);
    try {
      const job = await setupEnrollSelf();
      // Poll the enroll job to a terminal state so a failed enrollment
      // surfaces here instead of silently leaving the step un-done (the
      // first Mu wizard run failed agent-side and showed nothing).
      // Budget must cover a REAL enrollment, not just the mock: on hardware
      // the agent restarts tailscaled, waits for the daemon, runs `tailscale
      // up`, and only then returns the tailnet id the record step needs —
      // ~10-30s on an N100 (bench 2026-06-18: a 7s budget expired first, so
      // the step showed un-done even though the job later succeeded). Poll up
      // to ~60s; if it's still running after that, say so rather than leave a
      // silently-stale circle.
      let terminal = false;
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const j = await getJob(job.id);
        if (j.status === 'failed' || j.status === 'cancelled') {
          setErr(`Enrollment failed${j.error ? `: ${j.error}` : ' — see the Tasks panel for details.'}`);
          terminal = true;
          break;
        }
        if (j.status === 'succeeded') {
          terminal = true;
          break;
        }
      }
      if (!terminal) {
        setErr('Enrollment is still running — it may finish shortly. Check the Tasks panel, then refresh this page.');
      }
      await refresh();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleComplete() {
    setBusy('complete');
    setErr(null);
    try {
      const s = await completeSetup();
      setState(s);
      if (s.completed) router.replace('/');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  const requiredDone = state ? state.steps.every((s) => !s.required || s.done) : false;

  return (
    <PageShell>
      <PageHeader icon={Rocket} title="FIRST-RUN SETUP" />
      <PageBody>
        <p style={{ color: DIM, fontSize: 11, fontFamily: MONO, lineHeight: 1.6, marginTop: 0, marginBottom: 18, maxWidth: 640 }}>
          Steps to make your Rasputin useful. Each is derived live from the system — revisit any time to make changes.
        </p>

        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 14 }}>{err}</div>}

        {!state ? (
          <p style={{ color: DIM, fontSize: 11, fontFamily: MONO }}>LOADING…</p>
        ) : (
          <>
            <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 640 }}>
              {state.steps.map((step) => (
                <StepCard key={step.id} step={step} state={state} busy={busy} onSaveName={handleSaveName} onEnroll={handleEnroll} />
              ))}
            </ol>

            <div style={{ marginTop: 20, maxWidth: 640 }}>
              {state.completed ? (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: '#4ade80', fontSize: 11, fontFamily: MONO }}>
                  <Check size={13} color="#4ade80" /> SETUP COMPLETE
                  {state.completedAt ? ` · ${new Date(state.completedAt).toLocaleString()}` : ''}
                </span>
              ) : (
                <Btn
                  variant="primary"
                  disabled={!requiredDone || busy !== null}
                  onClick={handleComplete}
                  title={!requiredDone ? 'Finish the required steps first' : 'Mark setup complete and continue'}
                >
                  {busy === 'complete' ? 'FINISHING…' : 'FINISH SETUP & CONTINUE'}
                </Btn>
              )}
            </div>
          </>
        )}
      </PageBody>
    </PageShell>
  );
}

function StepCard({
  step,
  state,
  busy,
  onSaveName,
  onEnroll,
}: {
  step: SetupStep;
  state: SetupState;
  busy: string | null;
  onSaveName: (name: string) => void;
  onEnroll: () => void;
}) {
  return (
    <li
      style={{
        background: PANEL,
        border: `1px solid ${step.done ? 'rgba(74,222,128,0.25)' : HAIR}`,
        padding: '14px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {step.done ? <Check size={14} color="#4ade80" /> : <Circle size={14} color={ACCENT} />}
        <span style={{ color: FG, fontSize: 12, fontFamily: MONO, letterSpacing: '0.04em' }}>{step.title}</span>
        {step.required && !step.done && (
          <span style={{ marginLeft: 'auto' }}>
            <Badge color="#facc15">REQUIRED</Badge>
          </span>
        )}
      </div>
      {step.detail && <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>{step.detail}</p>}
      <StepBody step={step} state={state} busy={busy} onSaveName={onSaveName} onEnroll={onEnroll} />
    </li>
  );
}

function Hint({ children, warn = false }: { children: React.ReactNode; warn?: boolean }) {
  return (
    <p style={{ color: warn ? '#facc15' : DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>{children}</p>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span style={{ color: FG }}>{children}</span>;
}

function StepBody({
  step,
  state,
  busy,
  onSaveName,
  onEnroll,
}: {
  step: SetupStep;
  state: SetupState;
  busy: string | null;
  onSaveName: (name: string) => void;
  onEnroll: () => void;
}) {
  switch (step.id) {
    case 'passkey':
      return step.done ? (
        <Hint>An operator passkey is registered.</Hint>
      ) : (
        <Hint>
          Visit <Mono>/login</Mono> to register the first passkey, then come back here.
        </Hint>
      );
    case 'install_name':
      return <InstallNameForm state={state} busy={busy} onSave={onSaveName} />;
    case 'remote_access':
      return state.selfNodeId === '' ? (
        <Hint warn>
          <Mono>RASPUTIN_SELF_NODE_ID</Mono> is not set on the api process. Set it (the node id this api represents in inventory) and restart — then this step can run.
        </Hint>
      ) : step.done ? (
        <Hint>
          This node is enrolled in the mesh as <Mono>{state.selfNodeId}</Mono>.
        </Hint>
      ) : (
        <div>
          <Btn disabled={busy === 'remote_access'} onClick={onEnroll}>
            {busy === 'remote_access' ? 'ENROLLING…' : `ENROLL ${state.selfNodeId.toUpperCase()} IN MESH`}
          </Btn>
        </div>
      );
    case 'trust':
      return step.done ? (
        <Hint>Update signing is verified — OS updates are checked for authenticity before they install.</Hint>
      ) : (
        <Hint warn>
          The update trust root is missing, so OS updates can&apos;t be verified. On Rasputin hardware
          this is preinstalled — if you&apos;re seeing this on a real system, re-flash the OS image
          (images from 2026.06.0-dev.12 onward wire it up automatically). Developing locally? Run{' '}
          <Mono>./scripts/pki-init.sh</Mono> and copy <Mono>root-ca.pem</Mono> into <Mono>data/trust/</Mono>,
          then restart the api.
        </Hint>
      );
    default:
      return null;
  }
}

function InstallNameForm({
  state,
  busy,
  onSave,
}: {
  state: SetupState;
  busy: string | null;
  onSave: (name: string) => void;
}) {
  const [name, setName] = useState(state.installName);
  useEffect(() => setName(state.installName), [state.installName]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    onSave(name);
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 8 }}>
      <Input
        placeholder="rasputin-home"
        value={name}
        onChange={(e) => setName(e.target.value)}
        disabled={busy === 'install_name'}
        style={{ flex: 1, maxWidth: 280 }}
      />
      <Btn type="submit" variant="primary" disabled={busy === 'install_name' || !name.trim()}>
        {busy === 'install_name' ? 'SAVING…' : 'SAVE'}
      </Btn>
    </form>
  );
}
