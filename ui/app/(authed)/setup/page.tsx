'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  completeSetup,
  getSetupState,
  setInstallName,
  setupEnrollSelf,
} from '../../../lib/api';
import type { SetupState, SetupStep } from '../../../lib/types';

// First-run wizard. Step state is derived live from the api — see
// /api/setup/state. The wizard is idempotent and re-runnable; revisiting
// /setup any time after completion shows the same state with all steps
// already ticked.
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
      await setupEnrollSelf();
      // Poll once for state to update — the job is async; in mock mode
      // it completes in <1s. A real Headscale enroll can take longer; the
      // operator can just refresh the page.
      setTimeout(refresh, 1500);
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

  if (!state) {
    return (
      <section className="setup-section">
        <h2>Setup</h2>
        <p className="hint">Loading…</p>
        {err && <pre className="err">{err}</pre>}
      </section>
    );
  }

  const requiredDone = state.steps.every((s) => !s.required || s.done);

  return (
    <section className="setup-section">
      <h2>First-run setup</h2>
      <p className="hint">
        Walks through the steps needed to make your Rasputin useful. Each
        step is derived from the live system — re-visit any time to make
        changes.
      </p>

      {err && <pre className="err">{err}</pre>}

      <ol className="setup-steps">
        {state.steps.map((step) => (
          <StepCard
            key={step.id}
            step={step}
            state={state}
            busy={busy}
            onSaveName={handleSaveName}
            onEnroll={handleEnroll}
          />
        ))}
      </ol>

      <div className="setup-finish">
        {state.completed ? (
          <p className="hint">
            ✓ Setup completed{' '}
            {state.completedAt
              ? new Date(state.completedAt).toLocaleString()
              : ''}
            .
          </p>
        ) : (
          <button
            className="primary"
            disabled={!requiredDone || busy !== null}
            onClick={handleComplete}
            title={
              !requiredDone
                ? 'Finish the required steps first'
                : 'Mark setup complete and continue'
            }
          >
            {busy === 'complete' ? 'finishing…' : 'Finish setup & continue'}
          </button>
        )}
      </div>
    </section>
  );
}

// StepCard renders one step. The body varies by step.id — most are
// informational ("here's the state of this thing"); two have inline
// actions (install_name has a form, remote_access has a button).
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
    <li className={`setup-step ${step.done ? 'done' : 'pending'}`}>
      <div className="setup-step-head">
        <span className="setup-step-mark">{step.done ? '✓' : '○'}</span>
        <h3>{step.title}</h3>
        {step.required && !step.done && (
          <span className="setup-required">required</span>
        )}
      </div>
      {step.detail && <p className="hint">{step.detail}</p>}
      <StepBody
        step={step}
        state={state}
        busy={busy}
        onSaveName={onSaveName}
        onEnroll={onEnroll}
      />
    </li>
  );
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
        <p className="hint">An operator passkey is registered.</p>
      ) : (
        <p className="hint">
          Visit <a href="/login">/login</a> to register the first passkey,
          then come back here.
        </p>
      );
    case 'install_name':
      return <InstallNameForm state={state} busy={busy} onSave={onSaveName} />;
    case 'remote_access':
      return state.selfNodeId === '' ? (
        <p className="hint warn">
          <code>RASPUTIN_SELF_NODE_ID</code> is not set on the api process.
          Set it in your environment (the node id this api represents in
          inventory) and restart — then this step can run.
        </p>
      ) : step.done ? (
        <p className="hint">
          This node is enrolled in the mesh as{' '}
          <code>{state.selfNodeId}</code>.
        </p>
      ) : (
        <button onClick={onEnroll} disabled={busy === 'remote_access'}>
          {busy === 'remote_access'
            ? 'enrolling…'
            : `Enroll ${state.selfNodeId} in mesh`}
        </button>
      );
    case 'trust':
      return step.done ? (
        <p className="hint">
          Root CA is loaded; bundle signatures will be verified.
        </p>
      ) : (
        <p className="hint warn">
          No <code>data/trust/root-ca.pem</code>. Run{' '}
          <code>./scripts/pki-init.sh</code> in the repo, then copy the
          generated <code>root-ca.pem</code> into <code>data/trust/</code>{' '}
          on the api host and restart.
        </p>
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
  // Keep local state in sync if the api state changes underneath us
  // (e.g. another tab edited it).
  useEffect(() => setName(state.installName), [state.installName]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    onSave(name);
  }

  return (
    <form className="setup-name-form" onSubmit={submit}>
      <input
        placeholder="rasputin-bryce"
        value={name}
        onChange={(e) => setName(e.target.value)}
        disabled={busy === 'install_name'}
      />
      <button type="submit" disabled={busy === 'install_name' || !name.trim()}>
        {busy === 'install_name' ? 'saving…' : 'save'}
      </button>
    </form>
  );
}
