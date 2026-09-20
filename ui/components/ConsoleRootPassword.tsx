'use client';

// The console root password surface, shared by the first-run wizard's
// console_root step and the Settings section — the same shape as
// DeploymentModePicker, and for the same reason: two places asking the same
// question must not drift into asking it differently.
//
// geekdojo/geekdojo-brain#587 (decision #558). The copy has to say three
// things plainly, because none of them is guessable:
//
//   1. No image ships a console password. Until this is set and applied,
//      each node's console holds whatever its image was built with.
//   2. Saving applies it to EVERY node, the controlplane included, and the
//      job reports per node.
//   3. A node that could not take it is reported as failed with a reason —
//      it is never quietly skipped. That is the whole point of showing the
//      per-node list here rather than a single tick.
//
// The password itself never comes back from the api, so this form has no
// "current value" to show — only whether one is set, when, and where it has
// reached.

import { useCallback, useEffect, useState } from 'react';
import {
  getConsoleRootPassword,
  pushConsoleRootPassword,
  setConsoleRootPassword,
  type ConsoleRootNode,
  type ConsoleRootStatus,
} from '../lib/api';
import { consoleDraftState, consoleSummary, MIN_CONSOLE_PASSWORD, readNode } from '../lib/console-root';
import { Btn, DIM, FG, HAIR, Hint, Input } from './kit';
import { MONO } from './ui-theme';

const OK = '#4ade80';
const WARN = '#facc15';
const BAD = '#f87171';

export function ConsoleRootPassword({
  // onSaved lets the wizard refresh its derived step state after a save.
  onSaved,
  // compact drops the section heading (the wizard's card supplies one).
  compact = false,
}: {
  onSaved?: () => void;
  compact?: boolean;
}) {
  const [status, setStatus] = useState<ConsoleRootStatus | null>(null);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState<'save' | 'push' | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  // The first load is the promise chain rather than a call to refresh():
  // an effect body must not reach a setState synchronously
  // (react-hooks/set-state-in-effect), and `alive` keeps a reply that
  // arrives after an unmount from setting state on a gone component.
  useEffect(() => {
    let alive = true;
    getConsoleRootPassword()
      .then((s) => {
        if (alive) setStatus(s);
      })
      .catch((e) => {
        if (alive) setErr(String(e));
      });
    return () => {
      alive = false;
    };
  }, []);

  // refresh is the awaitable form the buttons and save() use, so a save can
  // report the new state before it hands control back to the wizard.
  const refresh = useCallback(async () => {
    try {
      setStatus(await getConsoleRootPassword());
    } catch (e) {
      setErr(String(e));
    }
  }, []);

  const draft = consoleDraftState(password, confirm);

  async function save() {
    setBusy('save');
    setErr(null);
    setNote(null);
    try {
      const saved = await setConsoleRootPassword(password);
      setPassword('');
      setConfirm('');
      setNote(
        saved.pushError
          ? `Saved, but the job that applies it did not start: ${saved.pushError}`
          : 'Saved. Applying it to every node — the per-node result appears below.',
      );
      await refresh();
      onSaved?.();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function reapply() {
    setBusy('push');
    setErr(null);
    setNote(null);
    try {
      await pushConsoleRootPassword();
      setNote('Applying the saved password to every node — the per-node result appears below.');
      await refresh();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div style={{ maxWidth: 720 }}>
      {!compact && (
        <Hint style={{ marginBottom: 8 }}>
          The password <Mono>root</Mono> uses at a node&apos;s physical console or its serial-over-LAN session.
          No Rasputin image ships one, so until you set it here each node keeps whatever its image was built with.
        </Hint>
      )}
      <Hint style={{ marginBottom: 16 }}>
        Saving applies it to <em>every</em> node in this cluster, the controlplane included, and to nodes that
        join later. A node that cannot take it is reported below with the reason — it is never skipped.
      </Hint>

      {err && (
        <Hint warn style={{ marginBottom: 12 }}>
          {err}
        </Hint>
      )}
      {note && <Hint style={{ marginBottom: 12, color: OK }}>{note}</Hint>}

      {status === null && !err && <Hint>Loading…</Hint>}

      {status !== null && (
        <>
          <Hint style={{ marginBottom: 12 }}>
            {status.set ? (
              <>
                A console root password is set
                {status.setAt ? ` · ${new Date(status.setAt).toLocaleString()}` : ''}. It is stored as a hash and
                is never shown again — to change it, type a new one.
              </>
            ) : (
              <span style={{ color: WARN }}>No console root password is set yet.</span>
            )}
          </Hint>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={`At least ${MIN_CONSOLE_PASSWORD} characters`}
              aria-label={status.set ? 'New console root password' : 'Console root password'}
              autoComplete="new-password"
              spellCheck={false}
            />
            <Input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Type it again"
              aria-label="Confirm the console root password"
              autoComplete="new-password"
              spellCheck={false}
            />
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <Btn variant="primary" small onClick={save} disabled={busy !== null || !draft.canSave}>
                {busy === 'save' ? 'SAVING…' : status.set ? 'CHANGE ON ALL NODES' : 'SET ON ALL NODES'}
              </Btn>
              {status.set && (
                <Btn small variant="ghost" onClick={reapply} disabled={busy !== null}>
                  {busy === 'push' ? 'APPLYING…' : 'RE-APPLY TO ALL NODES'}
                </Btn>
              )}
            </div>
            {draft.error ? (
              <Hint warn>{draft.error}</Hint>
            ) : (
              <Hint>
                You will need this at a console, where there is no clipboard — choose something you can type.
              </Hint>
            )}
          </div>

          <NodeList status={status} onRefresh={refresh} />
        </>
      )}
    </div>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span style={{ color: FG, fontFamily: MONO }}>{children}</span>;
}

// The per-node report. #558 asks for per-node success/failure; a fleet
// summary that hid which node failed would be the silent skip in another
// costume, so every node that is not holding the current password is listed
// with its reason.
function NodeList({ status, onRefresh }: { status: ConsoleRootStatus; onRefresh: () => void }) {
  const nodes = status.nodes ?? [];
  if (!status.set && nodes.length === 0) return null;
  const { applied, outstanding, total } = consoleSummary(status);

  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <span style={{ color: outstanding > 0 ? WARN : OK, fontSize: 10, fontFamily: MONO, letterSpacing: '0.04em' }}>
          {total === 0
            ? 'NO NODES HAVE BEEN SENT IT YET'
            : `${applied}/${total} NODE${total === 1 ? '' : 'S'} HOLD THIS PASSWORD`}
        </span>
        <Btn small variant="ghost" onClick={onRefresh}>
          REFRESH
        </Btn>
      </div>
      {nodes.length > 0 && (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {nodes.map((n) => (
            <NodeRow key={n.nodeId} node={n} currentHashId={status.hashId ?? ''} />
          ))}
        </ul>
      )}
    </div>
  );
}

function NodeRow({ node, currentHashId }: { node: ConsoleRootNode; currentHashId: string }) {
  const reading = readNode(node, currentHashId);
  const label = {
    applied: 'HOLDS IT',
    pending: 'APPLYING…',
    stale: 'HOLDS AN OLDER PASSWORD',
    failed: 'DID NOT TAKE IT',
  }[reading];
  const color = { applied: OK, pending: DIM, stale: WARN, failed: BAD }[reading];
  // A stale node has no failure reason of its own — say what is true.
  const detail = reading === 'stale' ? 'It applied an earlier password. Re-apply to bring it up to date.' : node.detail;

  return (
    <li style={{ border: `1px solid ${HAIR}`, padding: '8px 10px' }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
        <span style={{ color: FG, fontSize: 11, fontFamily: MONO }}>{node.nodeId}</span>
        <span style={{ color, fontSize: 10, fontFamily: MONO, letterSpacing: '0.04em', marginLeft: 'auto' }}>{label}</span>
      </div>
      {detail && (
        <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: '6px 0 0' }}>{detail}</p>
      )}
    </li>
  );
}
