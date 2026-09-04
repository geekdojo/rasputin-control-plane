'use client';

import { RotateCcw, X } from 'lucide-react';
import { useEffect, useId, useState } from 'react';
import { getAppRestoreSources } from '../lib/api';
import {
  RESTORE_CONFIRM_DEFAULT,
  canSubmitRestore,
  confirmationCopy,
  generationLine,
  restoreAppData,
  restoreBlocker,
} from '../lib/app-restore';
import { ArchiveKeyError, canonicalRecoveryCode, type CustodyPath, type CustodySecret } from '../lib/archive-key';
import type { App, AppRestoreGeneration, AppRestoreResponse, AppRestoreSources } from '../lib/types';
import { formatBytes } from '../lib/volumes';
import { ModalPortal, useModalChrome } from './modal';
import { MONO } from './ui-theme';
import { Badge, Btn, DIM, FG, HAIR_SOFT, Hint, Input, LinkBtn, SectionLabel } from './kit';

// "Restore data from a backup…" for one app — design/storage.md §4.5 phase 2
// (geekdojo/geekdojo-brain#291). Explicit, per app, operator-initiated.
//
// The operator's question order, then the informed confirmation in the same
// shape as #399's uninstall prompt:
//
//   1. which backup — the generations that hold this app's volumes, each with
//      its age, whether the run was complete, and which volumes it holds
//      (and which of those the plan will NOT put back, with why);
//   2. the custody secret — passphrase or recovery code, unwrapped here; the
//      key is checked against the disk, lent once to the api for this restore
//      (lib/app-restore.ts), and zeroed;
//   3. the confirmation — which volumes, from when, that the CURRENT DATA IS
//      REPLACED (the previous contents are kept beside the volume on the
//      node), and that the app is stopped while each volume is swapped. The
//      checkbox starts UNTICKED; keep-live is the default.
//
// What cannot proceed is said before a secret is asked for: an app that is
// not deployed, a node that is offline, a disk with nothing for this app.

const DANGER = '#f87171';
const WARN = '#facc15';
const OK_GREEN = '#4ade80';

function classColor(backup: string): string {
  switch (backup) {
    case 'critical':
      return DANGER;
    case 'state':
      return WARN;
    default:
      return DIM;
  }
}

export interface RestoreAppDataModalProps {
  app: App;
  onClose: () => void;
}

type Outcome = { kind: 'idle' } | { kind: 'submitted'; res: AppRestoreResponse };

export function RestoreAppDataModal({ app, onClose }: RestoreAppDataModalProps) {
  const { initialFocusRef } = useModalChrome({ open: true, onClose });
  const [src, setSrc] = useState<AppRestoreSources | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [generation, setGeneration] = useState<AppRestoreGeneration | null>(null);
  const [path, setPath] = useState<CustodyPath>('passphrase');
  const [passphrase, setPassphrase] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [confirmed, setConfirmed] = useState<boolean>(RESTORE_CONFIRM_DEFAULT);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome>({ kind: 'idle' });
  const checkboxId = useId();

  useEffect(() => {
    let cancelled = false;
    getAppRestoreSources(app.id)
      .then((s) => {
        if (cancelled) return;
        setSrc(s);
        // Preselect the newest restorable generation, so the common case is
        // one secret and one tick away — and never a generation that cannot
        // be restored.
        const first = s.generations.find((g) => g.restorable) ?? null;
        setGeneration(first);
      })
      .catch((e: unknown) => {
        if (!cancelled) setLoadErr(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [app.id]);

  const blocker = loadErr ?? restoreBlocker(src, generation);
  const secretReady = path === 'passphrase' ? passphrase.length > 0 : canonicalRecoveryCode(recoveryCode).length === 32;
  const canSubmit = canSubmitRestore({ confirmed, src, generation, secretReady, busy });
  const copy = src && generation && generation.restorable ? confirmationCopy(app, src, generation) : null;

  async function submit() {
    if (!src || !generation || !canSubmit) return;
    setBusy(true);
    setErr(null);
    try {
      const secret: CustodySecret =
        path === 'passphrase'
          ? { path: 'passphrase', passphrase: new TextEncoder().encode(passphrase) }
          : { path: 'recovery-code', code: canonicalRecoveryCode(recoveryCode) };
      const res = await restoreAppData(app, src, generation, secret);
      setPassphrase('');
      setRecoveryCode('');
      setOutcome({ kind: 'submitted', res });
    } catch (e: unknown) {
      setErr(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ModalPortal>
      <div onClick={onClose} aria-hidden style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000 }} />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Restore data of ${app.name} from a backup`}
        style={{
          position: 'fixed',
          inset: 0,
          margin: 'auto',
          height: 'fit-content',
          maxHeight: '90vh',
          overflowY: 'auto',
          zIndex: 1001,
          background: 'var(--rasp-panel)',
          border: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
          padding: '24px',
          width: 560,
          display: 'flex',
          flexDirection: 'column',
          gap: 14,
          fontFamily: MONO,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <RotateCcw size={14} color={WARN} />
            <span style={{ color: FG, fontSize: 11, letterSpacing: '0.1em' }}>RESTORE DATA FROM A BACKUP</span>
          </div>
          <button
            ref={initialFocusRef as React.RefObject<HTMLButtonElement | null>}
            type="button"
            onClick={onClose}
            aria-label="Close"
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            <X size={14} color={DIM} />
          </button>
        </div>
        <div style={{ height: 1, background: HAIR_SOFT }} />

        {outcome.kind === 'submitted' ? (
          <Submitted app={app} res={outcome.res} onClose={onClose} />
        ) : (
          <>
            <p style={{ color: DIM, fontSize: 11, lineHeight: 1.6, margin: 0 }}>
              Put {app.name}&apos;s data back from a backup generation. Nothing is restored automatically: this replaces
              what {app.name} holds now on {src?.nodeId ?? app.targetNode} with the copy in the backup you choose.
            </p>

            {blocker && (
              <Hint warn>{blocker}</Hint>
            )}

            {/* 1 · which backup */}
            {src && src.generations.length > 0 && (
              <div>
                <SectionLabel>1 · WHICH BACKUP</SectionLabel>
                <div role="radiogroup" aria-label="Backup generation" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {src.generations.map((g) => {
                    const selected = generation?.id === g.id;
                    return (
                      <label
                        key={g.id}
                        style={{
                          display: 'flex',
                          gap: 8,
                          alignItems: 'flex-start',
                          padding: '6px 8px',
                          border: `1px solid ${selected ? 'rgba(var(--rasp-fg-rgb),0.35)' : HAIR_SOFT}`,
                          cursor: g.restorable ? 'pointer' : 'not-allowed',
                          opacity: g.restorable ? 1 : 0.6,
                          fontSize: 10,
                          color: FG,
                          lineHeight: 1.6,
                        }}
                      >
                        <input
                          type="radio"
                          name="restore-generation"
                          checked={selected}
                          disabled={!g.restorable || busy}
                          onChange={() => {
                            setGeneration(g);
                            setConfirmed(RESTORE_CONFIRM_DEFAULT);
                          }}
                          aria-label={`Generation ${g.id}`}
                          style={{ marginTop: 3 }}
                        />
                        <span style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                          <span>{generationLine(g)}</span>
                          <span style={{ color: DIM, fontSize: 9, wordBreak: 'break-all' }}>{g.id}</span>
                          {!g.restorable && g.problem && <span style={{ color: WARN, fontSize: 9 }}>{g.problem}</span>}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>
            )}

            {/* The volumes the chosen generation holds for this app, and the verdict on each. */}
            {generation && (
              <div>
                <SectionLabel>VOLUMES IN THAT BACKUP</SectionLabel>
                <table aria-label="Volumes in the backup" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                  <thead>
                    <tr>
                      {['VOLUME', 'CLASS', 'SIZE', 'RESTORE'].map((h) => (
                        <th key={h} scope="col" style={{ textAlign: 'left', color: DIM, fontWeight: 400, fontSize: 9, letterSpacing: '0.1em', padding: '2px 6px 4px 0' }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {generation.volumes.map((v) => (
                      <tr key={v.volume}>
                        <td style={{ color: FG, padding: '3px 6px 3px 0', verticalAlign: 'top' }}>{v.volume}</td>
                        <td style={{ padding: '3px 6px 3px 0', verticalAlign: 'top' }}>
                          <Badge color={classColor(v.class)}>{(v.class || 'unclassified').toUpperCase()}</Badge>
                        </td>
                        <td style={{ color: DIM, padding: '3px 6px 3px 0', verticalAlign: 'top' }}>{formatBytes(v.sizeBytes)}</td>
                        <td style={{ color: v.restorable ? OK_GREEN : WARN, padding: '3px 0', verticalAlign: 'top', lineHeight: 1.5 }}>
                          {v.restorable ? 'yes' : `no — ${v.reason ?? 'not restorable'}`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {copy?.reinstalled && <Hint warn style={{ marginTop: 6 }}>{copy.reinstalled}</Hint>}
              </div>
            )}

            {/* 2 · the secret */}
            {src && generation && generation.restorable && !blocker && (
              <div>
                <SectionLabel>2 · UNLOCK THE ARCHIVE KEY</SectionLabel>
                <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                  <Btn small variant={path === 'passphrase' ? 'primary' : undefined} onClick={() => setPath('passphrase')} disabled={busy}>
                    PASSPHRASE
                  </Btn>
                  <Btn small variant={path === 'recovery-code' ? 'primary' : undefined} onClick={() => setPath('recovery-code')} disabled={busy}>
                    RECOVERY CODE
                  </Btn>
                </div>
                {path === 'passphrase' ? (
                  <label htmlFor="app-restore-passphrase" style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    <span style={{ color: DIM, fontSize: 9, letterSpacing: '0.1em' }}>BACKUP PASSPHRASE</span>
                    <Input id="app-restore-passphrase" type="password" autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} disabled={busy} />
                  </label>
                ) : (
                  <label htmlFor="app-restore-recovery-code" style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    <span style={{ color: DIM, fontSize: 9, letterSpacing: '0.1em' }}>
                      RECOVERY CODE <span style={{ color: DIM, marginLeft: 8 }}>32 characters · dashes and case ignored</span>
                    </span>
                    <Input id="app-restore-recovery-code" autoComplete="off" value={recoveryCode} onChange={(e) => setRecoveryCode(e.target.value)} disabled={busy} />
                  </label>
                )}
                <p style={{ color: DIM, fontSize: 9, lineHeight: 1.6, margin: '6px 0 0' }}>
                  The secret never leaves this browser. It unwraps the disk&apos;s archive key here; that key is checked against the
                  disk, sent once to the controlplane over its secure connection for this restore, and discarded when the restore
                  ends. The controlplane opens the backup; your nodes receive the data over the same secure connection updates use.
                </p>
              </div>
            )}

            {/* 3 · the confirmation. Unticked by default: keep-live is the path of least resistance. */}
            {copy && !blocker && (
              <div>
                <SectionLabel>3 · CONFIRM</SectionLabel>
                <p style={{ color: FG, fontSize: 10, lineHeight: 1.6, margin: '0 0 8px' }}>{copy.detail}</p>
                <label htmlFor={checkboxId} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer', color: FG, fontSize: 10, lineHeight: 1.6 }}>
                  <input
                    id={checkboxId}
                    type="checkbox"
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                    disabled={busy}
                    aria-label={copy.checkbox}
                    style={{ marginTop: 3 }}
                  />
                  <span>
                    {copy.checkbox}
                    <span style={{ color: DIM }}> Unticked, nothing happens and {app.name} keeps what it has.</span>
                  </span>
                </label>
              </div>
            )}

            {err && (
              <div role="alert" style={{ color: DANGER, fontSize: 10, lineHeight: 1.6, padding: '8px 10px', border: `1px solid rgba(248,113,113,0.5)`, background: 'rgba(248,113,113,0.08)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                {err}
              </div>
            )}

            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <Btn onClick={onClose} disabled={busy}>
                CANCEL
              </Btn>
              <Btn variant="danger" disabled={!canSubmit} aria-label={`Restore data of ${app.name}`} onClick={() => void submit()}>
                {busy ? 'UNLOCKING AND STARTING…' : 'REPLACE DATA FROM THIS BACKUP'}
              </Btn>
            </div>
          </>
        )}
      </div>
    </ModalPortal>
  );
}

function Submitted({ app, res, onClose }: { app: App; res: AppRestoreResponse; onClose: () => void }) {
  return (
    <>
      <p style={{ color: FG, fontSize: 11, lineHeight: 1.6, margin: 0 }}>
        The restore of {app.name}&apos;s data is running as job <span style={{ color: DIM }}>{res.job.id}</span>.
      </p>
      <p style={{ color: DIM, fontSize: 10, lineHeight: 1.6, margin: 0 }}>{res.detail}</p>
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <LinkBtn href={`/tasks?id=${encodeURIComponent(res.job.id)}`} variant="primary" aria-label={`Watch the restore of ${app.name}`}>
          WATCH IN TASKS
        </LinkBtn>
        <Btn onClick={onClose}>CLOSE</Btn>
      </div>
    </>
  );
}

function describeError(e: unknown): string {
  if (e instanceof ArchiveKeyError) {
    if (e.kind === 'wrong-secret') return 'That does not open this disk’s archive key. Check the passphrase or recovery code and try again. Nothing was sent and nothing was stopped.';
    if (e.kind === 'key-mismatch') return e.message;
    return `The disk’s archive key could not be read: ${e.message}`;
  }
  return String(e);
}
