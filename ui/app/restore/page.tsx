'use client';

// /restore — the first-run branch that puts a cluster back (design/storage.md
// §4.5, #291). Unauthenticated by necessity: a re-flashed controlplane has no
// users, and the api closes this surface the moment one exists.
//
// The shape is the operator's question order: which disk, which generation,
// which secret. The key is unwrapped here, checked against the disk, sent
// once, and zeroed — lib/restore.ts. Then the api restarts onto the restored
// identity and this page waits for it to come back with operators, which is
// the only observable proof that the restored database is the one serving.
//
// Copy rules: this phase restores IDENTITY ONLY. The app-volume gap is named,
// by volume, on the chosen generation and again on the result. A page that
// said "restored" and nothing else would be the failure mode this whole
// slice exists to avoid.

import { ArrowRight, HardDrive, RefreshCw, ShieldAlert } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { listRestoreCandidates } from '../../lib/api';
import { ArchiveKeyError, canonicalRecoveryCode, type CustodyPath } from '../../lib/archive-key';
import { getStatus } from '../../lib/auth';
import { appVolumeGap, clusterIdMismatch, generationHeadline, restoreFromGeneration } from '../../lib/restore';
import type { RestoreCandidate, RestoreCandidatesResponse, RestoreGeneration, RestoreReport } from '../../lib/types';
import { Badge, Btn, DIM, FG, HAIR, HAIR_SOFT, Hint, Input, LinkBtn, PANEL, SectionLabel, Tok } from '../../components/kit';
import { MONO } from '../../components/ui-theme';
import { formatDiskSize } from '../../components/storage/format';

const DANGER = '#f87171';
const WARN = '#facc15';
const OK_GREEN = '#4ade80';

// How long to wait for the restarted api to answer with operators before
// telling the operator to look at the box. A restart is seconds; the clock
// gate on an appliance with no NTP can hold the HTTPS listener for longer.
const RESTART_DEADLINE_MS = 4 * 60 * 1000;

type Phase =
  | { kind: 'loading' }
  | { kind: 'closed'; detail: string }
  | { kind: 'error'; detail: string }
  | { kind: 'pick'; data: RestoreCandidatesResponse }
  | { kind: 'submitting'; data: RestoreCandidatesResponse }
  | { kind: 'restarting'; report: RestoreReport; startedAt: number }
  | { kind: 'restored'; report: RestoreReport }
  | { kind: 'restart-timeout'; report: RestoreReport };

export default function RestorePage() {
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>({ kind: 'loading' });
  const [candidate, setCandidate] = useState<RestoreCandidate | null>(null);
  const [generation, setGeneration] = useState<RestoreGeneration | null>(null);
  const [path, setPath] = useState<CustodyPath>('passphrase');
  const [passphrase, setPassphrase] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    listRestoreCandidates()
      .then((data) => {
        setPhase({ kind: 'pick', data });
        // Preselect the only restorable disk and its newest generation, so
        // the common case is one secret away.
        const restorable = data.candidates.filter((c) => c.restorable);
        if (restorable.length === 1) {
          setCandidate(restorable[0]);
          const g = restorable[0].generations.find((x) => x.restorable) ?? null;
          setGeneration(g);
        }
      })
      .catch((e: unknown) => {
        const s = String(e);
        if (s.includes('409')) setPhase({ kind: 'closed', detail: s });
        else setPhase({ kind: 'error', detail: s });
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // After a restore the api exits and comes back on the restored database.
  // Poll the open status endpoint until it reports operators — the restored
  // ones — or the deadline passes.
  useEffect(() => {
    if (phase.kind !== 'restarting') return;
    const { report, startedAt } = phase;
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      try {
        const s = await getStatus();
        if (s.hasUsers) {
          setPhase({ kind: 'restored', report });
          return;
        }
      } catch {
        // Down while it restarts; keep polling.
      }
      if (Date.now() - startedAt > RESTART_DEADLINE_MS) {
        setPhase({ kind: 'restart-timeout', report });
        return;
      }
      setTimeout(tick, 2000);
    };
    const t = setTimeout(tick, 2000);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [phase]);

  async function submit() {
    if (phase.kind !== 'pick' || !candidate || !generation) return;
    setErr(null);
    const data = phase.data;
    setPhase({ kind: 'submitting', data });
    try {
      const secret =
        path === 'passphrase'
          ? { path: 'passphrase' as const, passphrase: new TextEncoder().encode(passphrase) }
          : { path: 'recovery-code' as const, code: canonicalRecoveryCode(recoveryCode) };
      const resp = await restoreFromGeneration(candidate, generation, secret);
      setPassphrase('');
      setRecoveryCode('');
      setPhase({ kind: 'restarting', report: resp.report, startedAt: Date.now() });
    } catch (e) {
      setErr(humanError(e));
      setPhase({ kind: 'pick', data });
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'var(--rasp-bg)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        fontFamily: MONO,
        padding: 24,
      }}
    >
      <div
        style={{
          width: 640,
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
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: OK_GREEN, boxShadow: `0 0 6px ${OK_GREEN}` }} />
          <span style={{ color: FG, fontSize: 13, letterSpacing: '0.18em' }}>RASPUTIN</span>
          <span style={{ color: DIM, fontSize: 11, letterSpacing: '0.1em', marginLeft: 6 }}>RESTORE FROM BACKUP</span>
        </div>

        {phase.kind === 'loading' && <p style={{ color: DIM, fontSize: 11, margin: 0 }}>LOOKING FOR A BACKUP DISK…</p>}

        {phase.kind === 'closed' && (
          <>
            <Hint warn>
              Restore is offered only before the first operator is registered, and this installation already has one.
              To restore onto this controlplane, re-flash it first.
            </Hint>
            <LinkBtn href="/login" variant="primary">
              SIGN IN <ArrowRight size={12} />
            </LinkBtn>
          </>
        )}

        {phase.kind === 'error' && (
          <>
            <Hint warn>Could not list backup disks: {phase.detail}</Hint>
            <div style={{ display: 'flex', gap: 10 }}>
              <Btn
                onClick={() => {
                  setPhase({ kind: 'loading' });
                  load();
                }}
              >
                <RefreshCw size={12} /> TRY AGAIN
              </Btn>
              <LinkBtn href="/login">SET UP FRESH INSTEAD</LinkBtn>
            </div>
          </>
        )}

        {(phase.kind === 'pick' || phase.kind === 'submitting') && (
          <Picker
            data={phase.data}
            busy={phase.kind === 'submitting'}
            candidate={candidate}
            generation={generation}
            onCandidate={(c) => {
              setCandidate(c);
              setGeneration(c.generations.find((g) => g.restorable) ?? null);
            }}
            onGeneration={setGeneration}
            path={path}
            onPath={setPath}
            passphrase={passphrase}
            onPassphrase={setPassphrase}
            recoveryCode={recoveryCode}
            onRecoveryCode={setRecoveryCode}
            onSubmit={submit}
            onRescan={() => {
              setPhase({ kind: 'loading' });
              load();
            }}
            err={err}
          />
        )}

        {phase.kind === 'restarting' && (
          <>
            <SectionLabel>RESTORING</SectionLabel>
            <p style={{ color: FG, fontSize: 11, lineHeight: 1.6, margin: 0 }}>
              The identity set from generation <Tok>{phase.report.generationId}</Tok> is staged and verified. The
              controlplane is restarting to come up on it — this page will notice when it is back.
            </p>
            <ReportSummary report={phase.report} />
            <p style={{ color: DIM, fontSize: 11, margin: 0 }}>WAITING FOR THE CONTROLPLANE…</p>
          </>
        )}

        {phase.kind === 'restored' && (
          <>
            <SectionLabel>RESTORED</SectionLabel>
            <p style={{ color: FG, fontSize: 11, lineHeight: 1.6, margin: 0 }}>
              This controlplane is now the cluster that wrote generation <Tok>{phase.report.generationId}</Tok>. Your
              devices trust its certificate again, your passkeys work again, and your nodes reconnect with the tokens
              they already hold. Sign in with the passkey you used before.
            </p>
            <ReportSummary report={phase.report} />
            <Btn variant="primary" onClick={() => router.replace('/login')}>
              SIGN IN WITH YOUR PASSKEY <ArrowRight size={12} />
            </Btn>
          </>
        )}

        {phase.kind === 'restart-timeout' && (
          <>
            <SectionLabel>STILL WAITING</SectionLabel>
            <Hint warn>
              The restore is staged but the controlplane has not come back with operators after several minutes. If it
              is up, reload this page; if the service did not restart, restart it by hand — the restore applies on its
              next start. Nothing on the backup disk was changed.
            </Hint>
            <ReportSummary report={phase.report} />
            <Btn onClick={() => window.location.reload()}>
              <RefreshCw size={12} /> RELOAD
            </Btn>
          </>
        )}
      </div>
    </div>
  );
}

function Picker(props: {
  data: RestoreCandidatesResponse;
  busy: boolean;
  candidate: RestoreCandidate | null;
  generation: RestoreGeneration | null;
  onCandidate: (c: RestoreCandidate) => void;
  onGeneration: (g: RestoreGeneration) => void;
  path: CustodyPath;
  onPath: (p: CustodyPath) => void;
  passphrase: string;
  onPassphrase: (s: string) => void;
  recoveryCode: string;
  onRecoveryCode: (s: string) => void;
  onSubmit: () => void;
  onRescan: () => void;
  err: string | null;
}) {
  const { data, busy, candidate, generation } = props;
  const mismatch = clusterIdMismatch(candidate?.marker?.clusterId ?? generation?.clusterId, data.clusterId);
  const secretReady = props.path === 'passphrase' ? props.passphrase.length > 0 : canonicalRecoveryCode(props.recoveryCode).length === 32;
  const canSubmit = Boolean(candidate && generation && generation.restorable && secretReady && !mismatch && !busy);

  if (data.candidates.length === 0) {
    return (
      <>
        <Hint>
          No attached disk carries a Rasputin backup set. Plug the backup disk into this controlplane and scan again,
          or set up fresh.
        </Hint>
        <div style={{ display: 'flex', gap: 10 }}>
          <Btn onClick={props.onRescan}>
            <RefreshCw size={12} /> SCAN AGAIN
          </Btn>
          <LinkBtn href="/login">SET UP FRESH</LinkBtn>
        </div>
      </>
    );
  }

  return (
    <>
      <SectionLabel>1 · BACKUP DISK</SectionLabel>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {data.candidates.map((c) => {
          const selected = candidate?.devicePath === c.devicePath;
          return (
            <button
              key={c.devicePath}
              type="button"
              disabled={!c.restorable || busy}
              onClick={() => props.onCandidate(c)}
              style={{
                textAlign: 'left',
                background: selected ? 'rgba(var(--rasp-accent-rgb),0.08)' : 'transparent',
                border: `1px solid ${selected ? 'var(--rasp-accent)' : HAIR_SOFT}`,
                color: FG,
                padding: '10px 12px',
                fontFamily: MONO,
                fontSize: 11,
                cursor: c.restorable ? 'pointer' : 'not-allowed',
                opacity: c.restorable ? 1 : 0.6,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <HardDrive size={12} />
                <span>{c.model || c.devicePath}</span>
                <span style={{ color: DIM }}>{formatDiskSize(c.sizeBytes)}</span>
                {c.marker?.clusterId && <Badge>cluster {c.marker.clusterId}</Badge>}
                {c.marker?.keyId && <Badge>key {c.marker.keyId}</Badge>}
                <Badge color={c.restorable ? OK_GREEN : DANGER}>
                  {c.restorable ? `${c.generations.filter((g) => g.restorable).length} generation(s)` : 'cannot restore'}
                </Badge>
              </div>
              {c.problem && <div style={{ color: WARN, marginTop: 6, lineHeight: 1.5 }}>{c.problem}</div>}
            </button>
          );
        })}
      </div>

      {candidate && (
        <>
          <SectionLabel>2 · GENERATION</SectionLabel>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {candidate.generations.map((g) => {
              const selected = generation?.id === g.id;
              return (
                <button
                  key={g.id}
                  type="button"
                  disabled={!g.restorable || busy}
                  onClick={() => props.onGeneration(g)}
                  style={{
                    textAlign: 'left',
                    background: selected ? 'rgba(var(--rasp-accent-rgb),0.08)' : 'transparent',
                    border: `1px solid ${selected ? 'var(--rasp-accent)' : HAIR_SOFT}`,
                    color: FG,
                    padding: '10px 12px',
                    fontFamily: MONO,
                    fontSize: 11,
                    cursor: g.restorable ? 'pointer' : 'not-allowed',
                    opacity: g.restorable ? 1 : 0.6,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <Tok>{g.id}</Tok>
                    <Badge color={g.complete ? OK_GREEN : WARN}>{g.complete ? 'complete' : 'incomplete'}</Badge>
                    {g.scope && <Badge>{g.scope}</Badge>}
                  </div>
                  <div style={{ color: DIM, marginTop: 6 }}>{generationHeadline(g)}</div>
                  {g.problem && <div style={{ color: WARN, marginTop: 6, lineHeight: 1.5 }}>{g.problem}</div>}
                </button>
              );
            })}
          </div>
          {generation && (
            <Hint warn>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <ShieldAlert size={12} /> IDENTITY ONLY.
              </span>{' '}
              This restores the database (users, passkeys, node tokens, app declarations), the mesh certificate authority
              and the mesh state.{' '}
              {appVolumeGap(generation) || 'This generation holds no app volumes.'}
              {generation.appVolumesAbsent.length > 0 && (
                <>
                  {' '}
                  Not captured in this generation: {generation.appVolumesAbsent.map((v) => v.name).join(', ')}.
                </>
              )}
            </Hint>
          )}
          {mismatch && <Hint warn>{mismatch}</Hint>}
        </>
      )}

      {candidate && generation && (
        <>
          <SectionLabel>3 · UNLOCK THE ARCHIVE KEY</SectionLabel>
          <div style={{ display: 'flex', gap: 8 }}>
            <Btn variant={props.path === 'passphrase' ? 'primary' : undefined} onClick={() => props.onPath('passphrase')} disabled={busy}>
              PASSPHRASE
            </Btn>
            <Btn variant={props.path === 'recovery-code' ? 'primary' : undefined} onClick={() => props.onPath('recovery-code')} disabled={busy}>
              RECOVERY CODE
            </Btn>
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (canSubmit) props.onSubmit();
            }}
            style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
          >
            {props.path === 'passphrase' ? (
              <label htmlFor="restore-passphrase" style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                <span style={{ color: DIM, fontSize: 9, letterSpacing: '0.1em' }}>BACKUP PASSPHRASE</span>
                <Input
                  id="restore-passphrase"
                  type="password"
                  autoComplete="off"
                  value={props.passphrase}
                  onChange={(e) => props.onPassphrase(e.target.value)}
                  disabled={busy}
                />
              </label>
            ) : (
              <label htmlFor="restore-recovery-code" style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                <span style={{ color: DIM, fontSize: 9, letterSpacing: '0.1em' }}>
                  RECOVERY CODE <span style={{ color: 'rgba(138,155,181,0.5)', marginLeft: 8 }}>32 characters · dashes and case ignored</span>
                </span>
                <Input
                  id="restore-recovery-code"
                  autoComplete="off"
                  value={props.recoveryCode}
                  onChange={(e) => props.onRecoveryCode(e.target.value)}
                  disabled={busy}
                />
              </label>
            )}
            <p style={{ color: DIM, fontSize: 10, lineHeight: 1.6, margin: 0 }}>
              The secret never leaves this browser. It unwraps the disk&apos;s archive key here; that key is checked
              against the disk, sent once to the controlplane over its secure connection, and discarded on both sides
              when the restore ends.
            </p>
            <Btn variant="primary" type="submit" disabled={!canSubmit}>
              {busy ? 'UNLOCKING AND RESTORING…' : 'RESTORE THIS GENERATION'}
            </Btn>
          </form>
        </>
      )}

      {props.err && (
        <pre style={{ color: DANGER, fontSize: 10, fontFamily: MONO, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
          {props.err}
        </pre>
      )}

      <div style={{ borderTop: `1px solid ${HAIR_SOFT}`, paddingTop: 12, display: 'flex', gap: 10, alignItems: 'center' }}>
        <LinkBtn href="/login">SET UP FRESH INSTEAD</LinkBtn>
        <Btn onClick={props.onRescan} disabled={busy}>
          <RefreshCw size={12} /> SCAN AGAIN
        </Btn>
      </div>
    </>
  );
}

function ReportSummary({ report }: { report: RestoreReport }) {
  return (
    <div style={{ border: `1px solid ${HAIR_SOFT}`, padding: '10px 12px', fontSize: 11, lineHeight: 1.6, color: FG }}>
      <div>
        Restored {report.restored.length} identity file(s), each verified against the manifest
        {report.keyId && (
          <>
            {' '}
            · key <Tok>{report.keyId}</Tok>
          </>
        )}
        .
      </div>
      <div style={{ color: WARN }}>
        {report.appVolumesPresent.length > 0
          ? `NOT restored (still sealed on the disk): ${report.appVolumesPresent.map((v) => v.name).join(', ')}.`
          : 'The generation held no app volumes.'}
      </div>
      {report.appVolumesAbsent.length > 0 && (
        <div style={{ color: DIM }}>Never captured in this generation: {report.appVolumesAbsent.map((v) => v.name).join(', ')}.</div>
      )}
    </div>
  );
}

function humanError(e: unknown): string {
  if (e instanceof ArchiveKeyError) {
    if (e.kind === 'wrong-secret') return 'That does not open this disk’s archive key. Check the passphrase or recovery code and try again.';
    return e.message;
  }
  const s = String(e);
  if (s.includes('403')) return 'The controlplane refused the key: it does not belong to this disk.';
  return s;
}
