'use client';

// Storage → Backups → the RUN panel — design/storage.md §4.1's producer, seen.
//
// Three jobs, in the order an operator asks them:
//
//   1. "Is my data actually backed up?"  → the scope banner, first and loudest
//   2. "When did one last work?"         → the last-success line, never a
//                                          count of attempts
//   3. "Run one now" / "how often?"      → the control and the cadence
//
// # Why the scope banner is at the top and cannot be dismissed
//
// Every generation this build writes contains the control-plane's identity —
// the database, the mesh CA, Headscale state — and NO app data, because no
// volume anywhere carries a backup class yet (#292/#293 unbuilt). A Vaultwarden
// vault is exactly what §4.2 classes `critical`, and it is not in the archive.
//
// A user who sees a green "backed up 2 hours ago" and nothing else will believe
// their apps are safe. That belief is the failure mode this whole panel is
// shaped around, so the caveat is rendered ABOVE the success line, in the
// api's own words (scopeWarning), on every render, with no way to hide it —
// and the per-run rows repeat it as a scope tag. When the fan-out stops being
// empty the api starts sending `scope: "full"` and this banner goes away on its
// own.

import { AlertTriangle, Clock, Play, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import {
  getBackupSchedule,
  listBackupRuns,
  setBackupSchedule,
  startBackupRun,
} from '../../lib/api';
import { timeAgo } from '../../lib/time';
import type { BackupRun, BackupRunsResponse, BackupSchedule } from '../../lib/types';
import { Badge, Btn, DIM, FG, HAIR_SOFT, Hint, SectionLabel, Select, srOnly, tdStyle, thStyle } from '../kit';
import { MONO } from '../ui-theme';
import {
  CADENCE_OFF,
  appVolumeSummary,
  cadenceRequest,
  cadenceValue,
  shouldWarnIncomplete,
} from './backup-runs';
import { formatDiskSize } from './format';

const DANGER = '#f87171';
const WARN = '#facc15';
const OK_GREEN = '#4ade80';

// The cadences a form offers. §4.1's default is weekly; the api's floor is an
// hour and its ceiling a year, so every option here is inside both.
const CADENCES: { label: string; value: string }[] = [
  { label: 'Daily', value: '24h' },
  { label: 'Every 3 days', value: '72h' },
  { label: 'Weekly (default)', value: '168h' },
  { label: 'Fortnightly', value: '336h' },
  { label: 'Monthly', value: '720h' },
];

export function BackupRuns({ hasTarget }: { hasTarget: boolean }) {
  const [data, setData] = useState<BackupRunsResponse | null>(null);
  const [schedule, setSchedule] = useState<BackupSchedule | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    listBackupRuns(20)
      .then((d) => {
        setData(d);
        setErr(null);
      })
      .catch((e) => setErr(String(e)));
    getBackupSchedule()
      .then(setSchedule)
      .catch(() => {
        // A schedule the api will not serve is not worth an error banner over
        // the run list: the runs are the answer to "am I backed up", and the
        // cadence control simply does not render.
        setSchedule(null);
      });
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const runNow = useCallback(() => {
    setBusy(true);
    startBackupRun()
      .then(() => {
        setErr(null);
        refresh();
      })
      .catch((e) => setErr(String(e)))
      .finally(() => setBusy(false));
  }, [refresh]);

  const changeCadence = useCallback(
    (next: { enabled: boolean; every?: string }) => {
      setBackupSchedule(next)
        .then((s) => {
          setSchedule(s);
          setErr(null);
        })
        .catch((e) => setErr(String(e)));
    },
    [],
  );

  const runs = data?.runs ?? [];
  const last = data?.lastSuccess ?? null;
  // Extracted so it is executed by `npm test` rather than only compiled — the
  // banner it gates is the one rendering decision on this page whose failure
  // costs somebody their data. See backup-runs.ts.
  const incomplete = shouldWarnIncomplete(data);

  return (
    <>
      <SectionLabel style={{ marginTop: 26 }}>BACKUP RUNS</SectionLabel>

      {/* Above everything, always. See the header comment. */}
      {incomplete && (
        <div
          style={{
            display: 'flex',
            gap: 10,
            alignItems: 'flex-start',
            border: `1px solid ${WARN}`,
            borderLeftWidth: 3,
            padding: '10px 12px',
            marginBottom: 14,
            lineHeight: 1.6,
            fontSize: 11,
            color: FG,
          }}
        >
          <AlertTriangle size={14} color={WARN} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden />
          <div>
            <strong style={{ color: WARN, fontFamily: MONO, fontSize: 10, letterSpacing: '0.1em' }}>
              IDENTITY ONLY — NOT A COMPLETE BACKUP
            </strong>
            <div style={{ marginTop: 5, color: DIM }}>
              {data?.scopeWarning ??
                'Backups from this build capture the control plane’s identity and no app data.'}
            </div>
          </div>
        </div>
      )}

      {err && <Hint warn style={{ marginBottom: 12 }}>{err}</Hint>}

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexWrap: 'wrap',
          paddingBottom: 8,
          marginBottom: 10,
          borderBottom: `1px solid ${HAIR_SOFT}`,
        }}
      >
        <LastSuccess last={last} hasTarget={hasTarget} />
        <div style={{ flex: 1 }} />
        {schedule && (
          <label htmlFor="backup-cadence" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span style={srOnly}>How often a backup runs</span>
            <Clock size={11} color={DIM} aria-hidden />
            <Select
              id="backup-cadence"
              value={cadenceValue(schedule)}
              onChange={(e) => changeCadence(cadenceRequest(e.target.value))}
              style={{ fontSize: 10 }}
            >
              {CADENCES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
              <option value={CADENCE_OFF}>Scheduled backups off</option>
            </Select>
          </label>
        )}
        <Btn small onClick={refresh}>
          <RefreshCw size={10} /> REFRESH
        </Btn>
        <Btn small disabled={busy || !hasTarget} onClick={runNow} title={hasTarget ? undefined : 'Claim a backup target first'}>
          <Play size={10} /> {busy ? 'STARTING…' : 'BACK UP NOW'}
        </Btn>
      </div>

      {/* A disabled schedule is shown, not hidden. §4.4's whole posture is that
          the absence of backups must never render like ordinary green. */}
      {schedule && !schedule.enabled && (
        <Hint warn style={{ marginBottom: 12 }}>
          Scheduled backups are turned off. Nothing will run on its own until you choose a cadence
          above.
        </Hint>
      )}

      {!hasTarget && (
        <Hint warn style={{ marginBottom: 12 }}>
          No disk is claimed, so there is nowhere to write. Until one is, nothing on this cluster is
          backed up anywhere.
        </Hint>
      )}

      {runs.length === 0 ? (
        <Hint>No backup has run yet.</Hint>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['STATUS', 'GENERATION', 'SCOPE', 'SIZE', 'RETENTION', 'WHEN'].map((c) => (
                <th key={c} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <RunRow key={r.jobId} run={r} />
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

// LastSuccess answers "when did a backup last actually work?" — never "when did
// one last run". A failed run must not be able to read as reassurance.
function LastSuccess({ last, hasTarget }: { last: BackupRun | null; hasTarget: boolean }) {
  if (!last || !last.finishedAt) {
    return (
      <span style={{ color: hasTarget ? WARN : DIM, fontSize: 11 }}>
        No backup has ever completed on this installation.
      </span>
    );
  }
  return (
    <span style={{ color: DIM, fontSize: 11 }}>
      Last successful backup <span style={{ color: OK_GREEN }}>{timeAgo(last.finishedAt)}</span>
      {last.generationId && (
        <span style={{ fontFamily: MONO, fontSize: 9, marginLeft: 8 }}>{last.generationId}</span>
      )}
    </span>
  );
}

function RunRow({ run }: { run: BackupRun }) {
  const color = run.status === 'succeeded' ? OK_GREEN : run.status === 'failed' ? DANGER : WARN;
  return (
    <tr>
      <td style={tdStyle}>
        <Badge color={color}>{run.status.toUpperCase()}</Badge>
        {run.reason && <span style={{ color: DIM, fontSize: 9, marginLeft: 8 }}>· {run.reason}</span>}
      </td>
      <td style={{ ...tdStyle, color: FG, wordBreak: 'break-all', fontFamily: MONO, fontSize: 10 }}>
        {run.generationId || '—'}
        {run.error && (
          <div style={{ color: DANGER, fontSize: 9, marginTop: 3, lineHeight: 1.5, fontFamily: 'inherit' }}>
            {run.error}
          </div>
        )}
      </td>
      <td style={tdStyle}>
        {/* Per row, not only in the banner: a row scanned on its own must still
            say what the archive it names contains. */}
        <span
          style={{ color: run.scope === 'full' ? OK_GREEN : WARN, fontSize: 10 }}
          title={appVolumeSummary(run.appVolumesCaptured)}
        >
          {run.scope ?? '—'}
        </span>
      </td>
      <td style={{ ...tdStyle, color: DIM }}>{run.sizeBytes ? formatDiskSize(run.sizeBytes) : '—'}</td>
      <td style={{ ...tdStyle, color: DIM }}>
        {run.status === 'succeeded'
          ? `${run.generationsKept ?? 0} kept${run.generationsPruned ? ` · ${run.generationsPruned} pruned` : ''}`
          : '—'}
      </td>
      <td style={{ ...tdStyle, color: DIM }}>
        {run.finishedAt ? timeAgo(run.finishedAt) : `started ${timeAgo(run.startedAt)}`}
      </td>
    </tr>
  );
}
