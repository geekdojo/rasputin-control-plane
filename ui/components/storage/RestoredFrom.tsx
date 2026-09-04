'use client';

// Storage → Backups → "this cluster was restored from generation X on date
// Y" (design/storage.md §4.5, #291).
//
// Rendered above the runs panel whenever the restore ledger has an entry,
// because the single most useful fact about a restored cluster is that it
// IS one — and the second most useful is what the restore did not put back.
// The app volumes the generation held are named here, by volume, exactly as
// the restore report names them; this component adds no words of its own to
// the gap.

import { RotateCcw } from 'lucide-react';
import { useEffect, useState } from 'react';
import { listRestores } from '../../lib/api';
import { timeAgo } from '../../lib/time';
import type { RestoreReport } from '../../lib/types';
import { Badge, DIM, FG, HAIR_SOFT, Tok } from '../kit';
import { MONO } from '../ui-theme';

const WARN = '#facc15';
const OK_GREEN = '#4ade80';

export function RestoredFrom() {
  const [latest, setLatest] = useState<RestoreReport | null>(null);
  useEffect(() => {
    listRestores()
      .then((rows) => setLatest(rows[0] ?? null))
      .catch(() => setLatest(null));
  }, []);
  if (!latest) return null;
  const when = latest.appliedAt ?? latest.recordedAt ?? latest.preparedAt;
  if (latest.phase === 'app-volumes') return <AppDataRestored report={latest} when={when} />;
  return (
    <div
      style={{
        border: `1px solid ${HAIR_SOFT}`,
        padding: '10px 12px',
        marginBottom: 14,
        fontFamily: MONO,
        fontSize: 11,
        lineHeight: 1.6,
        color: FG,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <RotateCcw size={12} />
        <span>
          This cluster was restored from generation <Tok>{latest.generationId}</Tok>{' '}
          <span style={{ color: DIM }} title={when}>
            {timeAgo(when)}
          </span>
        </span>
        <Badge color={OK_GREEN}>{latest.phase}</Badge>
        {latest.keyId && <Badge>key {latest.keyId}</Badge>}
        {latest.sourceLabel && <Badge>{latest.sourceLabel}</Badge>}
      </div>
      <div style={{ color: DIM }}>
        {latest.restored.length} identity file(s) put back and verified against the manifest.
      </div>
      <div style={{ color: WARN }}>
        {latest.appVolumesPresent.length > 0
          ? `App volumes present in that generation and NOT restored: ${latest.appVolumesPresent.map((v) => v.name).join(', ')}. They are still sealed on the backup disk.`
          : 'That generation held no app volumes.'}
      </div>
    </div>
  );
}

// A phase-2 record (#291): one app's data put back from a generation. The
// volumes are named as the record names them — restored, or not, with why.
function AppDataRestored({ report, when }: { report: RestoreReport; when: string }) {
  const vols = report.appVolumes ?? [];
  const restored = vols.filter((v) => v.restored);
  const failed = vols.filter((v) => v.failed);
  const skipped = vols.filter((v) => !v.restored && !v.failed);
  return (
    <div
      style={{
        border: `1px solid ${HAIR_SOFT}`,
        padding: '10px 12px',
        marginBottom: 14,
        fontFamily: MONO,
        fontSize: 11,
        lineHeight: 1.6,
        color: FG,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <RotateCcw size={12} />
        <span>
          {report.appName ?? 'An app'}&apos;s data was restored from generation <Tok>{report.generationId}</Tok>{' '}
          <span style={{ color: DIM }} title={when}>
            {timeAgo(when)}
          </span>
        </span>
        <Badge color={failed.length > 0 ? WARN : OK_GREEN}>{report.phase}</Badge>
        {report.nodeId && <Badge>on {report.nodeId}</Badge>}
      </div>
      <div style={{ color: DIM }}>
        {restored.length > 0
          ? `Put back: ${restored.map((v) => v.volume).join(', ')} — the previous contents were kept beside each volume on ${report.nodeId ?? 'the node'}.`
          : 'No volume was put back.'}
      </div>
      {failed.length > 0 && (
        <div style={{ color: WARN }}>NOT restored: {failed.map((v) => `${v.volume} (${v.reason ?? 'no reason recorded'})`).join('; ')}</div>
      )}
      {skipped.length > 0 && (
        <div style={{ color: DIM }}>Skipped: {skipped.map((v) => `${v.volume} (${v.reason ?? 'by design'})`).join('; ')}</div>
      )}
    </div>
  );
}
