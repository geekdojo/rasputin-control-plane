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
