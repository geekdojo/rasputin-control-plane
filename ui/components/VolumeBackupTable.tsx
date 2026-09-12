'use client';

import { Badge, DIM, FG } from './kit';
import { MONO } from './ui-theme';
import { describeCapture, formatBytes, type PromptVolume } from '../lib/volumes';

// The volumes-by-name-and-class table with each volume's last capture — #399's
// presentation, shared by every prompt that has to say what data an act
// touches: uninstall, reclaim, the upgrade confirm, and the dropped-volume
// refusal (geekdojo/geekdojo-brain#414).
//
// `tone` is the one thing the prompts disagree on. Uninstall and reclaim are
// about destroying data, so a volume never backed up reads "never" in red. The
// upgrade confirm shows the same facts as information (#181: informed, not
// gated), so it colours neither the class nor "never" as a warning.

export interface VolumeTableRow extends PromptVolume {
  dockerName?: string;
  sizeBytes?: number;
}

export function classColor(backup: string): string {
  switch (backup) {
    case 'critical':
      return '#f87171';
    case 'state':
      return '#facc15';
    case 'cache':
    case 'bulk':
      return DIM;
    default:
      return '#fb923c'; // unclassified — not knowing is worth a colour
  }
}

export interface VolumeBackupTableProps {
  volumes: VolumeTableRow[];
  tone: 'warn' | 'info';
  /**
   * When set, each row carries a checkbox keyed by its dockerName (falling
   * back to name), labelled "Delete <volume>". Used by the dropped-volume
   * refusal, where the owner selects exactly which volumes go.
   */
  selection?: {
    selected: readonly string[];
    onToggle: (key: string) => void;
    disabled?: boolean;
  };
}

export function VolumeBackupTable({ volumes, tone, selection }: VolumeBackupTableProps) {
  const headers = selection ? ['DELETE', 'VOLUME', 'CLASS', 'LAST BACKUP'] : ['VOLUME', 'CLASS', 'LAST BACKUP'];
  return (
    <table aria-label="Volumes" style={{ width: '100%', borderCollapse: 'collapse', fontFamily: MONO, fontSize: 10 }}>
      <thead>
        <tr>
          {headers.map((h) => (
            <th key={h} scope="col" style={{ textAlign: 'left', color: DIM, fontWeight: 400, fontSize: 9, letterSpacing: '0.1em', padding: '2px 6px 4px 0' }}>
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {volumes.map((v) => {
          const key = v.dockerName ?? v.name;
          const checked = selection ? selection.selected.includes(key) : false;
          return (
            <tr key={key}>
              {selection && (
                <td style={{ padding: '3px 6px 3px 0', verticalAlign: 'top', width: 1 }}>
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={selection.disabled}
                    onChange={() => selection.onToggle(key)}
                    aria-label={`Delete ${v.name}`}
                  />
                </td>
              )}
              <td style={{ color: FG, padding: '3px 6px 3px 0', verticalAlign: 'top' }} title={v.dockerName}>
                {v.name}
                {typeof v.sizeBytes === 'number' && <span style={{ color: DIM, marginLeft: 6 }}>{formatBytes(v.sizeBytes)}</span>}
              </td>
              <td style={{ padding: '3px 6px 3px 0', verticalAlign: 'top' }}>
                <Badge color={tone === 'info' ? DIM : classColor(v.backup)}>{(v.backup || 'unclassified').toUpperCase()}</Badge>
              </td>
              <td style={{ color: v.lastCaptured || tone === 'info' ? DIM : '#f87171', padding: '3px 0', verticalAlign: 'top' }}>
                {describeCapture(v)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
