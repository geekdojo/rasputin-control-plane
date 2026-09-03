'use client';

import { AlertTriangle, X } from 'lucide-react';
import { useId, useState } from 'react';
import { ModalPortal, useModalChrome } from './modal';
import { MONO } from './ui-theme';
import { Badge, DIM, FG, HAIR_SOFT } from './kit';
import {
  DELETE_VOLUMES_DEFAULT,
  deleteWarning,
  describeCapture,
  formatBytes,
  type PromptVolume,
} from '../lib/volumes';

// The uninstall confirmation, and the reclaim confirmation, which are the same
// question asked of different volumes (geekdojo/geekdojo-brain#399).
//
//   - "Delete volumes?" is a checkbox that starts UNTICKED. Keep is the
//     default; delete is a deliberate act.
//   - Beside it, the volumes by name and class, each with when it was last
//     captured into a retained backup: "never", or the generation and its age.
//   - Ticking delete over a critical/state volume with no backup shows §4.4's
//     warning in plain words before the operator can confirm.
//
// In `reclaim` mode there is no app to remove — the volumes ARE the act — so
// the confirm button stays disabled until the box is ticked.

export interface UninstallVolumeRow extends PromptVolume {
  dockerName?: string;
  sizeBytes?: number;
}

export interface UninstallAppModalProps {
  mode: 'uninstall' | 'reclaim';
  // The app's name for the title, or the former app's name/id for orphans.
  subject: string;
  // Where the volumes live — shown so the operator knows which node's disk
  // this touches.
  nodeId?: string;
  // null while the facts are still loading; the confirm stays disabled.
  volumes: UninstallVolumeRow[] | null;
  // Why the list is empty or unclassified, when it is.
  note?: string;
  backupNote?: string;
  onConfirm: (deleteVolumes: boolean) => void;
  onCancel: () => void;
}

function classColor(backup: string): string {
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

export function UninstallAppModal({
  mode,
  subject,
  nodeId,
  volumes,
  note,
  backupNote,
  onConfirm,
  onCancel,
}: UninstallAppModalProps) {
  const [deleteVolumes, setDeleteVolumes] = useState<boolean>(DELETE_VOLUMES_DEFAULT);
  const { initialFocusRef } = useModalChrome({ open: true, onClose: onCancel });
  const checkboxId = useId();
  const loading = volumes === null;
  const warning = deleteWarning(volumes ?? [], deleteVolumes);
  const title = mode === 'uninstall' ? 'DELETE APP' : 'RECLAIM VOLUMES';
  const canConfirm = !loading && (mode === 'uninstall' || deleteVolumes);
  const confirmLabel =
    mode === 'reclaim' ? 'DELETE VOLUMES' : deleteVolumes ? 'DELETE APP + VOLUMES' : 'DELETE APP, KEEP VOLUMES';
  const hasVolumes = !!volumes && volumes.length > 0;

  return (
    <ModalPortal>
      <div onClick={onCancel} aria-hidden style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000 }} />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
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
          width: 460,
          display: 'flex',
          flexDirection: 'column',
          gap: 14,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={14} color="#f87171" />
            <span style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.1em' }}>{title}</span>
          </div>
          <button type="button" onClick={onCancel} aria-label="Close" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            <X size={14} color={DIM} />
          </button>
        </div>

        <div style={{ height: 1, background: HAIR_SOFT }} />

        <p style={{ color: DIM, fontSize: 11, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
          {mode === 'uninstall'
            ? `Stop and remove "${subject}" and its containers?`
            : `These volumes belonged to "${subject}", which is no longer installed. Nothing owns them and nothing backs them up.`}
          {nodeId && <span style={{ color: DIM }}> Data lives on {nodeId}.</span>}
        </p>

        {/* The volumes: name, class, last backup. */}
        <div>
          <div style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em', marginBottom: 6 }}>VOLUMES</div>
          {loading && <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, margin: 0 }}>Checking backups…</p>}
          {!loading && !hasVolumes && (
            <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, margin: 0, lineHeight: 1.6 }}>
              {note ?? 'This app declares no data volumes.'}
            </p>
          )}
          {hasVolumes && (
            <table aria-label="Volumes" style={{ width: '100%', borderCollapse: 'collapse', fontFamily: MONO, fontSize: 10 }}>
              <thead>
                <tr>
                  {['VOLUME', 'CLASS', 'LAST BACKUP'].map((h) => (
                    <th key={h} scope="col" style={{ textAlign: 'left', color: DIM, fontWeight: 400, fontSize: 9, letterSpacing: '0.1em', padding: '2px 6px 4px 0' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {volumes!.map((v) => (
                  <tr key={v.dockerName ?? v.name}>
                    <td style={{ color: FG, padding: '3px 6px 3px 0', verticalAlign: 'top' }} title={v.dockerName}>
                      {v.name}
                      {typeof v.sizeBytes === 'number' && <span style={{ color: DIM, marginLeft: 6 }}>{formatBytes(v.sizeBytes)}</span>}
                    </td>
                    <td style={{ padding: '3px 6px 3px 0', verticalAlign: 'top' }}>
                      <Badge color={classColor(v.backup)}>{(v.backup || 'unclassified').toUpperCase()}</Badge>
                    </td>
                    <td style={{ color: v.lastCaptured ? DIM : '#f87171', padding: '3px 0', verticalAlign: 'top' }}>
                      {describeCapture(v)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {hasVolumes && note && <p style={{ color: DIM, fontSize: 9, fontFamily: MONO, margin: '6px 0 0', lineHeight: 1.5 }}>{note}</p>}
          {!loading && backupNote && <p style={{ color: DIM, fontSize: 9, fontFamily: MONO, margin: '6px 0 0', lineHeight: 1.5 }}>{backupNote}</p>}
        </div>

        {/* The choice. Unticked by default: keep is the path of least resistance. */}
        <label htmlFor={checkboxId} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer', color: FG, fontSize: 10, fontFamily: MONO, lineHeight: 1.6 }}>
          <input
            id={checkboxId}
            type="checkbox"
            checked={deleteVolumes}
            onChange={(e) => setDeleteVolumes(e.target.checked)}
            disabled={loading}
            aria-label={mode === 'uninstall' ? 'Delete volumes' : 'Delete these volumes'}
            style={{ marginTop: 3 }}
          />
          <span>
            {mode === 'uninstall' ? 'Delete volumes?' : 'Delete these volumes'}
            <span style={{ color: DIM }}>
              {mode === 'uninstall'
                ? ' Unticked, the data stays on the node with no app owning it; it appears under Orphaned volumes on this page until reclaimed.'
                : ' This is permanent.'}
            </span>
          </span>
        </label>

        {warning && (
          <div
            role="alert"
            style={{
              color: '#f87171',
              fontSize: 10,
              fontFamily: MONO,
              lineHeight: 1.6,
              padding: '8px 10px',
              border: '1px solid rgba(248,113,113,0.5)',
              background: 'rgba(248,113,113,0.08)',
            }}
          >
            {warning}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button
            ref={initialFocusRef as React.RefObject<HTMLButtonElement | null>}
            type="button"
            onClick={onCancel}
            style={{ padding: '7px 16px', background: 'transparent', border: '1px solid rgba(var(--rasp-fg-rgb),0.18)', color: DIM, fontSize: 10, fontFamily: MONO, letterSpacing: '0.08em', cursor: 'pointer' }}
          >
            CANCEL
          </button>
          <button
            type="button"
            disabled={!canConfirm}
            onClick={() => {
              onConfirm(deleteVolumes);
              onCancel();
            }}
            style={{
              padding: '7px 16px',
              background: 'rgba(248,113,113,0.12)',
              border: '1px solid rgba(248,113,113,0.5)',
              color: canConfirm ? '#f87171' : DIM,
              fontSize: 10,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: canConfirm ? 'pointer' : 'not-allowed',
              opacity: canConfirm ? 1 : 0.6,
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </ModalPortal>
  );
}
