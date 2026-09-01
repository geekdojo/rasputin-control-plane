'use client';

// Storage → Backups — design/storage.md §4.8's target picker.
//
// Two lists, and the order is the operator's question order: "what is my backup
// target?" then "what could it be?".
//
// The candidate list renders PROTECTED DISKS, disabled, with the reason the api
// gave. That is a requirement, not a courtesy: the operator who plugged in one
// disk and sees two should be told which one is the boot medium and why. A list
// with a silent hole in it makes the machine's own boot disk look like it does
// not exist, and the next thing that operator does is go looking for it.

import { HardDrive, Lock, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { listBackupCandidates, listBackupTargets, listNodes } from '../../../lib/api';
import { timeAgo } from '../../../lib/time';
import type { BackupCandidate, BackupTarget, Node } from '../../../lib/types';
import { ClaimTargetDrawer } from '../../../components/storage/ClaimTargetDrawer';
import {
  diskName,
  disposition,
  formatDiskSize,
  partitionLine,
  partitionSummary,
  transportLabel,
} from '../../../components/storage/format';
import {
  Badge,
  Btn,
  DIM,
  FG,
  HAIR,
  HAIR_SOFT,
  Hint,
  SectionLabel,
  Select,
  Tok,
  srOnly,
  tdStyle,
  thStyle,
} from '../../../components/kit';
import { ACCENT, MONO } from '../../../components/ui-theme';

const DANGER = '#f87171';
const WARN = '#facc15';
const OK_GREEN = '#4ade80';

export default function BackupsPage() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [nodeId, setNodeId] = useState<string>('');
  const [candidates, setCandidates] = useState<BackupCandidate[] | null>(null);
  const [backend, setBackend] = useState<string>('');
  const [scannedAt, setScannedAt] = useState<string>('');
  const [targets, setTargets] = useState<BackupTarget[]>([]);
  const [candidateErr, setCandidateErr] = useState<string | null>(null);
  const [targetErr, setTargetErr] = useState<string | null>(null);
  const [picked, setPicked] = useState<BackupCandidate | null>(null);

  // The backup disk is almost always on the controlplane — that is the machine
  // with the spare NVMe slot and the USB ports someone can reach. Default there
  // and let the operator pick another node rather than making them choose
  // before they have seen anything.
  useEffect(() => {
    listNodes()
      .then((ns) => {
        setNodes(ns);
        const cp = ns.find((n) => n.role === 'controlplane') ?? ns[0];
        if (cp) setNodeId(cp.id);
      })
      .catch((e) => setCandidateErr(String(e)));
  }, []);

  const refreshTargets = useCallback(() => {
    listBackupTargets()
      .then((t) => {
        setTargets(t);
        setTargetErr(null);
      })
      .catch((e) => setTargetErr(String(e)));
  }, []);

  // Every setState here lands in a promise callback, never in the body. That
  // is what lets the mount/node-change effect below call it: a setState run
  // synchronously from an effect is a cascading render, and the linter is
  // right to refuse it. "Scanning" is therefore a DERIVED state — candidates
  // null with no error — and the two places that start a scan clear the list
  // first, from an event handler where clearing it is free.
  const scan = useCallback((id: string) => {
    if (!id) return;
    listBackupCandidates(id)
      .then((r) => {
        setCandidates(r.candidates ?? []);
        setBackend(r.backend);
        setScannedAt(r.ts);
        setCandidateErr(null);
      })
      .catch((e) => {
        setCandidates(null);
        setCandidateErr(String(e));
      });
  }, []);

  useEffect(() => {
    refreshTargets();
  }, [refreshTargets]);

  useEffect(() => {
    scan(nodeId);
  }, [nodeId, scan]);

  const claimed = targets.find((t) => t.status === 'claimed');
  const scanning = candidates === null && candidateErr === null;

  return (
    <>
      <SectionLabel>BACKUP TARGET</SectionLabel>
      {targetErr ? (
        <Hint warn style={{ marginBottom: 14 }}>{targetErr}</Hint>
      ) : targets.length === 0 ? (
        <Hint style={{ marginBottom: 14 }}>
          No disk has been claimed yet. Pick one below — Rasputin formats it once, now, and never
          again on a later backup run.
        </Hint>
      ) : (
        <TargetTable targets={targets} />
      )}

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          margin: '22px 0 10px',
          paddingBottom: 6,
          borderBottom: `1px solid ${HAIR_SOFT}`,
          flexWrap: 'wrap',
        }}
      >
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em' }}>
          DISKS ON
        </span>
        <label htmlFor="storage-node" style={{ display: 'inline-flex' }}>
          <span style={srOnly}>Node to scan for candidate disks</span>
          <Select
            id="storage-node"
            value={nodeId}
            onChange={(e) => {
              setCandidates(null);
              setCandidateErr(null);
              setNodeId(e.target.value);
            }}
            style={{ fontSize: 10 }}
          >
            {nodes.length === 0 && <option value="">loading…</option>}
            {nodes.map((n) => (
              <option key={n.id} value={n.id}>
                {n.hostname} ({n.role})
              </option>
            ))}
          </Select>
        </label>
        <Btn
          small
          disabled={scanning || !nodeId}
          onClick={() => {
            setCandidates(null);
            setCandidateErr(null);
            scan(nodeId);
          }}
        >
          <RefreshCw size={10} /> {scanning ? 'SCANNING…' : 'RESCAN'}
        </Btn>
        {scannedAt && (
          <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
            scanned {timeAgo(scannedAt)}
            {backend ? ` · ${backend} backend` : ''}
          </span>
        )}
      </div>

      {candidateErr && (
        <Hint warn style={{ marginBottom: 12 }}>{candidateErr}</Hint>
      )}

      {candidates && candidates.length === 0 && !candidateErr && (
        <Hint>No disks reported on this node.</Hint>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {(candidates ?? []).map((c) => (
          <CandidateRow key={c.fingerprint || c.devicePath} candidate={c} onPick={() => setPicked(c)} />
        ))}
      </div>

      {picked && nodeId && (
        <ClaimTargetDrawer
          candidate={picked}
          nodeId={nodeId}
          existingTarget={claimed}
          onClose={() => {
            setPicked(null);
            // The picker's fingerprints are stale the moment a claim runs — the
            // format replaces the partition table the fingerprint hashes. Re-scan
            // so a second claim is not offered against a disk as it used to be.
            refreshTargets();
            if (nodeId) scan(nodeId);
          }}
          onSubmitted={refreshTargets}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------

function TargetTable({ targets }: { targets: BackupTarget[] }) {
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 4 }}>
      <thead>
        <tr>
          {['STATUS', 'LABEL', 'PARTITION UUID', 'SIZE', 'ENCRYPTION', 'WHEN'].map((c) => (
            <th key={c} style={thStyle}>
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {targets.map((t) => (
          <tr key={t.jobId}>
            <td style={tdStyle}>
              <StatusBadge target={t} />
            </td>
            <td style={{ ...tdStyle, color: FG }}>
              {t.label || '—'}
              {t.adopted && <span style={{ color: DIM, fontSize: 9, marginLeft: 8 }}>· adopted</span>}
              {/* Rows are never deleted, so this is the durable answer to "what
                  happened to the archive that used to be on that disk". */}
              {t.wiped && <span style={{ color: DANGER, fontSize: 9, marginLeft: 8 }}>· wiped a set</span>}
              {t.error && (
                <div style={{ color: DANGER, fontSize: 9, marginTop: 3, lineHeight: 1.5 }}>{t.error}</div>
              )}
            </td>
            <td style={{ ...tdStyle, color: DIM, wordBreak: 'break-all' }}>{t.partUuid || '—'}</td>
            <td style={{ ...tdStyle, color: DIM }}>{t.sizeBytes ? formatDiskSize(t.sizeBytes) : '—'}</td>
            <td style={tdStyle}>
              {t.hasWrappedKeys ? (
                <span style={{ color: OK_GREEN }} title={t.keyAlg || undefined}>
                  configured{t.keyId ? ` · ${t.keyId}` : ''}
                </span>
              ) : (
                <span style={{ color: DIM }}>not configured</span>
              )}
            </td>
            <td style={{ ...tdStyle, color: DIM }}>
              {t.claimedAt ? timeAgo(t.claimedAt) : `started ${timeAgo(t.createdAt)}`}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StatusBadge({ target }: { target: BackupTarget }) {
  const map: Record<BackupTarget['status'], { color: string; title: string }> = {
    claimed: { color: OK_GREEN, title: 'The cluster’s backup target' },
    pending: { color: ACCENT, title: 'The claim saga is still running' },
    replaced: {
      color: WARN,
      title: 'Superseded by a later claim. Kept because this disk may still hold the only copy of an archive',
    },
    failed: { color: DANGER, title: 'The claim did not reach persist_target' },
  };
  const m = map[target.status];
  return (
    <Badge color={m.color} title={m.title}>
      {target.status.toUpperCase()}
    </Badge>
  );
}

// ---------------------------------------------------------------------------

function CandidateRow({ candidate, onPick }: { candidate: BackupCandidate; onPick: () => void }) {
  const disp = disposition(candidate);
  const isProtected = disp === 'protected';
  const parts = candidate.partitions ?? [];

  return (
    <div
      style={{
        border: `1px solid ${isProtected ? HAIR_SOFT : HAIR}`,
        padding: '12px 14px',
        display: 'flex',
        gap: 14,
        alignItems: 'flex-start',
        opacity: isProtected ? 0.72 : 1,
      }}
    >
      <div style={{ paddingTop: 2 }}>
        {isProtected ? <Lock size={14} color={WARN} /> : <HardDrive size={14} color={ACCENT} />}
      </div>

      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ color: FG, fontSize: 11, fontFamily: MONO }}>{diskName(candidate)}</span>
          <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>
            {formatDiskSize(candidate.sizeBytes)} · {transportLabel(candidate.transport)}
            {candidate.removable ? ' · removable' : ''} · {candidate.devicePath}
          </span>
          {isProtected && <Badge color={WARN}>BOOT MEDIUM</Badge>}
          {disp === 'adopt' && <Badge color={OK_GREEN}>RASPUTIN BACKUP SET</Badge>}
          {disp === 'unreadable' && <Badge color={WARN}>MARKER UNREADABLE</Badge>}
          {candidate.identityWeak && !isProtected && (
            <Badge color={WARN} title="No WWN or serial reported — identified by model, size and partition table alone">
              WEAK IDENTITY
            </Badge>
          )}
        </div>

        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
          {partitionSummary(parts)}
        </span>
        {parts.length > 0 && (
          <ul style={{ margin: 0, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {parts.map((p) => (
              <li key={p.devicePath} style={{ color: DIM, fontSize: 9, fontFamily: MONO, lineHeight: 1.6 }}>
                {partitionLine(p)}
              </li>
            ))}
          </ul>
        )}

        {/* The whole point of returning protected disks rather than filtering
            them: show the operator WHY this one is ineligible. */}
        {isProtected && (
          <Hint warn>
            {candidate.protectedReason ||
              'Holds the currently-mounted boot or persistent partitions.'}{' '}
            Rasputin will not format it, and re-checks that immediately before any format runs.
          </Hint>
        )}

        {disp === 'adopt' && candidate.backupSet && (
          <Hint>
            {candidate.backupSet.generations
              ? `${candidate.backupSet.generations} retained generation${candidate.backupSet.generations === 1 ? '' : 's'}`
              : 'a Rasputin backup set'}
            {candidate.backupSet.clusterId ? ` from cluster ${candidate.backupSet.clusterId}` : ''}
            {candidate.backupSet.label ? ` · “${candidate.backupSet.label}”` : ''}. Adopt it to keep
            it; this is the disk a restore is plugged in from.
          </Hint>
        )}

        {disp === 'unreadable' && (
          <Hint warn>
            The disk announces a backup set whose marker (<Tok>.rasputin-backup-set.json</Tok>)
            could not be read, so there is no partition UUID to adopt it by.
          </Hint>
        )}
      </div>

      <div style={{ paddingTop: 2 }}>
        {isProtected ? (
          <Badge color={DIM} title={candidate.protectedReason}>
            NOT ELIGIBLE
          </Badge>
        ) : (
          <Btn
            variant={disp === 'adopt' ? 'default' : 'primary'}
            small
            onClick={onPick}
            aria-label={`${disp === 'format' ? 'Claim' : 'Review'} ${diskName(candidate)} at ${candidate.devicePath}`}
          >
            {disp === 'format' ? 'CLAIM THIS DISK' : 'REVIEW…'}
          </Btn>
        )}
      </div>
    </div>
  );
}
