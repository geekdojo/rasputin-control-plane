'use client';

import { AlertTriangle, ArrowUpCircle, FileCode, RotateCcw, X } from 'lucide-react';
import { useEffect, useId, useState } from 'react';
import { getAppVolumes, putAppCompose } from '../lib/api';
import {
  DROP_SELECTION_DEFAULT,
  REVERT_PROMPT,
  UPGRADE_WARNING,
  bodyFor,
  canResubmitWithDeletions,
  canSubmitEdit,
  dropDeletionStatement,
  toggleDropSelection,
  withDeleteVolumes,
  type ComposeChangeBody,
  type ComposeChangeKind,
  type ComposeOutcome,
} from '../lib/compose-change';
import type { App, AppVolumesResponse, DroppedVolume } from '../lib/types';
import { deleteWarning } from '../lib/volumes';
import { Btn, DIM, FG, HAIR_SOFT, Textarea } from './kit';
import { ModalPortal, useModalChrome } from './modal';
import { ACCENT, MONO } from './ui-theme';
import { VolumeBackupTable, type VolumeTableRow } from './VolumeBackupTable';

// Every compose change the Apps page starts, and the refusal any of them can
// meet (geekdojo/geekdojo-brain#414):
//
//   upgrade  a catalog app to its tile's compose. The confirm shows the app's
//            volumes by name and class with each one's last capture, as
//            information, and exactly one static warning: UPGRADE_WARNING.
//   edit     a custom app's compose, edited here and redeployed in place.
//   revert   re-apply a failed app's previous compose. The confirm is one
//            static prompt, REVERT_PROMPT, and nothing else.
//
// Any of the three can come back 409 because the new compose no longer
// declares a named volume the app has on disk (#412). The modal then lists
// those volumes and lets the owner select them — nothing is selected by
// default — and resubmits the same body naming exactly them in deleteVolumes.
//
// The edited compose lives in this component's state while the modal is open
// and in the request body while it is in flight. It is never logged, never
// written to storage or the URL, and goes when the modal closes.

export type ComposeChangeResult = Extract<ComposeOutcome, { kind: 'started' | 'noop' }>;

export interface ComposeChangeModalProps {
  app: App;
  kind: ComposeChangeKind;
  /** Called once, with a job that started or a no-op, before the modal closes. */
  onFinished: (kind: ComposeChangeKind, app: App, result: ComposeChangeResult) => void;
  onClose: () => void;
}

type Refusal = { dropped: DroppedVolume[]; notDropped: string[] };

const DANGER = '#f87171';
const WARN = '#facc15';

const TITLES: Record<ComposeChangeKind, string> = {
  upgrade: 'UPGRADE APP',
  edit: 'EDIT COMPOSE',
  revert: 'REVERT APP',
};

export function ComposeChangeModal({ app, kind, onFinished, onClose }: ComposeChangeModalProps) {
  const { initialFocusRef } = useModalChrome({ open: true, onClose });
  const editorId = useId();
  const [volumes, setVolumes] = useState<AppVolumesResponse | null>(null);
  const [draft, setDraft] = useState<string>(kind === 'edit' ? app.composeYaml : '');
  // The body of the change that was refused, held only so the resubmit can
  // send the same thing again.
  const [refusedBody, setRefusedBody] = useState<ComposeChangeBody | null>(null);
  const [refusal, setRefusal] = useState<Refusal | null>(null);
  const [selected, setSelected] = useState<string[]>([...DROP_SELECTION_DEFAULT]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (kind !== 'upgrade') return;
    let cancelled = false;
    getAppVolumes(app.id)
      .then((v) => {
        if (!cancelled) setVolumes(v);
      })
      .catch((e: unknown) => {
        // The confirm still opens, saying why the facts are missing — never a
        // silent "no volumes".
        if (!cancelled) {
          setVolumes({ appId: app.id, appName: app.name, classified: false, note: `Could not read this app's volumes: ${String(e)}`, volumes: [] });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [app.id, app.name, kind]);

  async function submit(body: ComposeChangeBody) {
    setBusy(true);
    setError(null);
    let outcome: ComposeOutcome;
    try {
      outcome = await putAppCompose(app.id, body);
    } catch (e: unknown) {
      setBusy(false);
      setError(`The request did not reach the control plane: ${String(e)}`);
      return;
    }
    setBusy(false);
    switch (outcome.kind) {
      case 'started':
      case 'noop':
        onFinished(kind, app, outcome);
        onClose();
        return;
      case 'dropped':
        setRefusedBody(body);
        setRefusal({ dropped: outcome.dropped, notDropped: outcome.notDropped });
        setSelected([...DROP_SELECTION_DEFAULT]);
        return;
      case 'error':
        setError(outcome.message);
        return;
    }
  }

  function confirm() {
    let body: ComposeChangeBody;
    try {
      body = bodyFor(kind, app, draft);
    } catch (e: unknown) {
      setError(String(e instanceof Error ? e.message : e));
      return;
    }
    void submit(body);
  }

  const inDropped = refusal !== null;
  const width = kind === 'edit' && !inDropped ? 720 : 480;
  const title = inDropped ? 'VOLUMES WOULD BE ORPHANED' : `${TITLES[kind]} — ${app.name.toUpperCase()}`;
  const Icon = inDropped ? AlertTriangle : kind === 'upgrade' ? ArrowUpCircle : kind === 'edit' ? FileCode : RotateCcw;
  const iconColor = inDropped ? DANGER : kind === 'revert' ? WARN : ACCENT;

  return (
    <ModalPortal>
      <div onClick={onClose} aria-hidden style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000 }} />
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
          width,
          maxWidth: 'calc(100vw - 32px)',
          display: 'flex',
          flexDirection: 'column',
          gap: 14,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon size={14} color={iconColor} />
            <span style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.1em' }}>{title}</span>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            <X size={14} color={DIM} />
          </button>
        </div>

        <div style={{ height: 1, background: HAIR_SOFT }} />

        {inDropped ? (
          <DroppedBody app={app} refusal={refusal} selected={selected} busy={busy} onToggle={(name) => setSelected((s) => toggleDropSelection(refusal.dropped, s, name))} />
        ) : kind === 'upgrade' ? (
          <UpgradeBody app={app} volumes={volumes} />
        ) : kind === 'revert' ? (
          <p style={{ color: FG, fontSize: 11, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>{REVERT_PROMPT}</p>
        ) : (
          <div>
            <label htmlFor={editorId} style={{ display: 'block', color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em', marginBottom: 6 }}>
              COMPOSE
            </label>
            <Textarea
              id={editorId}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              disabled={busy}
              rows={22}
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              aria-label={`Compose for ${app.name}`}
              style={{ width: '100%', boxSizing: 'border-box', fontSize: 10, whiteSpace: 'pre', overflowWrap: 'normal', overflowX: 'auto' }}
            />
            <p style={{ color: DIM, fontSize: 9, fontFamily: MONO, margin: '6px 0 0', lineHeight: 1.5 }}>
              Redeploys in place on {app.targetNode}: the same app, its images pulled first, its volumes kept. The compose is not
              validated before it is sent.
            </p>
          </div>
        )}

        {error && (
          <div role="alert" style={{ color: DANGER, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, wordBreak: 'break-word' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Btn ref={initialFocusRef as React.RefObject<HTMLButtonElement | null>} onClick={onClose}>
            CANCEL
          </Btn>
          {inDropped ? (
            <Btn
              variant="danger"
              disabled={busy || !canResubmitWithDeletions(refusal.dropped, selected)}
              onClick={() => refusedBody && void submit(withDeleteVolumes(refusedBody, selected))}
            >
              {busy ? 'APPLYING…' : `DELETE ${refusal.dropped.length} VOLUME${refusal.dropped.length === 1 ? '' : 'S'} AND APPLY`}
            </Btn>
          ) : kind === 'upgrade' ? (
            <Btn variant="primary" disabled={busy || volumes === null} onClick={confirm}>
              {busy ? 'UPGRADING…' : 'UPGRADE'}
            </Btn>
          ) : kind === 'revert' ? (
            <Btn variant="primary" disabled={busy} onClick={confirm}>
              {busy ? 'REVERTING…' : 'REVERT'}
            </Btn>
          ) : (
            <Btn variant="primary" disabled={busy || !canSubmitEdit(draft)} onClick={confirm}>
              {busy ? 'REDEPLOYING…' : 'REDEPLOY'}
            </Btn>
          )}
        </div>
      </div>
    </ModalPortal>
  );
}

function UpgradeBody({ app, volumes }: { app: App; volumes: AppVolumesResponse | null }) {
  const rows: VolumeTableRow[] = volumes?.volumes ?? [];
  return (
    <>
      <p style={{ color: DIM, fontSize: 11, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
        Upgrade &quot;{app.name}&quot; in place to the compose its catalog tile carries
        {app.upgradeCatalogVersion ? ` in catalog v${app.upgradeCatalogVersion}` : ''}. It keeps its volumes. Data lives on{' '}
        {app.targetNode}.
      </p>

      <div>
        <div style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em', marginBottom: 6 }}>VOLUMES</div>
        {volumes === null && <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, margin: 0 }}>Checking backups…</p>}
        {volumes !== null && rows.length === 0 && (
          <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, margin: 0, lineHeight: 1.6 }}>{volumes.note ?? 'This app declares no data volumes.'}</p>
        )}
        {rows.length > 0 && <VolumeBackupTable volumes={rows} tone="info" />}
        {rows.length > 0 && volumes?.note && <p style={{ color: DIM, fontSize: 9, fontFamily: MONO, margin: '6px 0 0', lineHeight: 1.5 }}>{volumes.note}</p>}
        {volumes?.backupNote && <p style={{ color: DIM, fontSize: 9, fontFamily: MONO, margin: '6px 0 0', lineHeight: 1.5 }}>{volumes.backupNote}</p>}
      </div>

      <div
        style={{
          color: WARN,
          fontSize: 10,
          fontFamily: MONO,
          lineHeight: 1.6,
          padding: '8px 10px',
          border: '1px solid rgba(250,204,21,0.45)',
          background: 'rgba(250,204,21,0.07)',
        }}
      >
        {UPGRADE_WARNING}
      </div>
    </>
  );
}

function DroppedBody({
  app,
  refusal,
  selected,
  busy,
  onToggle,
}: {
  app: App;
  refusal: Refusal;
  selected: string[];
  busy: boolean;
  onToggle: (name: string) => void;
}) {
  const n = refusal.dropped.length;
  const rows: VolumeTableRow[] = refusal.dropped.map((v) => ({
    name: v.volume || v.name,
    dockerName: v.name,
    backup: v.backup ?? '',
    lastCaptured: v.lastCaptured,
  }));
  const statement = dropDeletionStatement(refusal.dropped, selected);
  const unbacked = deleteWarning(
    rows.filter((r) => selected.includes(r.dockerName!)),
    selected.length > 0,
  );
  const partial = selected.length > 0 && !canResubmitWithDeletions(refusal.dropped, selected);

  return (
    <>
      <p style={{ color: FG, fontSize: 11, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
        Nothing was changed. The new compose for &quot;{app.name}&quot; no longer declares {n === 1 ? 'this volume' : 'these volumes'}, which{' '}
        {n === 1 ? 'holds' : 'hold'} data on {app.targetNode}. Applying it would leave that data where the app can no longer reach it.
      </p>
      <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
        To apply the change anyway, select {n === 1 ? 'the volume' : 'every listed volume'} for deletion. Otherwise cancel: nothing is
        deleted and the app&apos;s compose stays as it is.
      </p>

      <div>
        <VolumeBackupTable volumes={rows} tone="warn" selection={{ selected, onToggle, disabled: busy }} />
        {refusal.notDropped.length > 0 && (
          <p style={{ color: DIM, fontSize: 9, fontFamily: MONO, margin: '6px 0 0', lineHeight: 1.5 }}>
            Not dropped by this change, so not deletable here: {refusal.notDropped.join(', ')}.
          </p>
        )}
      </div>

      {partial && (
        <p style={{ color: WARN, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
          Select every listed volume to apply the change. It can only go ahead when it deletes all of the volumes it drops.
        </p>
      )}

      {statement && (
        <div
          role="alert"
          style={{
            color: DANGER,
            fontSize: 10,
            fontFamily: MONO,
            lineHeight: 1.6,
            padding: '8px 10px',
            border: '1px solid rgba(248,113,113,0.5)',
            background: 'rgba(248,113,113,0.08)',
          }}
        >
          {statement}
          {unbacked && <> {unbacked}</>}
        </div>
      )}
    </>
  );
}
