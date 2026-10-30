'use client';

// The owner-supplied secret fields (geekdojo/geekdojo-brain#781): one
// write-only row per secret the app's tile declares, marked SET or NOT SET.
// The drafts live in useOperatorSecrets so the action button belongs to the
// caller — SAVE in the Apps drawer, DEPLOY NOW in the install footer. Every
// decision is in lib/operator-secrets.ts; this file is rendering and wiring.

import { useCallback, useEffect, useState } from 'react';
import { listAppSecrets } from '../lib/api';
import { draftsAfterSave, listFailureText, pendingWrites, secretFieldView, type SaveResult, type SecretWrite } from '../lib/operator-secrets';
import type { OperatorSecretStatus } from '../lib/types';
import { Badge, DIM, FG, Hint, Input } from './kit';
import { ACCENT, MONO } from './ui-theme';

export interface OperatorSecrets {
  statuses: OperatorSecretStatus[];
  listError: string | null;
  drafts: Record<string, string>;
  setDraft: (name: string, value: string) => void;
  writes: SecretWrite[];
  /** Clears the saved drafts, keeps the unsaved ones, and re-reads the markers from the api. */
  afterSave: (r: SaveResult) => void;
}

export function useOperatorSecrets(appId: string): OperatorSecrets {
  const [statuses, setStatuses] = useState<OperatorSecretStatus[]>([]);
  const [listError, setListError] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});

  const reload = useCallback(() => {
    listAppSecrets(appId)
      .then((s) => {
        setStatuses(s);
        setListError(null);
      })
      .catch((e) => setListError(listFailureText(e)));
  }, [appId]);

  useEffect(() => {
    reload();
  }, [reload]);

  return {
    statuses,
    listError,
    drafts,
    setDraft: (name, value) => setDrafts((d) => ({ ...d, [name]: value })),
    writes: pendingWrites(statuses, drafts),
    afterSave: (r) => {
      setDrafts((d) => draftsAfterSave(d, r));
      reload();
    },
  };
}

export function OperatorSecretFields({ secrets, disabled }: { secrets: OperatorSecrets; disabled?: boolean }) {
  if (secrets.listError) return <Hint warn>{secrets.listError}</Hint>;
  if (secrets.statuses.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {secrets.statuses.map((s) => {
        const view = secretFieldView(s);
        const id = `operator-secret-${s.name}`;
        return (
          <div key={s.name}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
              <label htmlFor={id} style={{ color: FG, fontSize: 10, fontFamily: MONO }}>
                {s.label}
              </label>
              <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>{s.name}</span>
              <Badge color={s.set ? ACCENT : view.need === 'required' ? '#facc15' : DIM}>{view.marker}</Badge>
              <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>{view.need}</span>
            </div>
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              value={secrets.drafts[s.name] ?? ''}
              onChange={(e) => secrets.setDraft(s.name, e.target.value)}
              placeholder={view.placeholder}
              disabled={disabled}
              style={{ display: 'block', width: '100%' }}
            />
          </div>
        );
      })}
    </div>
  );
}
