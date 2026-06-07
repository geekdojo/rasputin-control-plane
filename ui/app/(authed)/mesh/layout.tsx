'use client';

import { GitBranch } from 'lucide-react';
import { useEffect, useState } from 'react';
import { applyMesh, getMeshState, openMeshWS, reconcileMesh } from '../../../lib/api';
import type { MeshStateEnvelope } from '../../../lib/types';
import {
  Badge,
  Btn,
  DIM,
  FG,
  HAIR,
  Hint,
  PageHeader,
  PageShell,
  PageTabs,
  PANEL,
  Tok,
  type PageTab,
} from '../../../components/kit';
import { MONO } from '../../../components/ui-theme';

const TABS: PageTab[] = [
  { label: 'OVERVIEW', href: '/mesh' },
  { label: 'DEVICES', href: '/mesh/devices' },
  { label: 'KEYS', href: '/mesh/keys' },
  { label: 'ROUTES', href: '/mesh/routes' },
  { label: 'ADVANCED', href: '/mesh/advanced' },
];

export default function MeshLayout({ children }: { children: React.ReactNode }) {
  const [env, setEnv] = useState<MeshStateEnvelope | null>(null);
  const [busy, setBusy] = useState<'apply' | 'reconcile' | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const close = openMeshWS(refresh);
    return close;
  }, []);

  function refresh() {
    getMeshState().then(setEnv).catch((e) => setErr(String(e)));
  }

  async function act(which: 'apply' | 'reconcile') {
    setBusy(which);
    setErr(null);
    try {
      await (which === 'apply' ? applyMesh() : reconcileMesh());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  const drift = env?.state.drift ?? false;
  const syncColor = drift ? '#facc15' : env?.state.lastApplied ? '#4ade80' : DIM;
  const syncLabel = drift ? 'DRIFT' : env?.state.lastApplied ? 'IN SYNC' : 'UNSTARTED';

  return (
    <PageShell>
      <PageHeader
        icon={GitBranch}
        title="MESH"
        right={
          env ? (
            <>
              <Btn variant="primary" small disabled={busy !== null} onClick={() => act('apply')}>
                {busy === 'apply' ? 'APPLYING…' : 'APPLY'}
              </Btn>
              <Btn small disabled={busy !== null} onClick={() => act('reconcile')}>
                {busy === 'reconcile' ? 'RECONCILING…' : 'RECONCILE'}
              </Btn>
            </>
          ) : undefined
        }
      />
      {env && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 14,
            flexWrap: 'wrap',
            padding: '10px 20px',
            borderBottom: `1px solid ${HAIR}`,
            flexShrink: 0,
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '6px 10px',
              background: PANEL,
              border: `1px solid ${HAIR}`,
            }}
          >
            <span style={{ color: FG, fontSize: 10, fontFamily: MONO }}>tailnet</span>
            <Badge color={syncColor}>{syncLabel}</Badge>
            <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
              {env.state.lastApplied
                ? `applied ${new Date(env.state.lastApplied).toLocaleTimeString()}`
                : 'never applied'}
            </span>
          </div>
          <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
            login server: <Tok>{env.loginServer}</Tok> · user: <Tok>{env.defaultUser}</Tok> · backend:{' '}
            <Tok>{env.backend}</Tok>
          </span>
          {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
        </div>
      )}
      {env?.backend === 'mock' && (
        <div
          style={{
            padding: '10px 20px',
            borderBottom: `1px solid ${HAIR}`,
            flexShrink: 0,
          }}
        >
          <Hint warn>
            ⚠ Headscale is in mock mode (file-backed). Real Headscale wiring lands when the controlplane node has
            Docker. See wiki <Tok>design/control-plane/mesh.md §2</Tok>.
          </Hint>
        </div>
      )}
      <PageTabs tabs={TABS} />
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>{children}</div>
    </PageShell>
  );
}
