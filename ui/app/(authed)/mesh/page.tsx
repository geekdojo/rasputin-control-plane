'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { listMeshDevices, listMeshKeys, listMeshRoutes } from '../../../lib/api';
import type { MeshDevice, MeshIntent } from '../../../lib/types';
import { DIM, FG, HAIR, Hint, PANEL, SectionLabel } from '../../../components/kit';
import { ACCENT, MONO } from '../../../components/ui-theme';

export default function MeshOverview() {
  const [devices, setDevices] = useState<MeshDevice[]>([]);
  const [keys, setKeys] = useState<MeshIntent[]>([]);
  const [routes, setRoutes] = useState<MeshIntent[]>([]);

  useEffect(() => {
    listMeshDevices().then(setDevices).catch(() => {});
    listMeshKeys().then(setKeys).catch(() => {});
    listMeshRoutes().then(setRoutes).catch(() => {});
  }, []);

  const rasputinNodes = devices.filter((d) => d.kind === 'rasputin').length;
  const userDevices = devices.filter((d) => d.kind === 'user').length;

  return (
    <>
      <SectionLabel>WHAT&apos;S MANAGED</SectionLabel>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 24 }}>
        <CountTile label="RASPUTIN NODES" count={rasputinNodes} href="/mesh/devices" />
        <CountTile label="USER DEVICES" count={userDevices} href="/mesh/devices" />
        <CountTile label="PRE-AUTH KEYS" count={keys.length} href="/mesh/keys" />
        <CountTile label="SUBNET ROUTES" count={routes.length} href="/mesh/routes" />
      </div>

      <SectionLabel>NEXT</SectionLabel>
      <Hint>
        Add your laptop or phone in{' '}
        <Link href="/mesh/keys" style={{ color: ACCENT, textDecoration: 'none' }}>
          KEYS
        </Link>{' '}
        — a single-use pre-auth key bootstraps the Tailscale client. Anything Rasputin doesn&apos;t model
        (ACL HuJSON, exit nodes, DERP map) lives in Headplane — see{' '}
        <Link href="/mesh/advanced" style={{ color: ACCENT, textDecoration: 'none' }}>
          ADVANCED
        </Link>
        .
      </Hint>
    </>
  );
}

function CountTile({ label, count, href }: { label: string; count: number; href: string }) {
  return (
    <Link
      href={href}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        padding: '12px 16px',
        minWidth: 140,
        background: PANEL,
        border: `1px solid ${HAIR}`,
        textDecoration: 'none',
      }}
    >
      <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em' }}>{label}</span>
      <span style={{ color: FG, fontSize: 22, fontFamily: MONO }}>{count}</span>
    </Link>
  );
}
