'use client';

import Link from 'next/link';
import { Hint, SectionLabel } from '../../../../components/kit';
import { ACCENT } from '../../../../components/ui-theme';

export default function WireGuardPage() {
  return (
    <>
      <SectionLabel>WIREGUARD</SectionLabel>
      <Hint>
        WireGuard peer management for direct (non-tailnet) clients lands after the Headscale mesh
        story settles — see open question F-5 in the firewall wiki. For mesh tailnet devices use{' '}
        <Link href="/mesh" style={{ color: ACCENT, textDecoration: 'none' }}>
          MESH
        </Link>{' '}
        instead.
      </Hint>
    </>
  );
}
