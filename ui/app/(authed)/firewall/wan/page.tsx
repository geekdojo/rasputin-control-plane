'use client';

import { Hint, SectionLabel } from '../../../../components/kit';

export default function WanPage() {
  return (
    <>
      <SectionLabel>WAN</SectionLabel>
      <Hint>
        WAN interface config (DHCP / static / PPPoE) is wired in via the setup wizard today.
        A dedicated editor for changing it post-setup lands once a design partner asks for it.
      </Hint>
    </>
  );
}
