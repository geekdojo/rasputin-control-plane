'use client';

import { Hint, SectionLabel } from '../../../../components/kit';

export default function RulesPage() {
  return (
    <>
      <SectionLabel>RULES</SectionLabel>
      <Hint>
        Zone-based accept/drop rules land in the next PR. The intent kind is{' '}
        <code>firewall_rule</code>; same compile → apply → reconcile loop as port forwards.
      </Hint>
    </>
  );
}
