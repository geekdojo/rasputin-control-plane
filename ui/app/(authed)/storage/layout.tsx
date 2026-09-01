'use client';

// Storage — the nav item design/storage.md §4.8 lights up.
//
// "UI placement: a Backups section under Storage, not Settings. The sidebar
// already carries a Storage nav item, present but disabled pending its
// subsystem; Settings holds operator preferences. Target selection is the work
// that lights Storage up."
//
// One tab today, and the tab strip is here rather than deferred because
// Storage is explicitly a section with more coming — §1's Node X data-disk
// mount contract is the same machinery on the same hardware, and §4.8 says to
// build one mount primitive both consume.

import { Database } from 'lucide-react';
import { PageHeader, PageShell, PageTabs, type PageTab } from '../../../components/kit';

const TABS: PageTab[] = [{ label: 'BACKUPS', href: '/storage' }];

export default function StorageLayout({ children }: { children: React.ReactNode }) {
  return (
    <PageShell>
      <PageHeader icon={Database} title="STORAGE" />
      <PageTabs tabs={TABS} />
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>{children}</div>
    </PageShell>
  );
}
