// Labels and colours for a node update's status, shared by the Updates page's
// History table, its live-events feed and the System updates card.
//
// fallen_back (geekdojo/geekdojo-brain#894) is an update that committed after
// which the node began reporting a different image version. It takes the same
// yellow as rolled_back: the node is not on the update, but it is running.

import { ACCENT, DIM } from '../components/ui-theme';
import type { NodeUpdate, NodeUpdateStatus } from './types';

const GREEN = '#4ade80';
const YELLOW = '#facc15';
const RED = '#f87171';

export function nodeUpdateColor(s: NodeUpdateStatus): string {
  switch (s) {
    case 'committed':
      return GREEN;
    case 'rolled_back':
    case 'fallen_back':
      return YELLOW;
    case 'failed':
      return RED;
    default:
      return ACCENT; // in_progress
  }
}

export function prettyStatus(s: NodeUpdateStatus): string {
  if (s === 'in_progress') return 'IN PROGRESS';
  if (s === 'rolled_back') return 'ROLLED BACK';
  if (s === 'fallen_back') return 'FALLEN BACK';
  return s.toUpperCase();
}

export function changeColor(change: string): string {
  if (change === 'committed') return GREEN;
  if (change === 'rolled_back' || change === 'fallen_back') return YELLOW;
  if (change === 'failed') return RED;
  if (change === 'started') return ACCENT;
  return DIM;
}

// childFellBack says whether the System updates card shows FALLEN BACK beside
// a node's SUCCEEDED: its child job's update row has since fallen back. The
// card's outcome is the cascade's stashed result and never changes after the
// run, so the History row is the only place the later fallback is recorded.
export function childFellBack(childJobId: string | undefined, history: readonly NodeUpdate[]): boolean {
  if (!childJobId) return false;
  return history.some((h) => h.jobId === childJobId && h.status === 'fallen_back');
}
