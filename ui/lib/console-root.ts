// The console root password's client-side rules, kept out of the components
// so they can be executed (console-root.test.ts).
//
// What it is (geekdojo/geekdojo-brain#587, decision #558): the password root
// uses at a node's physical console or its serial-over-LAN session. No image
// ships one. The operator chooses it in the first-run wizard; the api hashes
// it and a job applies the HASH to every node in inventory, the controlplane
// included. Settings can change it and re-apply it at any time.
//
// The rules below MIRROR the api's (api/internal/console/password.go) so the
// operator is told at the keystroke rather than on a round trip. The api is
// the authority — this never lets something through that it would refuse, and
// a refusal from it is still shown verbatim.

import type { ConsoleRootNode, ConsoleRootStatus } from './api';

// Mirrors console.MinPasswordLen / MaxPasswordLen.
export const MIN_CONSOLE_PASSWORD = 12;
export const MAX_CONSOLE_PASSWORD = 256;

// validateConsolePassword returns the refusal to show, or null.
//
// The character rule is about the console, not about strength: what is typed
// here has to be typable again on a serial terminal with no clipboard, so a
// control character — a stray tab, a pasted newline — is a password nobody
// can enter. Spaces inside it are fine.
export function validateConsolePassword(password: string): string | null {
  const runes = [...password];
  if (runes.length === 0) return null; // nothing typed yet: not an error
  if (runes.length < MIN_CONSOLE_PASSWORD) {
    return `At least ${MIN_CONSOLE_PASSWORD} characters (this one is ${runes.length}).`;
  }
  if (runes.length > MAX_CONSOLE_PASSWORD) {
    return `At most ${MAX_CONSOLE_PASSWORD} characters (this one is ${runes.length}).`;
  }
  if (password.trim() === '') return 'Spaces only — type a password.';
  // Control characters, by codepoint rather than a regex escape class: the
  // same set Go's unicode.IsControl refuses, plus a BOM that a paste can
  // carry invisibly.
  for (const ch of password) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0xfeff) {
      return 'Printable text on one line only — no tabs, newlines or other control characters.';
    }
  }
  return null;
}

// consoleDraftState is the form's state for one typed password plus its
// confirmation. Both must be present, valid and equal before a save is
// offered: the operator is choosing a credential they will next need at a
// serial console, where a typo is not recoverable from the UI.
export function consoleDraftState(
  password: string,
  confirm: string,
): { canSave: boolean; error?: string } {
  const err = validateConsolePassword(password);
  if (err) return { canSave: false, error: err };
  if (password === '') return { canSave: false };
  if (confirm === '') return { canSave: false };
  if (password !== confirm) return { canSave: false, error: 'The two entries do not match.' };
  return { canSave: true };
}

// A node's reading, in the words Settings shows.
export type ConsoleNodeReading = 'applied' | 'pending' | 'failed' | 'stale';

// readNode says where one node stands against the password now stored.
//
// "stale" is the case a bare status would hide: a node that applied an
// EARLIER password reads as applied in its own row, and is not holding the
// one the operator just chose.
export function readNode(node: ConsoleRootNode, currentHashId: string): ConsoleNodeReading {
  if (node.status === 'applied') {
    return node.hashId === currentHashId ? 'applied' : 'stale';
  }
  return node.status === 'pending' ? 'pending' : 'failed';
}

// consoleSummary counts the fleet for the one-line heading. Nodes that are
// not holding the current password — failed, pending or stale — are counted
// as outstanding: #558 says a node that did not take it is never quietly
// treated as done.
export function consoleSummary(status: ConsoleRootStatus): {
  applied: number;
  outstanding: number;
  total: number;
} {
  const nodes = status.nodes ?? [];
  let applied = 0;
  for (const n of nodes) {
    if (readNode(n, status.hashId ?? '') === 'applied') applied++;
  }
  return { applied, outstanding: nodes.length - applied, total: nodes.length };
}
