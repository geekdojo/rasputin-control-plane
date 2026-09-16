// The operator SSH key setting's rules, kept out of the components so they
// can be executed (operator-key.test.ts).
//
// What the setting is (geekdojo/geekdojo-brain#246): ONE public key, the one
// the Add-node wizard prefills, so it is written into the seeds of nodes
// enrolled from now on. It never changes a node that is already enrolled —
// that node's authorized_keys was written once, from its seed, and changing it
// is a manual step on the node. It used to be a list with add/remove; a second
// key was inert and "remove" revoked nothing, which is why it is one key now.

import type { OperatorKey } from './api';
import { validateSSHKey } from './enroll';

// Where the manual "replace or revoke the operator key on an enrolled node"
// procedure lives: the bench-verified page in the public docs
// (geekdojo/geekdojo-brain#246), published from rasputin-site's
// content/docs/replace-or-revoke-an-ssh-key.md. Settings links to it from the
// sentence saying that changing the key on an enrolled node is a manual step.
// The trailing slash is the page's canonical URL, so the link does not
// redirect. Renaming that page breaks this link: change both together.
export const ENROLLED_NODE_KEY_PROCEDURE_URL = 'https://rasputin.geekdojo.com/docs/replace-or-revoke-an-ssh-key/';

// keyToRemember decides whether an enrollment should save the key it used as
// the operator key. Only when no key is saved: the first enrollment with a key
// captures it, and a key typed for one node never silently replaces the key
// the operator chose in Settings. `stored` is null when the setting failed to
// load — then nothing is written, because a blind write could clobber it.
export function keyToRemember(stored: OperatorKey | null, usedKey: string): string | null {
  if (stored === null) return null;
  if (usedKey === '' || stored.key !== '') return null;
  return usedKey;
}

// operatorKeyDraft is the Settings editor's state for a pasted replacement.
// A save is offered for any valid key that would change what is stored —
// including re-saving the current key when a legacy value still carries
// ignored extras, since that is how they get removed.
export function operatorKeyDraft(
  stored: OperatorKey,
  draft: string,
): { key: string; error?: string; canSave: boolean } {
  const check = validateSSHKey(draft);
  if (check.key === '' || check.error) return { ...check, canSave: false };
  const changes = check.key !== stored.key || stored.ignoredKeys > 0;
  return { key: check.key, canSave: changes };
}
