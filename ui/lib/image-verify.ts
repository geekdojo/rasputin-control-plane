// What the Add-node wizard can honestly tell a person flashing an image BY HAND
// about its signature (geekdojo/geekdojo-brain#527).
//
// Three cases, and the page must never blur them:
//
//   - 'signed'   — the control plane verified the release's signed manifest AND
//                  handed over the exact bytes it verified, so the page can give
//                  the commands that repeat the check.
//   - 'unchecked' — it names a signer but did not hand over a usable manifest and
//                  signature. That is what the firewall path served before #527
//                  was fixed (bench 2026-09-27): "signed by leaf-003… to check it
//                  yourself" above an EMPTY command box. A claim the reader cannot
//                  check is not shown as though they could.
//   - 'unsigned' — no signer and no manifest: a release that predates manifest
//                  signing, where the sha256 is the whole integrity story.
//
// Kept out of the component so it runs under `node --test`.

import type { FlashableImage } from './types';

export type ImageVerifyState =
  | { kind: 'signed'; signer: string; commands: string }
  | { kind: 'unchecked'; signer: string }
  | { kind: 'unsigned' };

// Strict standard base64. These values are pasted into a shell command inside
// single quotes; anything outside this alphabet (a quote above all) is refused
// rather than escaped, since a control plane that sends it is not sending a
// manifest.
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function imageVerifyState(image: FlashableImage): ImageVerifyState {
  const m = image.manifestB64 ?? '';
  const s = image.manifestSigB64 ?? '';
  const signer = image.signer ?? '';
  if (signer && B64.test(m) && B64.test(s)) {
    return {
      kind: 'signed',
      signer,
      commands: [
        `printf '%s' '${m}' | base64 -d > manifest.json`,
        `printf '%s' '${s}' | base64 -d > manifest.json.sig`,
        'curl -fsSLO https://rasputin.geekdojo.com/rasputin-root-ca.pem',
        'openssl cms -verify -purpose any -binary -inform DER -in manifest.json.sig \\',
        '  -content manifest.json -CAfile rasputin-root-ca.pem -signer signer.pem -out /dev/null',
        "openssl x509 -in signer.pem -noout -text | grep -A1 'Extended Key Usage'",
      ].join('\n'),
    };
  }
  if (signer || m || s) {
    return { kind: 'unchecked', signer };
  }
  return { kind: 'unsigned' };
}
