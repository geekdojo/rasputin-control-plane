// The passkey or security-key second step, moved out of base's inline module
// in webauthn-authenticate.ftl (geekdojo/geekdojo-brain#988). It reads
// Keycloak's arguments from the button's data attributes and calls the
// forked webauthnAuthenticate.js on click.
import { authenticateByWebAuthn } from './webauthnAuthenticate.js';

const button = document.getElementById('authenticateWebAuthnButton');
if (button) {
  const d = button.dataset;
  button.addEventListener(
    'click',
    () => {
      authenticateByWebAuthn({
        isUserIdentified: d.isUserIdentified === 'true',
        challenge: d.challenge,
        userVerification: d.userVerification,
        rpId: d.rpId,
        createTimeout: Number(d.createTimeout || '0'),
        errmsg: d.errmsg,
      });
    },
    { once: true },
  );
}
