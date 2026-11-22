// Passkey sign-in, moved out of base's inline module in passkeys.ftl and
// login-passkeys-conditional-authenticate.ftl (geekdojo/geekdojo-brain#988).
// It reads Keycloak's arguments from the [data-rasputin-passkeys] button's
// data attributes and calls the forked webauthnAuthenticate.js;
// passkeysConditionalAuth.js is base's, and its own import of
// ./webauthnAuthenticate.js resolves to the same fork.
//
// data-rasputin-passkeys="sign-in": the button on the sign-in page.
// data-rasputin-passkeys="conditional": the passkey-first page, which shows
// the autofill field when the browser offers passkeys there and the button
// otherwise (base's style.display toggle, here the hidden attribute).
import { authenticateByWebAuthn } from './webauthnAuthenticate.js';
import { initAuthenticate } from './passkeysConditionalAuth.js';

/** Keycloak's arguments, as the template wrote them into data attributes. */
export function passkeyArgs(el) {
  const d = el.dataset;
  const args = {
    isUserIdentified: d.isUserIdentified === 'true',
    challenge: d.challenge,
    userVerification: d.userVerification,
    rpId: d.rpId,
    createTimeout: Number(d.createTimeout || '0'),
  };
  if (d.mediation) args.mediation = d.mediation;
  if (d.authenticatorAttachment) args.authenticatorAttachment = d.authenticatorAttachment;
  return args;
}

/** Wires the button: a click starts one passkey sign-in. */
export function startPasskeys(button) {
  const args = passkeyArgs(button);
  button.addEventListener(
    'click',
    (event) => {
      event.preventDefault();
      authenticateByWebAuthn({ errmsg: button.dataset.errmsg, ...args });
    },
    { once: true },
  );
  if (button.dataset.rasputinPasskeys === 'conditional') {
    initAuthenticate({ errmsg: button.dataset.conditionalErrmsg, ...args }, (available) => {
      const show = document.getElementById(available ? 'kc-form-login' : 'kc-form-passkey-button');
      if (show) show.hidden = false;
    });
  } else {
    initAuthenticate({ errmsg: button.dataset.conditionalErrmsg, ...args });
  }
}

const button = document.querySelector('[data-rasputin-passkeys]');
if (button) {
  startPasskeys(button);
}
