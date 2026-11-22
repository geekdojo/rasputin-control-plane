// Adding a passkey: THIS DEVICE, PHONE OR TABLET or SECURITY KEY, and an
// in-page NAME field (geekdojo/geekdojo-brain#988, ui.md §4.3; brings back
// geekdojo/geekdojo-brain#586's per-ceremony choice). Moved out of base's
// inline module in webauthn-register.ftl.
//
// Each choice wraps navigator.credentials.create for one ceremony: it adds
// the WebAuthn Level 3 hint and the matching authenticatorAttachment to the
// options Keycloak built and keeps everything else. The forked
// webauthnRegister.js then runs the ceremony and takes the NAME as the
// credential's label instead of asking through window.prompt.
import { registerByWebAuthn } from './webauthnRegister.js';

/**
 * Each choice's hint and attachment: the table the api's own passkey page
 * uses (api/internal/auth/handlers.go, go-webauthn's PublicKeyCredentialHint
 * values).
 */
export const CHOICES = {
  'this-device': { hint: 'client-device', attachment: 'platform' },
  'phone-or-tablet': { hint: 'hybrid', attachment: 'cross-platform' },
  'security-key': { hint: 'security-key', attachment: 'cross-platform' },
};

/** Keycloak's registration arguments, from the form's data attributes. */
export function registrationInput(el) {
  const d = el.dataset;
  return {
    challenge: d.challenge,
    userid: d.userid,
    username: d.username,
    signatureAlgorithms: (d.signatureAlgorithms || '')
      .split(',')
      .filter((s) => s !== '')
      .map(Number),
    rpEntityName: d.rpEntityName,
    rpId: d.rpId,
    attestationConveyancePreference: d.attestationConveyancePreference,
    authenticatorAttachment: d.authenticatorAttachment,
    requireResidentKey: d.requireResidentKey,
    residentKey: d.residentKey,
    userVerificationRequirement: d.userVerificationRequirement,
    createTimeout: Number(d.createTimeout || '0'),
    excludeCredentialIds: d.excludeCredentialIds || '',
    initLabel: d.initLabel,
    errmsg: d.errmsg,
  };
}

/** Wraps navigator.credentials.create so the next call carries choice. */
export function wrapCreate(container, choice) {
  const real = container.create.bind(container);
  container.create = (options) => {
    container.create = real;
    const publicKey = { ...options.publicKey };
    publicKey.hints = [choice.hint];
    publicKey.authenticatorSelection = {
      ...(publicKey.authenticatorSelection || {}),
      authenticatorAttachment: choice.attachment,
    };
    return real({ ...options, publicKey });
  };
}

const root = document.getElementById('rasputin-passkey');
if (root) {
  for (const button of root.querySelectorAll('[data-rasputin-passkey-choice]')) {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      const choice = CHOICES[button.getAttribute('data-rasputin-passkey-choice')];
      if (!choice) return;
      for (const b of root.querySelectorAll('[data-rasputin-passkey-choice]')) b.disabled = true;
      const input = registrationInput(root);
      const name = document.getElementById('rasputin-passkey-name');
      const typed = name && name.value.trim();
      if (typed) input.initLabel = typed;
      wrapCreate(navigator.credentials, choice);
      registerByWebAuthn(input);
    });
  }
}
