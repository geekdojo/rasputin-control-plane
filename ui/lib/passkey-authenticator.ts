// The kinds of authenticator an operator can choose when adding a passkey.
//
// Left to itself the browser picks, and on a machine whose built-in
// authenticator already holds a passkey for this account it picks badly: the
// api's excludeCredentials list correctly refuses that authenticator, and what
// the browser offers instead is its own password manager rather than the phone
// or the security key the operator is holding. So the operator says which one
// up front, before the ceremony starts.
//
// `value` is the wire value — it goes on the /api/auth/register/begin body and
// must stay in step with the api's authenticatorChoice constants
// (api/internal/auth/handlers.go); the api answers anything else with a 400.

export type PasskeyAuthenticator = 'platform' | 'hybrid' | 'security-key';

export interface PasskeyAuthenticatorChoice {
  value: PasskeyAuthenticator;
  /** Button copy. */
  label: string;
  /** One line under the buttons explaining what the operator will see. */
  hint: string;
}

// In the order they are offered: the common case first, then the two that
// exist because the common case can be refused.
export const PASSKEY_AUTHENTICATORS: PasskeyAuthenticatorChoice[] = [
  {
    value: 'platform',
    label: 'THIS DEVICE',
    hint: 'Uses the fingerprint, face or PIN built into the computer you’re on.',
  },
  {
    value: 'hybrid',
    label: 'PHONE OR TABLET',
    hint: 'Shows a QR code to scan with a phone or tablet, which then holds the passkey.',
  },
  {
    value: 'security-key',
    label: 'SECURITY KEY',
    hint: 'Uses a hardware key you plug in or tap.',
  },
];
