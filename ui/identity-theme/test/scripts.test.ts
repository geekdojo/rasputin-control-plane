// TC-988-10 to TC-988-13: the theme's scripts, which replace base's inline
// scripts and handlers (F-988-02, F-988-03), run under happy-dom
// (geekdojo/geekdojo-brain#988).
//
// They are browser ES modules. Each test copies them into a scratch tree laid
// out as the door serves them (login/rasputin/js/ beside
// common/keycloak/vendor/rfc4648/), with a package.json that makes .js ESM,
// a small rfc4648 stand-in (no upstream code is copied into the repo) and a
// stand-in for base's passkeysConditionalAuth.js that records its calls.
import { win } from '../../test/dom-globals';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { after, beforeEach, test } from 'node:test';
import { SRC } from './theme-files';

// tsc emits CommonJS here, which would turn import() into require(); a module
// needs the real dynamic import.
const importModule = new Function('url', 'return import(url)') as (url: string) => Promise<Record<string, unknown>>;

const root = mkdtempSync(path.join(tmpdir(), 'identity-theme-js-'));
after(() => rmSync(root, { recursive: true, force: true }));
const JS = path.join(root, 'login', 'rasputin', 'js');
cpSync(path.join(SRC, 'resources', 'js'), JS, { recursive: true });
writeFileSync(path.join(root, 'package.json'), '{"type":"module"}\n');
mkdirSync(path.join(root, 'common', 'keycloak', 'vendor', 'rfc4648'), { recursive: true });
writeFileSync(
  path.join(root, 'common', 'keycloak', 'vendor', 'rfc4648', 'rfc4648.js'),
  `export const base64url = {
  parse: (s) => new Uint8Array(Buffer.from(s, 'base64url')),
  stringify: (b) => Buffer.from(b).toString('base64url'),
};\n`,
);
writeFileSync(
  path.join(JS, 'passkeysConditionalAuth.js'),
  `export function initAuthenticate(input, cb) { (globalThis.initCalls ??= []).push(input); if (cb) cb(globalThis.conditionalAvailable === true); }\n`,
);

let fresh = 0;
/** Imports a fresh copy of the module, so its start-up code runs again. */
const load = (name: string) => importModule(`${pathToFileURL(path.join(JS, name)).href}?fresh=${++fresh}`);

const g = globalThis as unknown as Record<string, unknown>;

interface Recorded {
  creates: CredentialCreationOptions[];
  gets: CredentialRequestOptions[];
  submits: string[];
  prompts: number;
}
let rec: Recorded;

const buf = (s: string) => new TextEncoder().encode(s).buffer;

beforeEach(() => {
  document.body.innerHTML = '';
  rec = { creates: [], gets: [], submits: [], prompts: 0 };
  g.initCalls = [];
  g.conditionalAvailable = false;
  (win as unknown as Record<string, unknown>).PublicKeyCredential = function PublicKeyCredential() {};
  Object.defineProperty(win.navigator, 'credentials', {
    configurable: true,
    value: {
      create: async (o: CredentialCreationOptions) => {
        rec.creates.push(o);
        return {
          rawId: buf('raw-id'),
          authenticatorAttachment: 'platform',
          response: { clientDataJSON: buf('cd'), attestationObject: buf('ao'), getTransports: () => ['internal'] },
        };
      },
      get: async (o: CredentialRequestOptions) => {
        rec.gets.push(o);
        return null;
      },
    },
  });
  (win as unknown as Record<string, unknown>).prompt = () => {
    rec.prompts++;
    return 'from a prompt';
  };
  win.HTMLFormElement.prototype.requestSubmit = function (this: HTMLFormElement) {
    rec.submits.push(this.id || this.name);
  };
});

const settle = () => new Promise((r) => setTimeout(r, 0));

// ---- TC-988-10: the passkey choice ------------------------------------------

const REGISTER_PAGE = `
<form id="register"><input type="hidden" id="clientDataJSON"/><input type="hidden" id="attestationObject"/>
<input type="hidden" id="publicKeyCredentialId"/><input type="hidden" id="authenticatorLabel"/>
<input type="hidden" id="transports"/><input type="hidden" id="authenticatorAttachment"/><input type="hidden" id="error"/></form>
<div id="rasputin-passkey" data-challenge="Y2hhbGxlbmdl" data-userid="dXNlcg" data-username="hoodoo"
  data-signature-algorithms="-7,-257" data-rp-entity-name="Hoodoo Home" data-rp-id="bench.local"
  data-attestation-conveyance-preference="not specified" data-authenticator-attachment="not specified"
  data-require-resident-key="not specified" data-resident-key="required" data-user-verification-requirement="required"
  data-create-timeout="0" data-exclude-credential-ids="" data-init-label="Passkey" data-errmsg="unsupported">
  <input id="rasputin-passkey-name"/>
  <button id="this-device" data-rasputin-passkey-choice="this-device">THIS DEVICE</button>
  <button id="phone" data-rasputin-passkey-choice="phone-or-tablet">PHONE OR TABLET</button>
  <button id="key" data-rasputin-passkey-choice="security-key">SECURITY KEY</button>
</div>`;

for (const [button, hint, attachment] of [
  ['this-device', 'client-device', 'platform'],
  ['phone', 'hybrid', 'cross-platform'],
  ['key', 'security-key', 'cross-platform'],
] as const) {
  test(`TC-988-10: ${button} adds ${hint} and ${attachment}, keeps Keycloak's options, and takes the NAME`, async () => {
    document.body.innerHTML = REGISTER_PAGE;
    await load('rasputin-webauthn.js');
    (document.getElementById('rasputin-passkey-name') as HTMLInputElement).value = 'Kitchen laptop';
    (document.getElementById(button) as HTMLButtonElement).click();
    await settle();
    assert.equal(rec.creates.length, 1);
    const pk = rec.creates[0].publicKey as PublicKeyCredentialCreationOptions & { hints: string[] };
    assert.deepEqual(pk.hints, [hint]);
    assert.equal(pk.authenticatorSelection?.authenticatorAttachment, attachment);
    assert.equal(pk.authenticatorSelection?.residentKey, 'required');
    assert.equal(pk.authenticatorSelection?.requireResidentKey, true);
    assert.equal(pk.authenticatorSelection?.userVerification, 'required');
    assert.equal(pk.rp.id, 'bench.local');
    assert.deepEqual(pk.pubKeyCredParams.map((p) => p.alg), [-7, -257]);
    assert.equal((document.getElementById('authenticatorLabel') as HTMLInputElement).value, 'Kitchen laptop');
    assert.equal(rec.prompts, 0, 'window.prompt was called');
    assert.deepEqual(rec.submits, ['register']);
  });
}

test('TC-988-10: with no NAME typed the label is the default, still with no prompt', async () => {
  document.body.innerHTML = REGISTER_PAGE;
  await load('rasputin-webauthn.js');
  (document.getElementById('key') as HTMLButtonElement).click();
  await settle();
  assert.equal((document.getElementById('authenticatorLabel') as HTMLInputElement).value, 'Passkey');
  assert.equal(rec.prompts, 0);
});

// ---- TC-988-11: the recovery-codes page -------------------------------------

const CODES_PAGE = `
<div id="rasputin-recovery-codes" data-install-name="Hoodoo Home" data-username="bryce"
  data-file-intro="Recovery codes for {0} at {1} ({2})."
  data-file-advice="Move these codes into a password manager or onto paper, then delete this file. Each code works once.">
  <ol id="kc-recovery-codes-list"><li>AAAA-BBBB-CCCC</li><li>DDDD-EEEE-FFFF</li></ol>
  <button id="copyRecoveryCodes">COPY</button><button id="printRecoveryCodes">PRINT</button><button id="downloadRecoveryCodes">DOWNLOAD</button>
  <input type="checkbox" id="kcRecoveryCodesConfirmationCheck"/>
  <form id="kc-recovery-codes-settings-form"><input type="submit" id="saveRecoveryAuthnCodesBtn" disabled/></form>
</div>`;

test('TC-988-11: DOWNLOAD saves <install name>-recovery-codes.txt naming the person and the address, with the advice', async () => {
  document.body.innerHTML = CODES_PAGE;
  const clicked: { download: string; href: string }[] = [];
  const realClick = win.HTMLAnchorElement.prototype.click;
  win.HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
    clicked.push({ download: this.download, href: this.href });
  };
  try {
    await load('rasputin-recovery-codes.js');
    (document.getElementById('downloadRecoveryCodes') as HTMLButtonElement).click();
  } finally {
    win.HTMLAnchorElement.prototype.click = realClick;
  }
  assert.equal(clicked.length, 1);
  assert.equal(clicked[0].download, 'Hoodoo Home-recovery-codes.txt');
  const text = decodeURIComponent(clicked[0].href.replace(/^data:text\/plain;charset=utf-8,/, ''));
  assert.match(text, /^Recovery codes for bryce at Hoodoo Home \(http:\/\/localhost\)\./);
  assert.match(text, /AAAA-BBBB-CCCC\nDDDD-EEEE-FFFF/);
  assert.match(text, /into a password manager or onto paper, then delete this file/);
});

test('TC-988-11: COPY puts the codes on the clipboard, PRINT opens the print view', async () => {
  document.body.innerHTML = CODES_PAGE;
  const copied: string[] = [];
  Object.defineProperty(win.navigator, 'clipboard', { configurable: true, value: { writeText: async (t: string) => void copied.push(t) } });
  let printed = 0;
  (win as unknown as Record<string, unknown>).print = () => void printed++;
  await load('rasputin-recovery-codes.js');
  (document.getElementById('copyRecoveryCodes') as HTMLButtonElement).click();
  (document.getElementById('printRecoveryCodes') as HTMLButtonElement).click();
  assert.deepEqual(copied, ['AAAA-BBBB-CCCC\nDDDD-EEEE-FFFF']);
  assert.equal(printed, 1);
});

test('TC-988-11 (F-988-02): ticking the box enables the save button, and unticking disables it', async () => {
  document.body.innerHTML = CODES_PAGE;
  await load('rasputin-recovery-codes.js');
  const box = document.getElementById('kcRecoveryCodesConfirmationCheck') as HTMLInputElement;
  const save = document.getElementById('saveRecoveryAuthnCodesBtn') as HTMLInputElement;
  assert.equal(save.disabled, true);
  box.checked = true;
  box.dispatchEvent(new win.Event('change') as unknown as Event);
  assert.equal(save.disabled, false);
  box.checked = false;
  box.dispatchEvent(new win.Event('change') as unknown as Event);
  assert.equal(save.disabled, true);
});

// ---- TC-988-12: the SAML auto-post ------------------------------------------

test('TC-988-12: the SAML post form is submitted once when the page has loaded', async () => {
  document.body.innerHTML = '<form name="saml-post-binding" data-rasputin-autosubmit method="post" action="https://app.example/saml"></form>';
  let submits = 0;
  const realSubmit = win.HTMLFormElement.prototype.submit;
  win.HTMLFormElement.prototype.submit = function () {
    submits++;
  };
  try {
    await load('rasputin-autosubmit.js');
    win.dispatchEvent(new win.Event('load'));
    win.dispatchEvent(new win.Event('load'));
  } finally {
    win.HTMLFormElement.prototype.submit = realSubmit;
  }
  assert.equal(submits, 1);
});

// ---- TC-988-13: the other moved behaviours ----------------------------------

test('TC-988-13: "Try another way" submits kc-select-try-another-way-form', async () => {
  document.body.innerHTML = `<form id="kc-select-try-another-way-form"><input type="hidden" name="tryAnotherWay" value="on"/>
    <button type="button" id="try-another-way" data-rasputin-submit="kc-select-try-another-way-form">Try another way</button></form>`;
  await pageModule();
  (document.getElementById('try-another-way') as HTMLButtonElement).click();
  assert.deepEqual(rec.submits, ['kc-select-try-another-way-form']);
});

test('TC-988-13 (F-988-03): submitting a guarded form disables its named control, as base did', async () => {
  document.body.innerHTML = `<form id="kc-form-login" data-rasputin-once="login"><input name="username"/>
    <input type="submit" name="login" id="kc-login"/><button type="submit" name="cancel-aia" id="cancel">Cancel</button></form>`;
  await pageModule();
  document.getElementById('kc-form-login')!.dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }) as unknown as Event);
  assert.equal((document.getElementById('kc-login') as HTMLInputElement).disabled, true);
  assert.equal((document.getElementById('cancel') as HTMLButtonElement).disabled, false, 'another submit control keeps its value');
});

test("TC-988-13: the WebAuthn error page's retry fills its fields and submits", async () => {
  document.body.innerHTML = `<form id="kc-error-credential-form"><input type="hidden" id="executionValue"/><input type="hidden" id="isSetRetry"/></form>
    <button type="button" id="kc-try-again" data-rasputin-retry data-execution="exec-42">Try again</button>`;
  await pageModule();
  (document.getElementById('kc-try-again') as HTMLButtonElement).click();
  assert.equal((document.getElementById('isSetRetry') as HTMLInputElement).value, 'retry');
  assert.equal((document.getElementById('executionValue') as HTMLInputElement).value, 'exec-42');
  assert.deepEqual(rec.submits, ['kc-error-credential-form']);
});

const SIGN_IN_PASSKEY = (mode: string) => `
<form id="webauth"><input type="hidden" id="clientDataJSON"/><input type="hidden" id="authenticatorData"/><input type="hidden" id="signature"/>
<input type="hidden" id="credentialId"/><input type="hidden" id="userHandle"/><input type="hidden" id="error"/></form>
<form id="kc-form-login" hidden></form><div id="kc-form-passkey-button" hidden></div>
<button id="authenticateWebAuthnButton" type="button" data-rasputin-passkeys="${mode}" data-is-user-identified="false"
  data-challenge="Y2hhbGxlbmdl" data-user-verification="required" data-rp-id="bench.local" data-create-timeout="30"
  data-mediation="conditional" data-authenticator-attachment="not specified" data-errmsg="unsupported" data-conditional-errmsg="unsupported here">SIGN IN WITH A PASSKEY</button>`;

test('TC-988-13 (F-988-02): the passkey sign-in reads its arguments from data attributes and calls the forked authenticate on click', async () => {
  document.body.innerHTML = SIGN_IN_PASSKEY('sign-in');
  await load('rasputin-passkeys.js');
  const init = g.initCalls as Record<string, unknown>[];
  assert.equal(init.length, 1);
  assert.equal(init[0].challenge, 'Y2hhbGxlbmdl');
  assert.equal(init[0].mediation, 'conditional');
  assert.equal(init[0].errmsg, 'unsupported here');
  (document.getElementById('authenticateWebAuthnButton') as HTMLButtonElement).click();
  await settle();
  assert.equal(rec.gets.length, 1);
  const pk = rec.gets[0].publicKey!;
  assert.equal(pk.rpId, 'bench.local');
  assert.equal(pk.userVerification, 'required');
  assert.equal(pk.timeout, 30000);
  assert.equal(new TextDecoder().decode(pk.challenge as Uint8Array), 'challenge');
});

test('TC-988-13: on the passkey-first page the field or the button is shown, as the browser allows', async () => {
  for (const available of [true, false]) {
    document.body.innerHTML = SIGN_IN_PASSKEY('conditional');
    g.conditionalAvailable = available;
    await load('rasputin-passkeys.js');
    assert.equal(document.getElementById('kc-form-login')!.hidden, !available);
    assert.equal(document.getElementById('kc-form-passkey-button')!.hidden, available);
  }
});

test('TC-988-13 (F-988-02): the second-step passkey page calls the forked authenticate on click', async () => {
  document.body.innerHTML = SIGN_IN_PASSKEY('none').replace('data-rasputin-passkeys="none"', '');
  await load('rasputin-webauthn-authenticate.js');
  (document.getElementById('authenticateWebAuthnButton') as HTMLButtonElement).click();
  await settle();
  assert.equal(rec.gets.length, 1);
  assert.equal(rec.gets[0].publicKey!.rpId, 'bench.local');
});

test('TC-988-13: the front-channel sign-out follows its Continue link once the document is complete', async () => {
  document.body.innerHTML = '<a id="continue" href="https://bench.local/signed-out" data-rasputin-logout-redirect>Continue</a>';
  const followed: string[] = [];
  const realClick = win.HTMLAnchorElement.prototype.click;
  win.HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
    followed.push(this.href);
  };
  try {
    await load('rasputin-frontchannel-logout.js');
    if (document.readyState !== 'complete') document.dispatchEvent(new win.Event('readystatechange') as unknown as Event);
  } finally {
    win.HTMLAnchorElement.prototype.click = realClick;
  }
  assert.equal(document.readyState, 'complete');
  assert.deepEqual(followed, ['https://bench.local/signed-out']);
});

test('TC-988-13 (F-988-02): the forked modules import rfc4648 by its relative path', () => {
  for (const f of ['webauthnAuthenticate.js', 'webauthnRegister.js']) {
    const imports = [...readFileSync(path.join(SRC, 'resources', 'js', f), 'utf8').matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
    assert.deepEqual(imports, ['../../../common/keycloak/vendor/rfc4648/rfc4648.js'], f);
  }
});

// rasputin-page.js listens on document, so it is loaded once per file.
let pageLoaded: Promise<unknown> | undefined;
function pageModule() {
  pageLoaded ??= load('rasputin-page.js');
  return pageLoaded;
}
