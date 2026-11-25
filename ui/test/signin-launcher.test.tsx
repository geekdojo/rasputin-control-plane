// The DOM must exist before react-dom loads: keep this import first.
import { json, render, stubFetch } from './dom';
import assert from 'node:assert/strict';
import { afterEach, describe, test } from 'node:test';
import {
  NOT_READY_SENTENCE,
  SIGN_IN_SENTENCES,
  SignInLauncher,
  signInReturn,
  type SignInReturn,
} from '../components/SignInLauncher';
import SettingsPage from '../app/(authed)/settings/page';

// TC-989-31 (issue TC-07): the console's launcher holds no credential field;
// its one SIGN IN control goes to /api/auth/signin; it shows one sentence for
// each way a sign-in comes back, the not-ready sentence while sign-in is not
// ready, and the restore link at first run; no shown string names the
// identity service's engine, its database or its runtime (SC-ID-UI 2).
// Settings renders no Passkeys section.

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()?.();
});

const ENGINE_WORDS = /keycloak|postgres|java/i;

describe('TC-989-31 the launcher', () => {
  test('no input element, and SIGN IN links to /api/auth/signin', async () => {
    const r = await render(<SignInLauncher ready firstRun={false} returned={null} />);
    cleanups.push(r.unmount);
    assert.equal(r.container.querySelectorAll('input, textarea, select, form').length, 0);
    const links = Array.from(r.container.querySelectorAll('a'));
    const signIn = links.filter((a) => (a.textContent ?? '').trim() === 'SIGN IN');
    assert.equal(signIn.length, 1);
    assert.equal(signIn[0].getAttribute('href'), '/api/auth/signin');
    assert.ok(!r.container.textContent?.includes(NOT_READY_SENTENCE));
    assert.equal(links.filter((a) => a.getAttribute('href') === '/restore').length, 0, 'no restore link past first run');
    assert.doesNotMatch(r.container.textContent ?? '', ENGINE_WORDS);
  });

  test('one sentence for each ?signin= value, and none for an unknown one', async () => {
    const values: SignInReturn[] = [
      'failed',
      'expired',
      'unavailable',
      'wrong-host',
      'reset-done',
      'reset-incomplete',
      'reset-failed',
      'action-failed',
    ];
    const seen = new Set<string>();
    for (const v of values) {
      const returned = signInReturn(`?signin=${v}`);
      assert.equal(returned, v);
      const r = await render(<SignInLauncher ready firstRun={false} returned={returned} />);
      const text = r.container.textContent ?? '';
      assert.ok(text.includes(SIGN_IN_SENTENCES[v]), `${v}: ${text}`);
      for (const other of values) {
        if (other !== v) assert.ok(!text.includes(SIGN_IN_SENTENCES[other]), `${v} also shows ${other}`);
      }
      assert.doesNotMatch(text, ENGINE_WORDS);
      seen.add(SIGN_IN_SENTENCES[v]);
      await r.unmount();
    }
    assert.equal(seen.size, values.length, 'each value has its own sentence');
    assert.equal(signInReturn('?signin=bogus'), null);
    assert.equal(signInReturn(''), null);
  });

  // TC-992-23: the reset and action returns' exact sentences.
  test('the password reset and action sentences, word for word', () => {
    assert.equal(SIGN_IN_SENTENCES['reset-done'], 'Your password is changed. Sign in with it and your second step.');
    assert.equal(
      SIGN_IN_SENTENCES['reset-incomplete'],
      "Your password is changed, but Rasputin couldn't end your other sign-ins. Ask an administrator to sign you out everywhere.",
    );
    assert.equal(
      SIGN_IN_SENTENCES['reset-failed'],
      "Rasputin couldn't confirm the password reset. If you chose a new password, sign in with it. Otherwise start the reset again.",
    );
    assert.equal(SIGN_IN_SENTENCES['action-failed'], "Rasputin couldn't finish the change you signed in again for. Try it again.");
  });

  test('the not-ready sentence and no SIGN IN while not ready', async () => {
    const r = await render(<SignInLauncher ready={false} firstRun={false} returned={null} />);
    cleanups.push(r.unmount);
    assert.ok(r.container.textContent?.includes(NOT_READY_SENTENCE));
    assert.equal(r.container.querySelectorAll('a[href="/api/auth/signin"]').length, 0);
    assert.doesNotMatch(r.container.textContent ?? '', ENGINE_WORDS);
  });

  test('the restore link at first run', async () => {
    const r = await render(<SignInLauncher ready firstRun returned={null} />);
    cleanups.push(r.unmount);
    assert.equal(r.container.querySelectorAll('a[href="/restore"]').length, 1);
    assert.equal(r.container.querySelectorAll('input').length, 0);
  });
});

describe('TC-989-31 Settings', () => {
  test('renders no Passkeys section', async () => {
    const api = stubFetch((call) => (call.url.includes('/api/') ? json(404, { error: 'not found' }) : undefined));
    cleanups.push(api.restore);
    const r = await render(<SettingsPage />);
    cleanups.push(r.unmount);
    const text = r.container.textContent ?? '';
    assert.ok(text.includes('SETTINGS'), 'the page rendered');
    assert.ok(!/PASSKEYS/.test(text), 'Settings shows a Passkeys section');
    assert.ok(!text.includes('ADD PASSKEY'));
  });
});
