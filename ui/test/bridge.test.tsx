// The DOM must exist before react-dom loads: keep this import first.
import { button, click, json, render, stubFetch, type } from './dom';
import assert from 'node:assert/strict';
import { afterEach, describe, test } from 'node:test';
import { BridgeOffer } from '../components/profile/PreUpdateSignIn';
import {
  ChooseAPassword,
  CHOOSE_OPENING,
  CHOOSE_TITLE,
  EMAIL_NOTE,
  NO_GRANT,
  PASSWORD_RULE,
  nextAddress,
  refusalField,
} from '../components/profile/ChooseAPassword';
import { BRIDGE_OFFER, CEREMONY_CANCELLED } from '../lib/bridge';
import { spyNavigation, stubPasskey } from './passkey-stub';

// geekdojo/geekdojo-brain#1005: the /login offer and CHOOSE A PASSWORD.

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()?.();
});

const GRANT = { offered: true, name: 'b-1', previousName: 'b', signInOrigin: 'https://sso-bench.local' };

describe('TC-1005-25 the /login offer', () => {
  test('shown with offered:true; not with false or a failed read', async () => {
    for (const [answer, shown] of [
      [json(200, { offered: true }), true],
      [json(200, { offered: false }), false],
      [json(500, { error: 'x', code: 'bridge_unavailable' }), false],
      [json(404, { error: 'x', code: 'bridge_unavailable' }), false],
    ] as const) {
      const api = stubFetch(({ url }) => (url.endsWith('/api/auth/bridge') ? answer.clone() : undefined));
      const r = await render(<BridgeOffer />);
      assert.equal((r.container.textContent ?? '').includes(BRIDGE_OFFER), shown, `${answer.status}`);
      await r.unmount();
      api.restore();
    }
    assert.equal(BRIDGE_OFFER, 'Signed in here before this update? Continue with your passkey');
  });

  test('the offer runs the ceremony and opens CHOOSE A PASSWORD; a refusal shows its sentence', async () => {
    const nav = spyNavigation();
    cleanups.push(nav.restore);
    const pk = stubPasskey();
    cleanups.push(pk.restore);
    let finish = json(200, { next: '/login/bridge' });
    const api = stubFetch(({ url }) => {
      if (url.endsWith('/api/auth/bridge')) return json(200, { offered: true });
      if (url.endsWith('/api/auth/bridge/begin')) return json(200, { publicKey: { challenge: 'Y2hhbGxlbmdlLWNoYWxsZW5nZQ', rpId: 'localhost', userVerification: 'required' } });
      if (url.endsWith('/api/auth/bridge/finish')) return finish.clone();
      return undefined;
    });
    cleanups.push(api.restore);
    const r = await render(<BridgeOffer />);
    cleanups.push(r.unmount);
    await click(button(r.container, BRIDGE_OFFER));
    assert.deepEqual(nav.calls, ['/login/bridge']);
    assert.equal(pk.calls(), 1);

    finish = json(409, { error: "This account already has a password, so sign in with it instead.", code: 'has_password', correlationId: 'c' });
    await click(button(r.container, BRIDGE_OFFER));
    assert.equal(nav.calls.length, 1, 'a refusal navigated');
    const text = r.container.textContent ?? '';
    assert.ok(text.includes('This account already has a password, so sign in with it instead.'));
    // F-1005-07: has_password offers SIGN IN, to the console's sign-in.
    const signIn = Array.from(r.container.querySelectorAll('a')).filter((a) => (a.textContent ?? '').trim() === 'SIGN IN');
    assert.equal(signIn.length, 1);
    assert.equal(signIn[0].getAttribute('href'), '/api/auth/signin');

    pk.fail();
    await click(button(r.container, BRIDGE_OFFER));
    assert.ok((r.container.textContent ?? '').includes(CEREMONY_CANCELLED));
  });
});

// renderChooser renders CHOOSE A PASSWORD over grant and the password route.
async function renderChooser(grant: unknown, password: (body: string | undefined) => Response) {
  const api = stubFetch(({ url, method, body }) => {
    if (url.endsWith('/api/auth/bridge') && method === 'GET') return json(200, grant);
    if (url.endsWith('/api/auth/bridge/password') && method === 'POST') return password(body);
    return undefined;
  });
  cleanups.push(api.restore);
  const r = await render(<ChooseAPassword />);
  cleanups.push(r.unmount);
  return { r, api };
}

function inputs(c: HTMLElement) {
  return {
    name: c.querySelector('#bridge-name') as HTMLInputElement,
    password: c.querySelector('#bridge-password') as HTMLInputElement,
    email: c.querySelector('#bridge-email') as HTMLInputElement,
  };
}

async function fill(c: HTMLElement, pw: string, email: string) {
  const f = inputs(c);
  await type(f.password, pw);
  await type(f.email, email);
}

describe('TC-1005-26 CHOOSE A PASSWORD (F-1005-02)', () => {
  test('the screen ui.md §5.4 draws, with SHOW switching the field and back', async () => {
    const { r } = await renderChooser(GRANT, () => json(200, { next: '/api/auth/signin' }));
    const text = r.container.textContent ?? '';
    for (const s of [CHOOSE_TITLE, CHOOSE_OPENING, PASSWORD_RULE, EMAIL_NOTE, nextAddress('https://sso-bench.local')]) {
      assert.ok(text.includes(s), `missing ${s}`);
    }
    assert.equal(CHOOSE_OPENING, "Rasputin's sign-in changed. Choose a password and add your email, then sign in with them.");
    assert.equal(PASSWORD_RULE, 'At least 15 characters. Three or four words work well.');
    assert.equal(EMAIL_NOTE, 'Rasputin never sends you email.');
    assert.equal(
      nextAddress('https://sso-bench.local'),
      "Sign-in now has its own page, at https://sso-bench.local. You'll go there next; it's part of this Rasputin.",
    );
    const f = inputs(r.container);
    assert.equal(f.name.value, 'b-1');
    assert.ok(f.name.readOnly);
    assert.ok(text.includes('Before the update it was b.'));
    assert.equal(f.password.type, 'password');
    assert.ok(f.email.required);
    assert.equal(f.email.type, 'email');
    await click(button(r.container, 'SHOW'));
    assert.equal(inputs(r.container).password.type, 'text');
    await click(button(r.container, 'HIDE'));
    assert.equal(inputs(r.container).password.type, 'password');
  });

  test('no previous name when the name is unchanged', async () => {
    const { r } = await renderChooser({ offered: true, name: 'carol', signInOrigin: 'https://sso-bench.local' }, () => json(200, {}));
    assert.ok(!(r.container.textContent ?? '').includes('Before the update it was'));
  });

  test('no live grant: the expired sentence and a way back to /login', async () => {
    for (const grant of [{ offered: true }, undefined]) {
      const api = stubFetch(({ url }) => (url.endsWith('/api/auth/bridge') ? (grant ? json(200, grant) : json(500, {})) : undefined));
      const r = await render(<ChooseAPassword />);
      assert.ok((r.container.textContent ?? '').includes(NO_GRANT));
      assert.equal(r.container.querySelectorAll('a[href="/login"]').length, 1);
      assert.equal(r.container.querySelectorAll('input').length, 0);
      await r.unmount();
      api.restore();
    }
  });
});

describe('TC-1005-27 the page refusals and success', () => {
  test('a 422 sentence shows verbatim beside its own field', async () => {
    for (const [code, sentence, field] of [
      ['email_taken', 'Another account already uses that email address.', '#bridge-email'],
      ['email_invalid', 'Enter your email address, such as name@example.com.', '#bridge-email'],
      ['password_refused', 'That password is too common. Choose another.', '#bridge-password'],
    ] as const) {
      const { r } = await renderChooser(GRANT, () => json(422, { error: sentence, code, correlationId: 'c' }));
      await fill(r.container, 'a long unlisted passphrase', 'b@example.org');
      await click(button(r.container, 'SAVE AND CONTINUE TO SIGN IN'));
      const holder = r.container.querySelector(field)?.closest('div')?.parentElement;
      assert.ok(holder?.textContent?.includes(sentence), `${code} not beside ${field}`);
      assert.equal((r.container.textContent ?? '').split(sentence).length, 2, `${code} shown more than once`);
      assert.equal(refusalField(code), field === '#bridge-email' ? 'email' : 'password');
    }
  });

  test('409 grant_used shows its sentence and a way back to /login', async () => {
    const sentence = 'This step has already been used. Start again from the sign-in page.';
    const { r } = await renderChooser(GRANT, () => json(409, { error: sentence, code: 'grant_used', correlationId: 'c' }));
    await fill(r.container, 'a long unlisted passphrase', 'b@example.org');
    await click(button(r.container, 'SAVE AND CONTINUE TO SIGN IN'));
    assert.ok((r.container.textContent ?? '').includes(sentence));
    assert.equal(r.container.querySelectorAll('a[href="/login"]').length, 1);
    assert.equal(refusalField('grant_used'), null);
  });

  test('a success navigates to next, with the typed values posted', async () => {
    const nav = spyNavigation();
    cleanups.push(nav.restore);
    let posted: unknown;
    const { r } = await renderChooser(GRANT, (body) => {
      posted = JSON.parse(body ?? '{}');
      return json(200, { next: '/api/auth/signin' });
    });
    await fill(r.container, 'a long unlisted passphrase', 'b@example.org');
    await click(button(r.container, 'SAVE AND CONTINUE TO SIGN IN'));
    assert.deepEqual(posted, { password: 'a long unlisted passphrase', email: 'b@example.org' });
    assert.deepEqual(nav.calls, ['/api/auth/signin']);
  });
});
