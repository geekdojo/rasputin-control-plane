// The DOM must exist before react-dom loads: keep this import first.
import { button, click, json, render, stubFetch, type } from './dom';
import assert from 'node:assert/strict';
import { afterEach, describe, test } from 'node:test';
import { RepairLink } from '../components/RepairLink';
import {
  REPAIR_LINK_SENTENCE,
  isIPLiteral,
  repairLinkShown,
  repairSessionLive,
  whatHappensNext,
  type RepairState,
} from '../lib/repair';
import RepairPage from '../app/repair/page';

// geekdojo/geekdojo-brain#321: the /login repair link and the /repair page.

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()?.();
});

describe('TC-321-24 where the repair link is offered', () => {
  test('repairLinkShown: not ready, or reached by an IPv4 or IPv6 address', () => {
    assert.equal(repairLinkShown(false, 'ci.local'), true);
    assert.equal(repairLinkShown(true, '192.0.2.1'), true);
    assert.equal(repairLinkShown(true, '[fe80::1]'), true);
    assert.equal(repairLinkShown(true, 'fe80::1'), true);
    assert.equal(repairLinkShown(true, 'ci.local'), false);
    assert.equal(isIPLiteral('192.0.2.300'), false);
    assert.equal(isIPLiteral('1.2.3'), false);
    assert.equal(isIPLiteral('cafe.local'), false);
  });

  test('the link renders exactly then, and goes to /repair', async () => {
    for (const [ready, host, shown] of [
      [false, 'ci.local', true],
      [true, '192.0.2.1', true],
      [true, 'ci.local', false],
    ] as const) {
      const r = await render(<RepairLink ready={ready} hostname={host} />);
      const links = Array.from(r.container.querySelectorAll('a'));
      assert.equal(links.length, shown ? 1 : 0, `${ready} ${host}`);
      if (shown) {
        assert.equal(links[0].getAttribute('href'), '/repair');
        assert.equal((links[0].textContent ?? '').trim(), REPAIR_LINK_SENTENCE);
      }
      await r.unmount();
    }
  });

  test('/login is sent to /repair exactly when GET /api/repair/state answers 200', async () => {
    const live = stubFetch(({ url }) => (url.endsWith('/api/repair/state') ? json(200, { sentence: 's' }) : undefined));
    assert.equal(await repairSessionLive(), true);
    live.restore();
    const none = stubFetch(({ url }) => (url.endsWith('/api/repair/state') ? json(401, { error: 'x' }) : undefined));
    assert.equal(await repairSessionLive(), false);
    none.restore();
  });
});

const WAYS = {
  signInAt: 'https://ci.local',
  urls: ['https://ci.local/repair'],
  ways: [
    { id: 'screen', text: "On the control plane's own screen and keyboard, sign in as root and run:", command: 'rasputin-api repair-code' },
    { id: 'ssh', text: "From a computer that holds the control plane's SSH key, run:", command: 'ssh -t root@ci.local rasputin-api repair-code' },
  ],
};

const STATE: RepairState = {
  sentence: 'Sign-in is unavailable because the sign-in service could not start.',
  ready: false,
  signInAt: 'https://ci.local',
  actions: [{ id: 'restart', kind: 'identity.restart', label: 'RESTART', enabled: true }],
  jobs: [],
};

describe('/repair', () => {
  test('without a session: the ways, the code field, and the code posted in the body', async () => {
    let session = false;
    const f = stubFetch(({ method, url }) => {
      if (url.endsWith('/api/repair/state')) return session ? json(200, STATE) : json(401, { error: 'x' });
      if (url.endsWith('/api/repair/ways')) return json(200, WAYS);
      if (method === 'POST' && url.endsWith('/api/auth/break-glass')) {
        session = true;
        return json(200, { status: 'ok' });
      }
      return undefined;
    });
    cleanups.push(f.restore);
    const r = await render(<RepairPage />);
    cleanups.push(r.unmount);
    const textOf = () => r.container.textContent ?? '';
    assert.ok(textOf().includes('ssh -t root@ci.local rasputin-api repair-code'));
    assert.ok(textOf().includes(whatHappensNext('https://ci.local')));
    assert.equal(r.container.querySelectorAll('button[aria-label^="Copy the"]').length, 2);
    await type(r.container.querySelector('#repair-code') as HTMLInputElement, 'abcde-fghij-klmno-pqrst');
    await click(button(r.container, 'OPEN REPAIR SESSION'));
    const post = f.calls.find((c) => c.method === 'POST');
    assert.ok(post && !post.url.includes('abcde'), 'the code is not in the address');
    assert.deepEqual(JSON.parse(post?.body ?? '{}'), { code: 'abcde-fghij-klmno-pqrst' });
    assert.ok(textOf().includes(STATE.sentence), 'the state shows once the session is open');
  });

  test('with a session: the state, RESTART, the jobs, END, and SIGN IN NORMALLY once ready', async () => {
    let state: RepairState = { ...STATE };
    const f = stubFetch(({ method, url }) => {
      if (url.endsWith('/api/repair/state')) return json(200, state);
      if (method === 'POST' && url.endsWith('/api/repair/restart')) {
        state = { ...state, jobs: [{ id: 'J1', kind: 'identity.restart', status: 'succeeded', finished: true }] };
        return json(202, { id: 'J1' });
      }
      return undefined;
    });
    cleanups.push(f.restore);
    const r = await render(<RepairPage />);
    cleanups.push(r.unmount);
    assert.ok((r.container.textContent ?? '').includes(STATE.sentence));
    assert.throws(() => button(r.container, 'SIGN IN NORMALLY'));
    await click(button(r.container, 'RESTART'));
    assert.ok(f.calls.some((c) => c.method === 'POST' && c.url.endsWith('/api/repair/restart')));
    assert.ok((r.container.textContent ?? '').includes('identity.restart — succeeded'));
    button(r.container, 'END REPAIR SESSION');
    await r.unmount();
    cleanups.pop();

    state = { ...STATE, ready: true, sentence: 'Sign-in is running. Sign in normally, then end this repair session.' };
    const r2 = await render(<RepairPage />);
    cleanups.push(r2.unmount);
    button(r2.container, 'SIGN IN NORMALLY');
    assert.ok((r2.container.textContent ?? '').includes(whatHappensNext('https://ci.local')));
  });

  test('a disabled action shows its reason', async () => {
    const f = stubFetch(({ url }) =>
      url.endsWith('/api/repair/state')
        ? json(200, { ...STATE, actions: [{ id: 'restart', kind: 'identity.restart', label: 'RESTART', enabled: false, reason: 'Busy now.' }] })
        : undefined,
    );
    cleanups.push(f.restore);
    const r = await render(<RepairPage />);
    cleanups.push(r.unmount);
    assert.equal(button(r.container, 'RESTART').disabled, true);
    assert.ok((r.container.textContent ?? '').includes('Busy now.'));
  });
});

// TC-321-51: the reset and the move on /repair (geekdojo/geekdojo-brain#321 PR 2).
describe('TC-321-51 /repair renders the reset and the move', () => {
  const RESET_SENTENCE = "This resets alice's sign-in: … This is recorded and raises an alert.";
  const MOVE_SENTENCE = 'This brings back the 3 accounts this cluster had before its sign-in update, with no passwords: …';
  const withActions = (actions: RepairState['actions']): RepairState => ({ ...STATE, actions });
  const RESET = {
    id: 'reset',
    kind: 'accounts.repair_reset',
    label: "RESET THIS ADMIN'S SIGN-IN",
    enabled: true,
    targets: [
      { id: 'sub-alice', name: 'alice' },
      { id: 'sub-dora', name: 'dora' },
    ],
  };
  const MOVE = { id: 'move', kind: 'identity.move', label: 'BRING BACK THE ACCOUNTS FROM BEFORE THE UPDATE…', enabled: true };

  test('each target has a reset; its 409 opens the panel; CONFIRM posts the token and the password, and empties the field', async () => {
    let refuse = true;
    const f = stubFetch(({ method, url, body }) => {
      if (url.endsWith('/api/repair/state')) return json(200, withActions([STATE.actions[0], RESET]));
      if (method === 'POST' && url.endsWith('/api/repair/reset')) {
        const b = JSON.parse(body ?? '{}');
        if (!b.stateToken) {
          return json(409, { error: RESET_SENTENCE, code: 'repair_confirm', correlationId: 'c', stateToken: 'T1', account: { id: b.accountId, name: 'alice' } });
        }
        if (refuse) return json(400, { error: 'That password is too common. Choose another.', code: 'password_refused' });
        return json(202, { id: 'J2' });
      }
      return undefined;
    });
    cleanups.push(f.restore);
    const r = await render(<RepairPage />);
    cleanups.push(r.unmount);
    const resets = Array.from(r.container.querySelectorAll('button')).filter((b) => (b.textContent ?? '').trim() === RESET.label);
    assert.equal(resets.length, 2, 'one reset per target');
    await click(resets[0]);
    assert.deepEqual(JSON.parse(f.calls.filter((c) => c.method === 'POST').at(-1)?.body ?? '{}'), { accountId: 'sub-alice' });
    assert.ok((r.container.textContent ?? '').includes(RESET_SENTENCE), 'the api sentence shows');
    const field = r.container.querySelector('#repair-temp-password') as HTMLInputElement;
    assert.ok(field, 'the password field shows');
    assert.equal(field.getAttribute('type'), 'password');
    assert.equal(field.getAttribute('autocomplete'), 'new-password');

    // A refused password: the field is emptied, and the refusal shows.
    await type(field, 'correcthorsebatterystaple');
    await click(button(r.container, 'CONFIRM'));
    assert.deepEqual(JSON.parse(f.calls.filter((c) => c.method === 'POST').at(-1)?.body ?? '{}'), {
      accountId: 'sub-alice',
      stateToken: 'T1',
      password: 'correcthorsebatterystaple',
    });
    assert.equal((r.container.querySelector('#repair-temp-password') as HTMLInputElement).value, '');
    assert.ok((r.container.textContent ?? '').includes('That password is too common. Choose another.'));

    // Accepted: the field is emptied and the panel closes.
    refuse = false;
    await type(r.container.querySelector('#repair-temp-password') as HTMLInputElement, 'a long unlisted passphrase');
    await click(button(r.container, 'CONFIRM'));
    assert.equal(JSON.parse(f.calls.filter((c) => c.method === 'POST').at(-1)?.body ?? '{}').password, 'a long unlisted passphrase');
    assert.equal(r.container.querySelector('#repair-temp-password'), null, 'the panel closed');
  });

  test('a disabled reset shows its reason', async () => {
    const reason = 'This repair session has already reset a sign-in. Make a new repair code to reset another.';
    const f = stubFetch(({ url }) =>
      url.endsWith('/api/repair/state') ? json(200, withActions([{ ...RESET, enabled: false, targets: undefined, reason }])) : undefined,
    );
    cleanups.push(f.restore);
    const r = await render(<RepairPage />);
    cleanups.push(r.unmount);
    assert.equal(button(r.container, RESET.label).disabled, true);
    assert.ok((r.container.textContent ?? '').includes(reason));
  });

  test('the move shows its 409 sentence and CONFIRM posts the token', async () => {
    const f = stubFetch(({ method, url, body }) => {
      if (url.endsWith('/api/repair/state')) return json(200, withActions([STATE.actions[0], MOVE]));
      if (method === 'POST' && url.endsWith('/api/repair/move')) {
        const b = JSON.parse(body ?? '{}');
        if (!b.stateToken) return json(409, { error: MOVE_SENTENCE, code: 'repair_confirm', correlationId: 'c', stateToken: 'M1', accounts: 3 });
        return json(202, { id: 'J3' });
      }
      return undefined;
    });
    cleanups.push(f.restore);
    const r = await render(<RepairPage />);
    cleanups.push(r.unmount);
    await click(button(r.container, MOVE.label));
    assert.ok((r.container.textContent ?? '').includes(MOVE_SENTENCE));
    assert.equal(r.container.querySelector('#repair-temp-password'), null, 'the move takes no password');
    await click(button(r.container, 'CONFIRM'));
    assert.deepEqual(JSON.parse(f.calls.filter((c) => c.method === 'POST').at(-1)?.body ?? '{}'), { stateToken: 'M1' });
  });

  test('neither renders when the state does not list it', async () => {
    const f = stubFetch(({ url }) => (url.endsWith('/api/repair/state') ? json(200, STATE) : undefined));
    cleanups.push(f.restore);
    const r = await render(<RepairPage />);
    cleanups.push(r.unmount);
    assert.throws(() => button(r.container, RESET.label));
    assert.throws(() => button(r.container, MOVE.label));
  });
});
