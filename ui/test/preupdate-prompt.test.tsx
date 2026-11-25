// The DOM must exist before react-dom loads: keep this import first.
import { button, click, json, render, stubFetch } from './dom';
import assert from 'node:assert/strict';
import { afterEach, describe, test } from 'node:test';
import SettingsPage from '../app/(authed)/settings/page';
import { PRE_UPDATE_PROMPT } from '../lib/bridge';
import { spyNavigation, stubPasskey } from './passkey-stub';

// TC-1005-28 (geekdojo/geekdojo-brain#1005): the pre-update session's prompt
// on the real /settings page.

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()?.();
});

const ME = { sub: 's', name: 'b-1', roles: ['admin'], capabilities: [] };

describe('TC-1005-28 the pre-update prompt on /settings', () => {
  test('shown only while me.preUpdate.needsPassword', async () => {
    for (const [me, shown] of [
      [{ ...ME, preUpdate: { needsPassword: true } }, true],
      [{ ...ME, preUpdate: { needsPassword: false } }, false],
      [ME, false],
    ] as const) {
      const api = stubFetch(({ url }) => (url.endsWith('/api/auth/me') ? json(200, me) : undefined));
      const r = await render(<SettingsPage />);
      const text = r.container.textContent ?? '';
      assert.ok(text.includes('SETTINGS'), 'the page rendered');
      assert.equal(text.includes(PRE_UPDATE_PROMPT), shown, JSON.stringify(me));
      assert.equal(Array.from(r.container.querySelectorAll('button')).some((b) => b.textContent?.trim() === 'SET YOUR PASSWORD'), shown);
      await r.unmount();
      api.restore();
    }
    assert.equal(PRE_UPDATE_PROMPT, "Rasputin's sign-in changed. Set your password now; this session ends within seven days.");
  });

  test('the button runs the ceremony, then opens /login/bridge without signing out', async () => {
    const nav = spyNavigation();
    cleanups.push(nav.restore);
    const pk = stubPasskey();
    cleanups.push(pk.restore);
    const api = stubFetch(({ url }) => {
      if (url.endsWith('/api/auth/me')) return json(200, { ...ME, preUpdate: { needsPassword: true } });
      if (url.endsWith('/api/auth/bridge/begin')) return json(200, { publicKey: { challenge: 'Y2hhbGxlbmdlLWNoYWxsZW5nZQ', rpId: 'localhost' } });
      if (url.endsWith('/api/auth/bridge/finish')) return json(200, { next: '/login/bridge' });
      return undefined;
    });
    cleanups.push(api.restore);
    const r = await render(<SettingsPage />);
    cleanups.push(r.unmount);
    await click(button(r.container, 'SET YOUR PASSWORD'));
    assert.equal(pk.calls(), 1, 'the ceremony ran');
    const finish = api.calls.find((c) => c.url.endsWith('/api/auth/bridge/finish'));
    assert.ok(finish && JSON.parse(finish.body ?? '{}').rawId, 'finish carried the assertion');
    assert.deepEqual(nav.calls, ['/login/bridge']);
    assert.equal(api.calls.filter((c) => c.url.includes('/api/auth/logout')).length, 0, 'the prompt signed out');
  });
});
