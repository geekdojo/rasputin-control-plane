// The DOM must exist before react-dom loads: keep this import first.
import { button, click, json, render, stubFetch, type } from '../test/dom';
import assert from 'node:assert/strict';
import { afterEach, describe, test } from 'node:test';
import type { OperatorSecretStatus } from '../lib/types';
import { OperatorSecretFields, useOperatorSecrets } from './OperatorSecretFields';

// geekdojo/geekdojo-brain#781: the SECRETS fields and their hook, rendered,
// against a stubbed fetch. The decisions behind the copy are lib's
// (operator-secrets.test.ts); these tests prove the rendering and the hook's
// state: what the operator sees, and which drafts survive a save.

const APP = '01JAPPID0000000000000000AB';

const STATUSES: OperatorSecretStatus[] = [
  { name: 'feed-key', label: 'Feed key', required: true, set: true },
  { name: 'map-key', label: 'Map key', required: true, set: false },
  { name: 'extra-key', label: 'Extra key', required: false, set: false },
];

// The hook's afterSave is driven from a button, the way SAVE and DEPLOY NOW drive it.
function Harness({ saved, unsaved }: { saved: string[]; unsaved: string[] }) {
  const secrets = useOperatorSecrets(APP);
  return (
    <>
      <OperatorSecretFields secrets={secrets} />
      <button type="button" onClick={() => secrets.afterSave({ saved, unsaved })}>
        AFTER SAVE
      </button>
    </>
  );
}

let restore: (() => void) | undefined;
afterEach(() => {
  restore?.();
  restore = undefined;
});

function inputFor(root: ParentNode, name: string): HTMLInputElement {
  const el = root.querySelector(`#operator-secret-${name}`);
  assert.ok(el, `no input for ${name}`);
  return el as HTMLInputElement;
}

function rowText(root: ParentNode, name: string): string {
  return inputFor(root, name).parentElement?.textContent ?? '';
}

describe('OperatorSecretFields', () => {
  // TC-781-01, TC-781-02 rendered
  test('lists each declared secret with its marker, need and a password input', async () => {
    const f = stubFetch((c) => (c.url === `/api/apps/${APP}/secrets` ? json(200, STATUSES) : undefined));
    restore = f.restore;
    const r = await render(<Harness saved={[]} unsaved={[]} />);

    assert.equal(r.container.querySelectorAll('input').length, 3);
    for (const s of STATUSES) {
      const input = inputFor(r.container, s.name);
      assert.equal(input.type, 'password');
      assert.equal(input.value, '');
      // The label names the field for assistive tech and browser agents.
      const label = r.container.querySelector(`label[for="operator-secret-${s.name}"]`);
      assert.equal(label?.textContent, s.label);
    }
    assert.match(rowText(r.container, 'feed-key'), /^Feed keyfeed-keySETrequired$/);
    assert.match(rowText(r.container, 'map-key'), /^Map keymap-keyNOT SETrequired$/);
    assert.match(rowText(r.container, 'extra-key'), /^Extra keyextra-keyNOT SEToptional$/);
    assert.equal(inputFor(r.container, 'feed-key').placeholder, 'Set — leave blank to keep');
    assert.equal(inputFor(r.container, 'map-key').placeholder, 'Not set — required before this app can deploy');
    assert.equal(inputFor(r.container, 'extra-key').placeholder, 'Not set — optional');
    await r.unmount();
  });

  test('renders nothing for an app that declares no secret', async () => {
    const f = stubFetch((c) => (c.url === `/api/apps/${APP}/secrets` ? json(200, null) : undefined));
    restore = f.restore;
    const r = await render(<Harness saved={[]} unsaved={[]} />);
    assert.equal(r.container.querySelectorAll('input').length, 0);
    assert.equal(r.container.textContent, 'AFTER SAVE');
    await r.unmount();
  });

  // TC-781-14 rendered (F-781-02): the sentence alone, never the request URL.
  test('shows the list failure as a sentence with no URL', async () => {
    const sentence = "The app's secrets could not be listed. The api log names the cause.";
    const f = stubFetch(() => json(500, { error: sentence }));
    restore = f.restore;
    const r = await render(<Harness saved={[]} unsaved={[]} />);
    const text = r.container.textContent ?? '';
    assert.equal(text, `${sentence}AFTER SAVE`);
    assert.ok(!text.includes('/api/'));
    assert.ok(!text.includes('→'));
    assert.equal(r.container.querySelectorAll('input').length, 0);
    await r.unmount();
  });

  test('a list read that never reaches the api shows the fixed sentence', async () => {
    const real = globalThis.fetch;
    globalThis.fetch = (async () => {
      throw new TypeError('Failed to fetch');
    }) as typeof fetch;
    restore = () => (globalThis.fetch = real);
    const r = await render(<Harness saved={[]} unsaved={[]} />);
    assert.equal(r.container.textContent, "This app's secrets could not be listed.AFTER SAVE");
    await r.unmount();
  });

  // TC-781-07 / TC-781-16(b) rendered: after a save, a saved input is empty
  // and a refused one keeps what was typed; the markers are re-read from the api.
  test('after a save, saved inputs are empty and unsaved drafts are kept', async () => {
    const f = stubFetch((c) => (c.url === `/api/apps/${APP}/secrets` ? json(200, STATUSES) : undefined));
    restore = f.restore;
    const r = await render(<Harness saved={['map-key']} unsaved={['extra-key']} />);
    await type(inputFor(r.container, 'map-key'), 'typed-map');
    await type(inputFor(r.container, 'extra-key'), 'typed-extra');
    assert.equal(inputFor(r.container, 'map-key').value, 'typed-map');
    assert.equal(inputFor(r.container, 'extra-key').value, 'typed-extra');

    const reads = f.calls.length;
    await click(button(r.container, 'AFTER SAVE'));

    assert.equal(inputFor(r.container, 'map-key').value, '');
    assert.equal(inputFor(r.container, 'extra-key').value, 'typed-extra');
    assert.equal(inputFor(r.container, 'feed-key').value, '');
    // The markers come from the api again, never from a local guess.
    assert.deepEqual(
      f.calls.slice(reads).map((c) => `${c.method} ${c.url}`),
      [`GET /api/apps/${APP}/secrets`],
    );
    await r.unmount();
  });
});
