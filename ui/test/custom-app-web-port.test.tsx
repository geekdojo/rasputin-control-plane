// The DOM must exist before react-dom loads: keep this import first.
import { button, click, json, render, stubFetch, type, type Call, type Rendered } from './dom';
import assert from 'node:assert/strict';
import { afterEach, describe, test } from 'node:test';
import type { ReactElement } from 'react';
import type { App, Node } from '../lib/types';
import { CREATE_APP_FAILED } from '../lib/api';
import AppCatalogPage from '../app/(authed)/app-catalog/page';
import { ComposeChangeModal } from '../components/ComposeChangeModal';

// geekdojo/geekdojo-brain#1090 on the real catalog page and the real EDIT
// COMPOSE modal: the WEB PORT field on both custom-app forms, what each sends
// as the contract's webPort, and what the owner sees when the api refuses.

const SENTENCE = 'The web port must be a whole number from 1 to 65535.';
const CODED = { error: SENTENCE, code: 'web_port_invalid', correlationId: 'x' };
const LABEL = 'WEB PORT (PUBLISHED ON THE NODE)';
const MEANING =
  "The port your Compose file publishes on 127.0.0.1 for this app's web page, such as 8080 in 127.0.0.1:8080:80. It is not the container's port.";
const APP_ID = '01JAPPID0000000000000000AB';

const NODE: Node = {
  id: 'node-1',
  role: 'compute',
  hostname: 'node-1',
  agentVersion: 'dev',
  firstSeen: '2026-11-22T00:00:00Z',
  lastSeen: '2026-11-22T00:00:00Z',
  status: 'online',
};

function makeApp(over: Partial<App> = {}): App {
  return {
    id: APP_ID,
    name: 'whoami',
    composeYaml: 'services:\n  web:\n    image: traefik/whoami\n',
    targetNode: 'node-1',
    lastStatus: 'running',
    createdAt: '2026-11-22T00:00:00Z',
    updatedAt: '2026-11-22T00:00:00Z',
    ...over,
  };
}

let cleanup: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  for (const c of cleanup.reverse()) await c();
  cleanup = [];
});

async function mount(ui: ReactElement, f: { restore: () => void }): Promise<Rendered> {
  cleanup.push(f.restore);
  const r = await render(ui);
  cleanup.push(r.unmount);
  return r;
}

function byLabel<T extends Element>(label: string): T {
  const el = document.querySelector(`[aria-label="${label}"]`);
  assert.ok(el, `no element labelled ${label}`);
  return el as T;
}

function posts(calls: Call[]): Call[] {
  return calls.filter((c) => c.method === 'POST' && c.url === '/api/apps');
}

// ----- the create drawer -----------------------------------------------------

type CreateAnswer = (call: Call) => Response;

// The catalog page with one online node, whose POST /api/apps answers with
// `answer` (default: 201 with the created app). An answer that throws is a
// request that never reached the api: the stubbed fetch rejects.
async function openCreate(answer: CreateAnswer = () => json(201, makeApp())): Promise<{ calls: Call[] }> {
  const f = stubFetch((c: Call) => {
    if (c.method === 'GET' && c.url === '/api/catalog') return json(200, []);
    if (c.method === 'GET' && c.url === '/api/nodes') return json(200, [NODE]);
    if (c.method === 'POST' && c.url === '/api/apps') return answer(c);
    return undefined;
  });
  const r = await mount(<AppCatalogPage />, f);
  await click(button(r.container, 'NEW CUSTOM APP'));
  return { calls: f.calls };
}

async function fillAndAdd(port: string | null): Promise<void> {
  await type(byLabel<HTMLInputElement>('App name'), 'whoami');
  await type(byLabel<HTMLTextAreaElement>('Docker Compose YAML') as unknown as HTMLInputElement, 'services: {}');
  if (port !== null) await type(byLabel<HTMLInputElement>('Web port'), port);
  await click(button(document.body, 'ADD APP'));
}

function createError(): string {
  const el = document.querySelector('[role="alert"]');
  assert.ok(el, 'no error shown');
  return (el.textContent ?? '').trim();
}

describe('the create drawer', () => {
  // TC-1090-10
  test('has a web-port field between name/target and compose, and sends a typed port as a number', async () => {
    const { calls } = await openCreate();
    const port = byLabel<HTMLInputElement>('Web port');
    const name = byLabel('App name');
    const target = byLabel('Target node');
    const compose = byLabel('Docker Compose YAML');
    assert.ok(name.compareDocumentPosition(port) & Node_FOLLOWING);
    assert.ok(target.compareDocumentPosition(port) & Node_FOLLOWING);
    assert.ok(port.compareDocumentPosition(compose) & Node_FOLLOWING);
    // The label and hint say which port it is (Bryce, 2026-11-22).
    assert.ok(document.body.textContent?.includes(LABEL));
    assert.ok(document.body.textContent?.includes(`Optional. ${MEANING} Leave it empty if the app has no web page.`));

    await fillAndAdd('8080');
    assert.equal(posts(calls).length, 1);
    const body = JSON.parse(posts(calls)[0].body!);
    assert.deepEqual(body, { name: 'whoami', targetNode: 'node-1', composeYaml: 'services: {}', webPort: 8080 });
    assert.equal(typeof body.webPort, 'number');
  });

  // TC-1090-11
  for (const port of [null, '   ']) {
    test(`an empty field sends no webPort (${port === null ? 'untouched' : 'spaces'})`, async () => {
      const { calls } = await openCreate();
      await fillAndAdd(port);
      assert.equal(posts(calls).length, 1);
      assert.deepEqual(Object.keys(JSON.parse(posts(calls)[0].body!)), ['name', 'targetNode', 'composeYaml']);
    });
  }

  // TC-1090-12
  test('text that is not a number reaches the api as text', async () => {
    const { calls } = await openCreate();
    await fillAndAdd('abc');
    assert.strictEqual(JSON.parse(posts(calls)[0].body!).webPort, 'abc');
  });

  // TC-1090-13
  test('a coded refusal shows the api sentence alone and keeps what was typed', async () => {
    await openCreate(() => json(400, CODED));
    await fillAndAdd('70000');
    assert.equal(createError(), SENTENCE);
    const text = document.body.textContent ?? '';
    for (const bad of ['/api/apps', '→', 'ApiError', '400']) assert.ok(!text.includes(bad), `drawer shows ${bad}`);
    assert.equal(byLabel<HTMLInputElement>('App name').value, 'whoami');
    assert.equal(byLabel<HTMLTextAreaElement>('Docker Compose YAML').value, 'services: {}');
    assert.equal(byLabel<HTMLInputElement>('Web port').value, '70000');
    assert.equal(button(document.body, 'ADD APP').disabled, false);
  });

  // TC-1090-14
  test('an uncoded refusal also loses the URL and status arrow', async () => {
    await openCreate(() => json(409, { error: 'an app with that name already exists' }));
    await fillAndAdd('8080');
    assert.equal(createError(), 'an app with that name already exists');
    const text = document.body.textContent ?? '';
    assert.ok(!text.includes('/api/apps'));
    assert.ok(!text.includes('→'));
  });

  // TC-1090-15 (F-1090-01)
  const failures: Array<[string, CreateAnswer]> = [
    [
      'never reached',
      () => {
        throw new TypeError('Failed to fetch');
      },
    ],
    ['502 with no JSON', () => new Response('<html>bad gateway</html>', { status: 502, headers: { 'Content-Type': 'text/html' } })],
  ];
  for (const [what, answer] of failures) {
    test(`a create with no reason shows one neutral sentence (${what})`, async () => {
      await openCreate(answer);
      await fillAndAdd('8080');
      const shown = createError();
      assert.equal(shown, CREATE_APP_FAILED);
      assert.match(shown, /^[A-Z].*\.$/);
      for (const bad of ['TypeError', 'Failed to fetch', '/api/apps', '→', 'gave no reason']) assert.ok(!shown.includes(bad), `shows ${bad}`);
    });
  }
});

// Node.DOCUMENT_POSITION_FOLLOWING, without naming the DOM's Node beside the
// api's Node type.
const Node_FOLLOWING = 4;

// ----- the edit modal ----------------------------------------------------------

async function openModal(app: App, kind: 'edit' | 'upgrade' | 'revert', answer?: (c: Call) => Response): Promise<Call[]> {
  const f = stubFetch((c: Call) => {
    if (c.method === 'PUT' && c.url === `/api/apps/${APP_ID}/compose`) return answer ? answer(c) : json(202, { id: 'job', status: 'pending' });
    if (c.method === 'GET' && c.url === `/api/apps/${APP_ID}/volumes`) return json(200, { appId: APP_ID, appName: app.name, classified: true, volumes: [] });
    return undefined;
  });
  await mount(<ComposeChangeModal app={app} kind={kind} onFinished={() => {}} onClose={() => {}} />, f);
  return f.calls;
}

function puts(calls: Call[]): Call[] {
  return calls.filter((c) => c.method === 'PUT');
}

function portInput(): HTMLInputElement {
  return byLabel<HTMLInputElement>('Web port');
}

function composeInput(app: App): HTMLInputElement {
  return byLabel<HTMLInputElement>(`Compose for ${app.name}`);
}

describe('the edit modal', () => {
  // TC-1090-16
  test('has a labelled field that starts from the stored port and sends a changed one', async () => {
    const app = makeApp({ publishedPort: 8080 });
    const calls = await openModal(app, 'edit');
    const input = portInput();
    const label = Array.from(document.querySelectorAll('label')).find((l) => (l.textContent ?? '').trim() === LABEL);
    assert.ok(label, 'no WEB PORT label');
    assert.equal(label.getAttribute('for'), input.id);
    assert.equal(input.value, '8080');
    assert.ok(document.body.textContent?.includes(`${MEANING} Leave it empty to keep the current port.`));

    await type(input, '9090');
    await click(button(document.body, 'REDEPLOY'));
    assert.equal(puts(calls).length, 1);
    assert.deepEqual(JSON.parse(puts(calls)[0].body!), { composeYaml: app.composeYaml, webPort: 9090 });
  });

  // TC-1090-17
  test('a compose-only edit sends the stored port unchanged', async () => {
    const app = makeApp({ publishedPort: 8080 });
    const calls = await openModal(app, 'edit');
    await type(composeInput(app), 'services: {}');
    await click(button(document.body, 'REDEPLOY'));
    assert.deepEqual(JSON.parse(puts(calls)[0].body!), { composeYaml: 'services: {}', webPort: 8080 });
  });

  // TC-1090-18
  test('an app with no port starts empty and sends compose only', async () => {
    const app = makeApp();
    const calls = await openModal(app, 'edit');
    assert.equal(portInput().value, '');
    await click(button(document.body, 'REDEPLOY'));
    assert.deepEqual(Object.keys(JSON.parse(puts(calls)[0].body!)), ['composeYaml']);
  });

  // TC-1090-19
  test('a cleared field keeps the stored port and says so', async () => {
    const app = makeApp({ publishedPort: 8080 });
    const calls = await openModal(app, 'edit');
    await type(portInput(), '');
    await click(button(document.body, 'REDEPLOY'));
    assert.equal('webPort' in JSON.parse(puts(calls)[0].body!), false);
    assert.ok(document.body.textContent?.includes('Leave it empty to keep the current port.'));
  });

  // TC-1090-20
  test('a coded refusal shows the api sentence alone and keeps the modal open', async () => {
    const app = makeApp({ publishedPort: 8080 });
    await openModal(app, 'edit', () => json(400, CODED));
    await type(portInput(), '0');
    await click(button(document.body, 'REDEPLOY'));
    const alert = document.querySelector('[role="alert"]');
    assert.ok(alert, 'no alert');
    assert.equal(alert.textContent, SENTENCE);
    assert.ok(!(alert.textContent ?? '').includes('malformed'));
    assert.ok(document.querySelector('[role="dialog"]'), 'the modal closed');
    assert.equal(portInput().value, '0');
  });
});

describe('the upgrade and revert confirms', () => {
  // TC-1090-21
  for (const kind of ['upgrade', 'revert'] as const) {
    test(`${kind} has no web-port field`, async () => {
      const app = makeApp({
        publishedPort: 8080,
        sourceTile: 'whoami',
        upgradeAvailable: true,
        revertAvailable: true,
        previousComposeSha256: 'a'.repeat(64),
      });
      await openModal(app, kind);
      const dialog = document.querySelector('[role="dialog"]');
      assert.ok(dialog, 'no dialog');
      assert.equal(dialog.querySelector('[aria-label="Web port"]'), null);
      assert.ok(!Array.from(dialog.querySelectorAll('label')).some((l) => (l.textContent ?? '').includes('WEB PORT')));
      assert.ok(!(dialog.textContent ?? '').includes('WEB PORT'));
    });
  }
});
