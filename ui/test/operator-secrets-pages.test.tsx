// The DOM must exist before react-dom loads: keep this import first.
import { button, click, json, render, stubFetch, type, type Call, type Rendered } from './dom';
import assert from 'node:assert/strict';
import { afterEach, describe, test } from 'node:test';
import type { ReactElement } from 'react';
import type { App, AppStatus, CatalogTile, Node, OperatorSecretStatus } from '../lib/types';
import AppsPage from '../app/(authed)/apps/page';
import AppCatalogPage from '../app/(authed)/app-catalog/page';

// geekdojo/geekdojo-brain#781 on the real pages: the Apps drawer's SECRETS
// section and the install footer's DEPLOY NOW, rendered whole, against a fake
// api behind a stubbed fetch. These prove the wiring between the pages and
// lib/operator-secrets.ts (which lib's own tests prove in isolation): which
// requests go out, in what order, and what the operator is shown.

const SENTINEL = 'Qz7Xv9Kj4W';
const APP_ID = '01JAPPID0000000000000000AB';
const JOB_ID = '01JJOBID0000000000000000CD';
const REFUSAL = 'The value was refused. It must not be empty, must not contain a NUL byte, and must not be a date and time in RFC 3339 form.';

function makeApp(status: AppStatus): App {
  return {
    id: APP_ID,
    name: 'shadowbroker',
    composeYaml: 'services: {}',
    targetNode: 'node-1',
    sourceTile: 'shadowbroker',
    lastStatus: status,
    createdAt: '2026-10-30T00:00:00Z',
    updatedAt: '2026-10-30T00:00:00Z',
  };
}

const TILE: CatalogTile = {
  id: 'shadowbroker',
  name: 'shadowbroker',
  tagline: 'Signals on a map.',
  collection: 'show-off',
  arch: 'both',
  ramFloorMB: 512,
  exposureDefault: 'tailnet',
  ports: [],
  composeYaml: 'services: {}',
};

const NODE: Node = {
  id: 'node-1',
  role: 'compute',
  hostname: 'node-1',
  agentVersion: 'dev',
  firstSeen: '2026-10-30T00:00:00Z',
  lastSeen: '2026-10-30T00:00:00Z',
  status: 'online',
};

// fakeApi answers the routes these pages read, and keeps the secrets' SET
// markers the way the api does: a stored value marks its name set.
function fakeApi(opts: { status: AppStatus; secrets: OperatorSecretStatus[]; refusePut?: string }) {
  const secrets = opts.secrets.map((s) => ({ ...s }));
  const app = makeApp(opts.status);
  const secretsPath = `/api/apps/${APP_ID}/secrets`;
  const f = stubFetch((c: Call) => {
    if (c.method === 'GET' && c.url === '/api/apps') return json(200, [app]);
    if (c.method === 'GET' && c.url === secretsPath) return json(200, secrets);
    if (c.method === 'PUT' && c.url.startsWith(`${secretsPath}/`)) {
      const name = decodeURIComponent(c.url.slice(secretsPath.length + 1));
      if (name === opts.refusePut) return json(400, { error: REFUSAL, code: 'secret_value_invalid' });
      const s = secrets.find((x) => x.name === name);
      if (!s) return json(404, { error: 'This app declares no such secret.' });
      s.set = true;
      return json(204);
    }
    if (c.method === 'POST' && c.url === `/api/apps/${APP_ID}/deploy`) {
      return json(202, { id: JOB_ID, kind: 'app.deploy', spec: { appId: APP_ID }, status: 'pending', createdBy: 'op', createdAt: '2026-10-30T00:00:00Z' });
    }
    if (c.method === 'GET' && c.url === '/api/catalog') return json(200, [TILE]);
    if (c.method === 'GET' && c.url === '/api/nodes') return json(200, [NODE]);
    if (c.method === 'POST' && c.url === `/api/catalog/${TILE.id}/install`) return json(201, app);
    return undefined;
  });
  return f;
}

const REQUIRED: OperatorSecretStatus = { name: 'feed-key', label: 'Feed key', required: true, set: false };
const OPTIONAL: OperatorSecretStatus = { name: 'map-key', label: 'Map key', required: false, set: false };

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

function input(name: string): HTMLInputElement {
  const el = document.querySelector(`#operator-secret-${name}`);
  assert.ok(el, `no input for ${name}`);
  return el as HTMLInputElement;
}

// The requests that changed something, in order: the secrets and the deploy.
function writes(calls: Call[]): string[] {
  return calls.filter((c) => c.method !== 'GET').map((c) => `${c.method} ${c.url}`);
}

// TC-781-11 rendered: no 4-character piece of the value anywhere the operator
// or a log could see it — the document's markup and text, and every request URL.
function assertNoValue(calls: Call[]): void {
  const surfaces = [document.body.innerHTML, document.body.textContent ?? '', ...calls.map((c) => c.url)];
  for (let i = 0; i + 4 <= SENTINEL.length; i++) {
    const piece = SENTINEL.slice(i, i + 4);
    for (const s of surfaces) assert.ok(!s.includes(piece), `found ${piece} in ${s.slice(0, 120)}`);
  }
  for (const el of Array.from(document.querySelectorAll('input'))) assert.equal((el as HTMLInputElement).value.includes(SENTINEL), false);
}

async function openDrawer(r: Rendered): Promise<void> {
  await click(button(r.container, 'Details for shadowbroker'));
}

const SAVE = 'Save secrets of shadowbroker';

describe('Apps drawer SECRETS', () => {
  test('SAVE is disabled until a value is typed', async () => {
    const f = fakeApi({ status: 'running', secrets: [REQUIRED] });
    const r = await mount(<AppsPage />, f);
    await openDrawer(r);
    assert.ok(document.body.textContent?.includes('SECRETS'));
    assert.equal(button(document.body, SAVE).disabled, true);
    await type(input('feed-key'), SENTINEL);
    assert.equal(button(document.body, SAVE).disabled, false);
    await type(input('feed-key'), '');
    assert.equal(button(document.body, SAVE).disabled, true);
  });

  test('an app that declares no secret has no SECRETS section', async () => {
    const f = fakeApi({ status: 'running', secrets: [] });
    const r = await mount(<AppsPage />, f);
    await openDrawer(r);
    assert.ok(document.body.textContent?.includes('LAN ACCESS'), 'the drawer is open');
    assert.ok(!document.body.textContent?.includes('SECRETS'));
    assert.equal(document.querySelectorAll('input[type="password"]').length, 0);
  });

  // TC-781-05 and TC-781-11 through the drawer.
  test('a save on a running app PUTs, then deploys once, and links the task', async () => {
    const f = fakeApi({ status: 'running', secrets: [REQUIRED] });
    const r = await mount(<AppsPage />, f);
    await openDrawer(r);
    await type(input('feed-key'), SENTINEL);
    await click(button(document.body, SAVE));

    assert.deepEqual(writes(f.calls), [`PUT /api/apps/${APP_ID}/secrets/feed-key`, `POST /api/apps/${APP_ID}/deploy`]);
    assert.equal(f.calls.find((c) => c.method === 'PUT')?.body, JSON.stringify({ value: SENTINEL }));
    assert.equal(document.querySelector('[role="status"]')?.textContent, 'Saved. A redeploy has started so the app picks up the change.');
    const link = document.querySelector('a[aria-label="View the redeploy task"]');
    assert.equal(link?.getAttribute('href'), `/tasks?id=${JOB_ID}`);
    // The input is empty and the marker re-read from the api says SET.
    assert.equal(input('feed-key').value, '');
    assert.match(input('feed-key').parentElement?.textContent ?? '', /Feed keyfeed-keySETrequired/);
    assertNoValue(f.calls);
  });

  // TC-781-06 through the drawer.
  test('a save on a stopped app stores the value and starts nothing', async () => {
    const f = fakeApi({ status: 'stopped', secrets: [REQUIRED] });
    const r = await mount(<AppsPage />, f);
    await openDrawer(r);
    await type(input('feed-key'), SENTINEL);
    await click(button(document.body, SAVE));

    assert.deepEqual(writes(f.calls), [`PUT /api/apps/${APP_ID}/secrets/feed-key`]);
    assert.equal(document.querySelector('[role="status"]')?.textContent, 'Saved. It takes effect the next time the app is deployed.');
    assert.equal(document.querySelector('a[aria-label="View the redeploy task"]'), null);
    assertNoValue(f.calls);
  });

  // TC-781-03 through the drawer: empty keeps stored.
  test('a field left blank sends no PUT', async () => {
    const f = fakeApi({ status: 'stopped', secrets: [{ ...REQUIRED, set: true }, OPTIONAL] });
    const r = await mount(<AppsPage />, f);
    await openDrawer(r);
    await type(input('map-key'), SENTINEL);
    await click(button(document.body, SAVE));

    assert.deepEqual(writes(f.calls), [`PUT /api/apps/${APP_ID}/secrets/map-key`]);
    assert.match(input('feed-key').parentElement?.textContent ?? '', /SETrequired/);
  });
});

// The install drawer, opened from the catalog and installed, ends in the footer.
async function installToFooter(r: Rendered): Promise<void> {
  await click(button(r.container, 'Install shadowbroker'));
  const install = Array.from(document.querySelectorAll('button[aria-label="Install shadowbroker"]')).pop();
  assert.ok(install, 'the install drawer has an INSTALL button');
  await click(install);
  assert.ok(document.body.textContent?.includes("It isn't running yet."), 'the footer shows');
}

describe('install footer DEPLOY NOW', () => {
  // TC-781-16(a) on the page (F-781-01): what was typed is saved before the one deploy.
  test('typed values are PUT before the one deploy', async () => {
    const f = fakeApi({ status: 'stopped', secrets: [REQUIRED, OPTIONAL] });
    const r = await mount(<AppCatalogPage />, f);
    await installToFooter(r);
    await type(input('feed-key'), SENTINEL);
    await type(input('map-key'), `${SENTINEL}-2`);
    await click(button(document.body, 'DEPLOY NOW'));

    assert.deepEqual(writes(f.calls), [
      `POST /api/catalog/${TILE.id}/install`,
      `PUT /api/apps/${APP_ID}/secrets/feed-key`,
      `PUT /api/apps/${APP_ID}/secrets/map-key`,
      `POST /api/apps/${APP_ID}/deploy`,
    ]);
    assert.ok(document.body.textContent?.includes('Deploying now…'));
    // The fields are gone with DEPLOY NOW, and nothing shows the value.
    assert.equal(document.querySelectorAll('input[type="password"]').length, 0);
    assertNoValue(f.calls);
  });

  // TC-781-16(b) on the page: a refused write deploys nothing and keeps the draft.
  test('a refused PUT deploys nothing, keeps the draft and DEPLOY NOW, and says why', async () => {
    const f = fakeApi({ status: 'stopped', secrets: [REQUIRED, OPTIONAL], refusePut: 'feed-key' });
    const r = await mount(<AppCatalogPage />, f);
    await installToFooter(r);
    await type(input('feed-key'), SENTINEL);
    await type(input('map-key'), 'optional-value');
    await click(button(document.body, 'DEPLOY NOW'));

    assert.deepEqual(writes(f.calls), [`POST /api/catalog/${TILE.id}/install`, `PUT /api/apps/${APP_ID}/secrets/feed-key`]);
    const text = document.body.textContent ?? '';
    assert.ok(text.includes(`Feed key was not saved. ${REFUSAL}`));
    assert.ok(!text.includes('/api/'));
    assert.ok(!text.includes('→'));
    assert.ok(!text.includes(SENTINEL));
    assert.ok(!text.includes('Deploying now…'));
    assert.equal(button(document.body, 'DEPLOY NOW').disabled, false);
    // The refused draft and the one after it are kept for another try.
    assert.equal(input('feed-key').value, SENTINEL);
    assert.equal(input('map-key').value, 'optional-value');
    assert.ok(f.calls.every((c) => !c.url.includes(SENTINEL)));
  });

  // TC-781-16(c) on the page: nothing typed is the old DEPLOY NOW, one deploy.
  test('with nothing typed, DEPLOY NOW deploys once and writes no secret', async () => {
    const f = fakeApi({ status: 'stopped', secrets: [{ ...REQUIRED, set: true }] });
    const r = await mount(<AppCatalogPage />, f);
    await installToFooter(r);
    await click(button(document.body, 'DEPLOY NOW'));

    assert.deepEqual(writes(f.calls), [`POST /api/catalog/${TILE.id}/install`, `POST /api/apps/${APP_ID}/deploy`]);
    assert.ok(document.body.textContent?.includes('Deploying now…'));
  });
});
