import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { ApiError } from './api';
import {
  draftsAfterSave,
  footerNote,
  pendingWrites,
  redeployAfterSave,
  saveNote,
  saveOperatorSecrets,
  saveThenDeploy,
  secretFieldView,
  type SaveDeps,
  type SaveResult,
  type SecretWrite,
} from './operator-secrets';
import type { AppStatus, Job, OperatorSecretStatus } from './types';

// geekdojo/geekdojo-brain#781: what the Apps drawer and the install footer
// decide about owner-supplied secrets, executed with fake put/deploy.

const SENTINEL = 'Qz7Xv9Kj4W';
const VENDOR = /openbao|\bbao\b|vault|hashicorp/i;
const VALUE_REFUSED =
  'The value was refused. It must not be empty, must not contain a NUL byte, and must not be a date and time in RFC 3339 form.';

const job: Job = {
  id: '01JOB',
  kind: 'app.deploy',
  spec: { appId: '01APP' },
  status: 'queued',
  createdBy: 'operator',
  createdAt: '2026-10-30T10:00:00Z',
};

// Every string produced in this file, for the TC-781-02 vendor scan and the
// TC-781-11 value scan at the end.
const produced: string[] = [];
function record(r: SaveResult, note: string | null): void {
  produced.push(JSON.stringify(r));
  if (note !== null) produced.push(note);
}

type Call = string;
function fakes(opts: { refuse?: Record<string, unknown>; deployFails?: unknown } = {}): SaveDeps & { log: Call[] } {
  const log: Call[] = [];
  return {
    log,
    put: async (name) => {
      log.push(`put(${name})`);
      if (opts.refuse && name in opts.refuse) throw opts.refuse[name];
    },
    deploy: async () => {
      log.push('deploy');
      if (opts.deployFails !== undefined) throw opts.deployFails;
      return job;
    },
  };
}

function w(name: string, value = SENTINEL): SecretWrite {
  return { name, label: `${name.toUpperCase()} label`, value };
}

function assertNoUrl(s: string): void {
  assert.ok(!s.includes('/api/'), s);
  assert.ok(!s.includes('→'), s);
  assert.ok(!s.includes('HTTP'), s);
}

describe('secretFieldView', () => {
  // TC-781-01
  test('a set secret is SET with the keep placeholder, required or optional', () => {
    assert.deepEqual(secretFieldView({ set: true, required: true }), {
      marker: 'SET',
      need: 'required',
      placeholder: 'Set — leave blank to keep',
    });
    assert.deepEqual(secretFieldView({ set: true, required: false }), {
      marker: 'SET',
      need: 'optional',
      placeholder: 'Set — leave blank to keep',
    });
  });

  // TC-781-02
  test('an unset secret is NOT SET, and says whether a deploy needs it', () => {
    const req = secretFieldView({ set: false, required: true });
    const opt = secretFieldView({ set: false, required: false });
    assert.equal(req.marker, 'NOT SET');
    assert.equal(opt.marker, 'NOT SET');
    assert.equal(req.placeholder, 'Not set — required before this app can deploy');
    assert.equal(opt.placeholder, 'Not set — optional');
    for (const v of [req, opt, secretFieldView({ set: true, required: true })]) {
      for (const s of Object.values(v)) assert.doesNotMatch(s, VENDOR);
    }
  });
});

describe('pendingWrites', () => {
  // TC-781-03
  const statuses: OperatorSecretStatus[] = [
    { name: 'set-key', label: 'Set key', required: true, set: true },
    { name: 'unset-key', label: 'Unset key', required: true, set: false },
    { name: 'opt-key', label: 'Optional key', required: false, set: false },
  ];

  test('an empty field keeps the stored value; undeclared names are dropped; a space is a value', () => {
    assert.deepEqual(pendingWrites(statuses, { 'set-key': '', 'unset-key': 'v', 'opt-key': ' ', extra: 'x' }), [
      { name: 'unset-key', label: 'Unset key', value: 'v' },
      { name: 'opt-key', label: 'Optional key', value: ' ' },
    ]);
  });

  test('declaration order, not draft order', () => {
    assert.deepEqual(
      pendingWrites(statuses, { 'opt-key': 'b', 'unset-key': 'a' }).map((x) => x.name),
      ['unset-key', 'opt-key'],
    );
  });

  test('all drafts empty, or none, writes nothing', () => {
    assert.deepEqual(pendingWrites(statuses, { 'set-key': '', 'unset-key': '', 'opt-key': '' }), []);
    assert.deepEqual(pendingWrites(statuses, {}), []);
  });
});

describe('saveOperatorSecrets (the drawer SAVE)', () => {
  // TC-781-04
  test('nothing to write: no put, no deploy', async () => {
    const f = fakes();
    const r = await saveOperatorSecrets([], true, f);
    assert.deepEqual(f.log, []);
    assert.deepEqual(r.saved, []);
    assert.equal(r.job, undefined);
  });

  // TC-781-05
  test('a change starts one redeploy, after every write', async () => {
    const f = fakes();
    const r = await saveOperatorSecrets([w('a'), w('b')], true, f);
    assert.deepEqual(f.log, ['put(a)', 'put(b)', 'deploy']);
    assert.deepEqual(r.saved, ['a', 'b']);
    assert.deepEqual(r.unsaved, []);
    assert.equal(r.job, job);
    const note = saveNote(r);
    assert.equal(note, 'Saved. A redeploy has started so the app picks up the change.');
    record(r, note);
  });

  // TC-781-06
  test('no redeploy when one is not due', async () => {
    const f = fakes();
    const r = await saveOperatorSecrets([w('a'), w('b')], false, f);
    assert.deepEqual(f.log, ['put(a)', 'put(b)']);
    const note = saveNote(r);
    assert.equal(note, 'Saved. It takes effect the next time the app is deployed.');
    record(r, note);
  });

  // TC-781-07
  test('a refused write stops the save and deploys nothing', async () => {
    const refusal = new ApiError(VALUE_REFUSED, 400, VALUE_REFUSED);
    const f = fakes({ refuse: { b: refusal } });
    const r = await saveOperatorSecrets([w('a'), w('b'), w('c')], true, f);
    assert.deepEqual(f.log, ['put(a)', 'put(b)']);
    assert.deepEqual(r.saved, ['a']);
    assert.deepEqual(r.unsaved, ['b', 'c']);
    assert.equal(r.failed?.label, 'B label');
    const note = saveNote(r);
    assert.equal(note, `B label was not saved. ${VALUE_REFUSED}`);
    assert.ok(!note.includes('/api/') && !note.includes('→'), note);
    record(r, note);
    produced.push(refusal.message);
  });

  // TC-781-08
  test('a write that fails at the network deploys nothing and says so in a sentence', async () => {
    const f = fakes({ refuse: { a: new TypeError('Failed to fetch') } });
    const r = await saveOperatorSecrets([w('a')], true, f);
    assert.deepEqual(f.log, ['put(a)']);
    const note = saveNote(r);
    assert.equal(note, 'A label was not saved. The secret could not be saved.');
    assertNoUrl(note);
    record(r, note);
  });

  // TC-781-09 (F-781-02)
  test('saved but the redeploy refused: the api sentence, never the request URL', async () => {
    const refused = new ApiError('/api/apps/01JAPP/deploy → 400: x', 400, 'x');
    const f = fakes({ deployFails: refused });
    const r = await saveOperatorSecrets([w('a'), w('b')], true, f);
    assert.deepEqual(r.saved, ['a', 'b']);
    assert.equal(r.deployError, 'x');
    const note = saveNote(r);
    assert.equal(note, 'Saved, but the redeploy did not start: x Deploy the app to apply it.');
    assertNoUrl(note);
    record(r, note);
  });

  // TC-781-09 (F-781-02), the network case
  test('saved but the redeploy never reached the api: a fixed sentence', async () => {
    const f = fakes({ deployFails: new TypeError('Failed to fetch') });
    const r = await saveOperatorSecrets([w('a')], true, f);
    assert.deepEqual(r.saved, ['a']);
    const note = saveNote(r);
    assert.equal(
      note,
      'Saved, but the redeploy did not start: The deploy request did not reach the control plane. Deploy the app to apply it.',
    );
    assertNoUrl(note);
    record(r, note);
  });
});

describe('redeployAfterSave', () => {
  // TC-781-10
  const want: Record<AppStatus, boolean> = {
    running: true,
    failed: true,
    stopped: false,
    unknown: false,
    deploying: false,
    stopping: false,
  };
  for (const [status, expected] of Object.entries(want) as [AppStatus, boolean][]) {
    test(`${status} → ${expected}`, () => assert.equal(redeployAfterSave(status), expected));
  }
});

describe('saveThenDeploy (the install footer DEPLOY NOW)', () => {
  // TC-781-16 (a)
  test('typed values are saved, then one deploy', async () => {
    const f = fakes();
    const r = await saveThenDeploy([w('required-key'), w('optional-key')], f);
    assert.deepEqual(f.log, ['put(required-key)', 'put(optional-key)', 'deploy']);
    assert.equal(r.job, job);
    assert.equal(footerNote(r), null);
    record(r, null);
  });

  // TC-781-16 (b)
  test('a refused write deploys nothing and keeps the draft', async () => {
    const f = fakes({ refuse: { 'required-key': new ApiError(VALUE_REFUSED, 400, VALUE_REFUSED) } });
    const r = await saveThenDeploy([w('required-key'), w('optional-key')], f);
    assert.deepEqual(f.log, ['put(required-key)']);
    assert.deepEqual(r.unsaved, ['required-key', 'optional-key']);
    assert.equal(r.job, undefined);
    const note = footerNote(r);
    assert.equal(note, `REQUIRED-KEY label was not saved. ${VALUE_REFUSED}`);
    record(r, note);
    // The kept draft survives the post-save clear.
    assert.deepEqual(draftsAfterSave({ 'required-key': SENTINEL, 'optional-key': 'o' }, r), {
      'required-key': SENTINEL,
      'optional-key': 'o',
    });
  });

  // TC-781-16 (c)
  test('nothing typed: no put, one deploy — the footer as it was', async () => {
    const f = fakes();
    const r = await saveThenDeploy([], f);
    assert.deepEqual(f.log, ['deploy']);
    assert.equal(r.job, job);
  });

  test('saved, but the deploy refused: a sentence, and nothing left to re-save', async () => {
    const f = fakes({ deployFails: new ApiError('/api/apps/01JAPP/deploy → 409: busy', 409, 'busy') });
    const r = await saveThenDeploy([w('required-key')], f);
    const note = footerNote(r);
    assert.equal(note, 'The deploy did not start: busy');
    assertNoUrl(note ?? '');
    assert.deepEqual(draftsAfterSave({ 'required-key': SENTINEL }, r), {});
    record(r, note);
  });
});

describe('draftsAfterSave', () => {
  test('a saved draft is cleared, others are kept', () => {
    assert.deepEqual(draftsAfterSave({ a: 'x', b: 'y', c: '' }, { saved: ['a'] }), { b: 'y', c: '' });
  });
});

// Runs after every describe above has recorded its strings (node:test runs
// top-level suites in order).
describe('every produced string', () => {
  // TC-781-02: vendor-neutral copy on every path.
  test('names no vendor', () => {
    assert.ok(produced.length >= 8, `expected the paths above to record their strings, got ${produced.length}`);
    for (const s of produced) assert.doesNotMatch(s, VENDOR);
  });

  // TC-781-11: no value, nor any 4-character piece of one, in any UI text.
  test('holds no piece of the value', () => {
    for (const s of produced) {
      for (let i = 0; i + 4 <= SENTINEL.length; i++) {
        const piece = SENTINEL.slice(i, i + 4);
        assert.ok(!s.includes(piece), `found ${piece} in ${s}`);
      }
    }
  });
});
