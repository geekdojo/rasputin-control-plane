// geekdojo/geekdojo-brain#414: the Apps page's compose-change rules, executed.
//
//   - which of UPDATE AVAILABLE / UPGRADE / EDIT / REVERT an app offers;
//   - each PUT /api/apps/{id}/compose body, exactly;
//   - reading 202 / 200 / 409 (both shapes) / 400 / 413;
//   - the dropped-volume resubmit: nothing selected by default, only the
//     exact dropped set can be resubmitted, and the body is the same body
//     plus deleteVolumes;
//   - anonymous orphan rows are named by service and path;
//   - the two static strings, verbatim.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  DROP_SELECTION_DEFAULT,
  REVERT_PROMPT,
  UPGRADE_WARNING,
  bodyFor,
  canResubmitWithDeletions,
  canSubmitEdit,
  composeActions,
  composeErrorMessage,
  dropDeletionStatement,
  editBody,
  noopNote,
  orphanVolumeLabel,
  parseComposeResponse,
  revertBody,
  startedNote,
  toggleDropSelection,
  upgradeBody,
  withDeleteVolumes,
} from './compose-change';
import type { App, AppStatus, DroppedVolume } from './types';

const HASH = 'a'.repeat(64);

type ActionInput = Parameters<typeof composeActions>[0];

function app(over: Partial<ActionInput> = {}): ActionInput {
  return {
    sourceTile: 'immich',
    lastStatus: 'running',
    upgradeAvailable: false,
    revertAvailable: false,
    ...over,
  };
}

describe('the verbatim strings', () => {
  test('the upgrade warning', () => {
    assert.equal(UPGRADE_WARNING, 'Be sure you have reviewed changes on GitHub before upgrading!');
  });
  test('the revert prompt', () => {
    assert.equal(REVERT_PROMPT, 'Reverting does not restore your data and may cause unexpected behavior. Proceed?');
  });
});

describe('composeActions', () => {
  test('a catalog app with an upgrade shows the badge and UPGRADE', () => {
    const a = composeActions(app({ upgradeAvailable: true }));
    assert.deepEqual(a, { updateBadge: true, upgrade: true, edit: false, revert: false });
  });

  test('a catalog app with no upgrade shows nothing', () => {
    assert.deepEqual(composeActions(app()), { updateBadge: false, upgrade: false, edit: false, revert: false });
  });

  test('a catalog app is never offered EDIT', () => {
    for (const s of ['running', 'stopped', 'failed'] as AppStatus[]) {
      assert.equal(composeActions(app({ lastStatus: s, upgradeAvailable: true })).edit, false);
    }
  });

  test('a custom app is offered EDIT and never an upgrade, whatever the flag says', () => {
    for (const sourceTile of [undefined, '']) {
      const a = composeActions(app({ sourceTile, upgradeAvailable: true }));
      assert.equal(a.edit, true);
      assert.equal(a.updateBadge, false);
      assert.equal(a.upgrade, false);
    }
  });

  test('nothing new starts while a deploy or stop is mid-flight, but the badge stays', () => {
    for (const lastStatus of ['deploying', 'stopping'] as AppStatus[]) {
      const cat = composeActions(app({ lastStatus, upgradeAvailable: true }));
      assert.equal(cat.updateBadge, true);
      assert.equal(cat.upgrade, false);
      assert.equal(composeActions(app({ lastStatus, sourceTile: '' })).edit, false);
    }
  });

  test('REVERT for any app with a previous compose and its hash, whatever its status', () => {
    for (const lastStatus of ['running', 'stopped', 'failed'] as AppStatus[]) {
      for (const sourceTile of ['immich', '']) {
        assert.equal(
          composeActions(app({ lastStatus, sourceTile, revertAvailable: true, previousComposeSha256: HASH })).revert,
          true,
          `${lastStatus} ${sourceTile || 'custom'}`,
        );
      }
    }
  });

  test('a running app that upgraded offers REVERT beside its other actions', () => {
    assert.deepEqual(composeActions(app({ revertAvailable: true, previousComposeSha256: HASH })), {
      updateBadge: false,
      upgrade: false,
      edit: false,
      revert: true,
    });
    assert.deepEqual(composeActions(app({ sourceTile: '', revertAvailable: true, previousComposeSha256: HASH })), {
      updateBadge: false,
      upgrade: false,
      edit: true,
      revert: true,
    });
  });

  test('no REVERT without a previous compose, or without its hash', () => {
    assert.equal(composeActions(app({ lastStatus: 'failed', revertAvailable: false, previousComposeSha256: HASH })).revert, false);
    assert.equal(composeActions(app({ lastStatus: 'running', revertAvailable: false, previousComposeSha256: HASH })).revert, false);
    assert.equal(composeActions(app({ lastStatus: 'failed', revertAvailable: true })).revert, false);
    assert.equal(composeActions(app({ lastStatus: 'running', revertAvailable: true, previousComposeSha256: '' })).revert, false);
  });

  test('REVERT is hidden while a deploy or stop is mid-flight, like UPGRADE and EDIT', () => {
    for (const lastStatus of ['deploying', 'stopping'] as AppStatus[]) {
      for (const sourceTile of ['immich', '']) {
        assert.equal(composeActions(app({ lastStatus, sourceTile, revertAvailable: true, previousComposeSha256: HASH })).revert, false);
      }
    }
  });
});

describe('request bodies', () => {
  test('upgrade is {"source":"catalog"}', () => {
    assert.equal(JSON.stringify(upgradeBody()), '{"source":"catalog"}');
    assert.deepEqual(bodyFor('upgrade', {}), { source: 'catalog' });
  });

  test('edit carries the compose and nothing else', () => {
    const yaml = 'services:\n  web:\n    image: nginx\n';
    assert.equal(JSON.stringify(editBody(yaml)), JSON.stringify({ composeYaml: yaml }));
    assert.deepEqual(bodyFor('edit', {}, yaml), { composeYaml: yaml });
  });

  test('revert names the previous compose by hash', () => {
    assert.equal(JSON.stringify(revertBody({ revertAvailable: true, previousComposeSha256: HASH })), `{"sha256":"${HASH}"}`);
    assert.deepEqual(bodyFor('revert', { revertAvailable: true, previousComposeSha256: HASH }), { sha256: HASH });
  });

  test('revert refuses to build a body without a previous compose', () => {
    assert.throws(() => revertBody({ revertAvailable: false, previousComposeSha256: HASH }));
    assert.throws(() => revertBody({ revertAvailable: true }));
  });

  test('an empty or blank edit is not submittable', () => {
    assert.equal(canSubmitEdit(''), false);
    assert.equal(canSubmitEdit('  \n\t'), false);
    assert.equal(canSubmitEdit('services: {}'), true);
  });
});

describe('parseComposeResponse', () => {
  test('202 is a started job', () => {
    const job = { id: 'job-1', kind: 'app.upgrade', spec: {}, status: 'pending', createdBy: 'bryce', createdAt: '' };
    const o = parseComposeResponse(202, job);
    assert.equal(o.kind, 'started');
    assert.equal(o.kind === 'started' && o.job.id, 'job-1');
  });

  test('200 is a no-op, not a job', () => {
    const o = parseComposeResponse(200, { id: 'app-1', name: 'immich' } as App);
    assert.equal(o.kind, 'noop');
  });

  test('409 with droppedVolumes is the dropped-volume refusal', () => {
    const o = parseComposeResponse(409, {
      error: 'the change drops volumes',
      droppedVolumes: [
        { name: 'rasp_01abc_data', volume: 'data', backup: 'critical', lastCaptured: { generationId: 'g1', at: '2026-09-01T00:00:00Z' } },
        { name: 'rasp_01abc_cache', volume: 'cache', lastCaptured: null },
      ],
      notDropped: [],
    });
    assert.equal(o.kind, 'dropped');
    if (o.kind !== 'dropped') return;
    assert.deepEqual(Object.keys(o).sort(), ['dropped', 'kind', 'notDropped']);
    assert.deepEqual(o.dropped, [
      { name: 'rasp_01abc_data', volume: 'data', backup: 'critical', lastCaptured: { generationId: 'g1', at: '2026-09-01T00:00:00Z' } },
      { name: 'rasp_01abc_cache', volume: 'cache', lastCaptured: null },
    ]);
    assert.deepEqual(o.notDropped, []);
  });

  test("the dropped-volume refusal does not carry the API's raw error text", () => {
    const raw =
      'the new compose no longer declares 2 volume(s) this app has on disk: rasp_01abc_library, rasp_01abc_thumbs; name them in deleteVolumes to delete them';
    const o = parseComposeResponse(409, {
      error: raw,
      droppedVolumes: [
        { name: 'rasp_01abc_library', volume: 'library', lastCaptured: null },
        { name: 'rasp_01abc_thumbs', volume: 'thumbs', lastCaptured: null },
      ],
      notDropped: [],
    });
    assert.equal(o.kind, 'dropped');
    const text = JSON.stringify(o);
    assert.equal(text.includes(raw), false);
    assert.equal(text.includes('deleteVolumes'), false);
    assert.equal('message' in o, false);
  });

  test('a missing lastCaptured reads as never, and malformed rows are dropped', () => {
    const o = parseComposeResponse(409, { error: 'x', droppedVolumes: [{ name: 'rasp_a_b', volume: 'b' }, { nope: true }, 'junk'] });
    assert.equal(o.kind, 'dropped');
    if (o.kind === 'dropped') assert.deepEqual(o.dropped, [{ name: 'rasp_a_b', volume: 'b', lastCaptured: null }]);
  });

  test('409 with nothing dropped but notDropped is an explained refusal', () => {
    const o = parseComposeResponse(409, { error: 'names volumes it keeps', droppedVolumes: [], notDropped: ['rasp_a_keep'] });
    assert.equal(o.kind, 'error');
    if (o.kind === 'error') {
      assert.match(o.message, /refused: names volumes it keeps/);
      assert.match(o.message, /rasp_a_keep/);
    }
  });

  test('a plain 409 keeps the api reason', () => {
    const o = parseComposeResponse(409, { error: 'tile "immich" is not in the catalog in effect' });
    assert.deepEqual(o, { kind: 'error', status: 409, message: 'The change was refused: tile "immich" is not in the catalog in effect' });
  });

  test('400 says the request was malformed', () => {
    const o = parseComposeResponse(400, { error: 'composeYaml must not be empty' });
    assert.deepEqual(o, { kind: 'error', status: 400, message: 'The change was not accepted — the request was malformed: composeYaml must not be empty' });
  });

  test('413 names the 1 MiB limit', () => {
    const o = parseComposeResponse(413, { error: 'body larger than 1048576 bytes' });
    assert.equal(o.kind, 'error');
    if (o.kind === 'error') assert.match(o.message, /too large .* 1 MiB/);
  });

  test('a response with no body still reads', () => {
    assert.deepEqual(parseComposeResponse(413, undefined), { kind: 'error', status: 413, message: composeErrorMessage(413, '') });
    assert.equal(parseComposeResponse(502, undefined).kind, 'error');
    assert.equal(parseComposeResponse(404, { error: 'app not found' }).kind, 'error');
  });
});

describe('the dropped-volume resubmit', () => {
  const dropped: DroppedVolume[] = [
    { name: 'rasp_01abc_data', volume: 'data', backup: 'critical', lastCaptured: null },
    { name: 'rasp_01abc_media', volume: 'media', backup: 'state', lastCaptured: null },
  ];

  test('nothing is selected by default, and nothing selected cannot resubmit', () => {
    assert.deepEqual(DROP_SELECTION_DEFAULT, []);
    assert.equal(canResubmitWithDeletions(dropped, DROP_SELECTION_DEFAULT), false);
    assert.equal(dropDeletionStatement(dropped, DROP_SELECTION_DEFAULT), null);
  });

  test('only the exact dropped set can be resubmitted', () => {
    assert.equal(canResubmitWithDeletions(dropped, ['rasp_01abc_data']), false);
    assert.equal(canResubmitWithDeletions(dropped, ['rasp_01abc_data', 'rasp_01abc_media']), true);
    assert.equal(canResubmitWithDeletions(dropped, ['rasp_01abc_media', 'rasp_01abc_data']), true);
    assert.equal(canResubmitWithDeletions(dropped, ['rasp_01abc_data', 'rasp_01abc_media', 'rasp_01abc_other']), false);
    assert.equal(canResubmitWithDeletions(dropped, ['rasp_01abc_data', 'rasp_01abc_other']), false);
    assert.equal(canResubmitWithDeletions([], []), false);
  });

  test('toggling keeps the list order and toggles back', () => {
    let sel = toggleDropSelection(dropped, [], 'rasp_01abc_media');
    sel = toggleDropSelection(dropped, sel, 'rasp_01abc_data');
    assert.deepEqual(sel, ['rasp_01abc_data', 'rasp_01abc_media']);
    assert.deepEqual(toggleDropSelection(dropped, sel, 'rasp_01abc_data'), ['rasp_01abc_media']);
  });

  test('the resubmit is the same body plus deleteVolumes, for every variant', () => {
    const names = ['rasp_01abc_data', 'rasp_01abc_media'];
    assert.equal(JSON.stringify(withDeleteVolumes(upgradeBody(), names)), '{"source":"catalog","deleteVolumes":["rasp_01abc_data","rasp_01abc_media"]}');
    const yaml = 'services: {}\n';
    assert.deepEqual(withDeleteVolumes(editBody(yaml), names), { composeYaml: yaml, deleteVolumes: names });
    assert.deepEqual(withDeleteVolumes({ sha256: HASH }, names), { sha256: HASH, deleteVolumes: names });
  });

  test('a resubmit replaces an earlier deleteVolumes and never duplicates a name', () => {
    const earlier = withDeleteVolumes(upgradeBody(), ['rasp_01abc_gone']);
    assert.deepEqual(withDeleteVolumes(earlier, ['rasp_01abc_data', 'rasp_01abc_data']), { source: 'catalog', deleteVolumes: ['rasp_01abc_data'] });
  });

  test('the deletion statement names the selected volumes and says the data goes', () => {
    const s = dropDeletionStatement(dropped, ['rasp_01abc_data']);
    assert.ok(s);
    assert.match(s, /data in data will be permanently deleted/);
    assert.match(s, /cannot be undone/);
    assert.doesNotMatch(s, /media/);
  });
});

describe('what the page says afterwards', () => {
  test('a no-op is quiet and says up to date', () => {
    assert.equal(noopNote('upgrade', 'immich'), 'immich is already up to date.');
    assert.match(noopNote('edit', 'mc'), /nothing to redeploy/);
    assert.match(noopNote('revert', 'mc'), /nothing to revert/);
  });
  test('a start names the change', () => {
    assert.equal(startedNote('upgrade', 'immich'), 'Upgrade of immich started.');
    assert.equal(startedNote('edit', 'mc'), 'Redeploy of mc started.');
    assert.equal(startedNote('revert', 'mc'), 'Revert of mc started.');
  });
});

describe('orphanVolumeLabel', () => {
  const hex = 'f'.repeat(64);
  test('a named volume is its compose key', () => {
    assert.equal(orphanVolumeLabel({ name: 'rasp_01abc_data', volume: 'data' }), 'data');
  });
  test('an anonymous volume is named by service and path', () => {
    assert.equal(orphanVolumeLabel({ name: hex, volume: '', anonymous: true, service: 'valkey', path: '/data' }), 'valkey:/data (anonymous)');
  });
  test('with only one of service or path, that one', () => {
    assert.equal(orphanVolumeLabel({ name: hex, volume: '', anonymous: true, service: 'valkey' }), 'valkey (anonymous)');
    assert.equal(orphanVolumeLabel({ name: hex, volume: '', anonymous: true, path: '/data' }), '/data (anonymous)');
  });
  test('never an empty label', () => {
    assert.equal(orphanVolumeLabel({ name: hex, volume: '', anonymous: true }), `anonymous ${hex.slice(0, 12)}`);
  });
});
