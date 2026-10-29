import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { changeColor, childFellBack, nodeUpdateColor, prettyStatus } from './update-status';
import type { NodeUpdate, NodeUpdateStatus } from './types';

// geekdojo/geekdojo-brain#894: a committed update the node later falls back
// from reads FALLEN BACK, in yellow, in History, the live feed and the System
// updates card.

const GREEN = '#4ade80';
const YELLOW = '#facc15';
const RED = '#f87171';

// TC-894-19: label and colours for fallen_back, and the existing outputs unchanged.
describe('update status label and colours', () => {
  test('fallen_back reads FALLEN BACK in yellow, not the committed green', () => {
    assert.equal(prettyStatus('fallen_back'), 'FALLEN BACK');
    assert.equal(nodeUpdateColor('fallen_back'), YELLOW);
    assert.equal(nodeUpdateColor('fallen_back'), nodeUpdateColor('rolled_back'));
    assert.notEqual(nodeUpdateColor('fallen_back'), GREEN);
    assert.equal(changeColor('fallen_back'), YELLOW);
  });

  test('existing statuses are unchanged', () => {
    assert.equal(nodeUpdateColor('committed'), GREEN);
    assert.equal(changeColor('committed'), GREEN);
    assert.equal(prettyStatus('committed'), 'COMMITTED');
    assert.equal(prettyStatus('rolled_back'), 'ROLLED BACK');
    assert.equal(nodeUpdateColor('rolled_back'), YELLOW);
    assert.equal(prettyStatus('in_progress'), 'IN PROGRESS');
    assert.equal(nodeUpdateColor('failed'), RED);
    assert.equal(changeColor('failed'), RED);
    assert.equal(prettyStatus('failed'), 'FAILED');
  });
});

function row(jobId: string, status: NodeUpdateStatus): NodeUpdate {
  return { jobId, nodeId: 'cp-firewall1', status } as NodeUpdate;
}

// F-894-03: the System updates card shows FALLEN BACK beside SUCCEEDED when
// the child job's History row has fallen back.
describe('childFellBack', () => {
  const history = [row('child-1', 'fallen_back'), row('child-2', 'committed'), row('other', 'fallen_back')];

  test('true when the child job\'s row is fallen_back', () => {
    assert.equal(childFellBack('child-1', history), true);
  });

  test('false when the child job\'s row is still committed', () => {
    assert.equal(childFellBack('child-2', history), false);
  });

  test('false for a child with no History row, or no child job', () => {
    assert.equal(childFellBack('child-3', history), false);
    assert.equal(childFellBack(undefined, history), false);
  });
});
