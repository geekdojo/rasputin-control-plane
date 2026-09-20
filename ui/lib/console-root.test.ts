// The console root password's client-side rules (geekdojo/geekdojo-brain#587,
// decision #558). They mirror api/internal/console/password.go; the cases
// below are the same ones that package's tests cover, so a drift between the
// two shows up as a refusal the operator sees only after a round trip.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ConsoleRootNode, ConsoleRootStatus } from './api';
import {
  consoleDraftState,
  consoleSummary,
  MAX_CONSOLE_PASSWORD,
  MIN_CONSOLE_PASSWORD,
  readNode,
  validateConsolePassword,
} from './console-root';

const GOOD = 'a perfectly fine console password';

test('validateConsolePassword accepts what the api accepts', () => {
  for (const pw of [GOOD, 'twelve chars', 'påsswörd with ünicode', 'x'.repeat(MAX_CONSOLE_PASSWORD)]) {
    assert.equal(validateConsolePassword(pw), null, pw);
  }
});

test('validateConsolePassword says nothing about an empty field', () => {
  // Nothing typed yet is not an error — the save button is what is disabled.
  assert.equal(validateConsolePassword(''), null);
  assert.equal(consoleDraftState('', '').canSave, false);
  assert.equal(consoleDraftState('', '').error, undefined);
});

test('validateConsolePassword refuses what the api refuses', () => {
  const bad: Record<string, string> = {
    'eleven characters': 'x'.repeat(MIN_CONSOLE_PASSWORD - 1),
    'too long': 'x'.repeat(MAX_CONSOLE_PASSWORD + 1),
    newline: 'has a newline\nin it',
    'carriage return': 'has a return\rin it',
    tab: 'has a tab\tin it',
    nul: 'has a nul' + String.fromCharCode(0) + 'in it',
    escape: 'has an escape' + String.fromCharCode(27) + 'in it',
    'spaces only': ' '.repeat(MIN_CONSOLE_PASSWORD + 2),
  };
  for (const [name, pw] of Object.entries(bad)) {
    assert.notEqual(validateConsolePassword(pw), null, name);
  }
});

test('a password is counted in characters, not UTF-16 code units', () => {
  // Twelve emoji is twelve characters, though .length says 24. The api
  // counts runes, so the UI must not refuse what the api would take.
  assert.equal(validateConsolePassword('😀'.repeat(MIN_CONSOLE_PASSWORD)), null);
  assert.notEqual(validateConsolePassword('😀'.repeat(MIN_CONSOLE_PASSWORD - 1)), null);
});

test('consoleDraftState needs both entries to match before it offers a save', () => {
  assert.deepEqual(consoleDraftState(GOOD, GOOD), { canSave: true });
  assert.equal(consoleDraftState(GOOD, '').canSave, false);
  assert.equal(consoleDraftState(GOOD, 'something else').canSave, false);
  assert.equal(consoleDraftState(GOOD, 'something else').error, 'The two entries do not match.');
  assert.equal(consoleDraftState('short', 'short').canSave, false);
});

function node(nodeId: string, status: ConsoleRootNode['status'], hashId = '', detail = ''): ConsoleRootNode {
  return { nodeId, status, hashId, detail, updatedAt: '2026-09-19T00:00:00Z', current: false };
}

test('readNode calls out a node holding an older password', () => {
  assert.equal(readNode(node('cp', 'applied', 'aaa'), 'aaa'), 'applied');
  // The case a bare status hides: applied, but not to what is stored now.
  assert.equal(readNode(node('old', 'applied', 'bbb'), 'aaa'), 'stale');
  assert.equal(readNode(node('slow', 'pending'), 'aaa'), 'pending');
  assert.equal(readNode(node('bad', 'failed', '', 'old agent'), 'aaa'), 'failed');
});

test('consoleSummary counts anything not holding the current password as outstanding', () => {
  const status: ConsoleRootStatus = {
    set: true,
    hashId: 'aaa',
    nodes: [
      node('cp', 'applied', 'aaa'),
      node('compute1', 'applied', 'aaa'),
      node('stale1', 'applied', 'bbb'),
      node('slow', 'pending'),
      node('old', 'failed', '', 'the agent predates the verb'),
    ],
  };
  assert.deepEqual(consoleSummary(status), { applied: 2, outstanding: 3, total: 5 });
});

test('consoleSummary survives a status with no nodes yet', () => {
  assert.deepEqual(consoleSummary({ set: true, hashId: 'aaa', nodes: [] }), {
    applied: 0,
    outstanding: 0,
    total: 0,
  });
  assert.deepEqual(consoleSummary({ set: false } as ConsoleRootStatus), {
    applied: 0,
    outstanding: 0,
    total: 0,
  });
});
