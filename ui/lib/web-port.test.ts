// geekdojo/geekdojo-brain#1090: the WEB PORT field's text, turned into the
// contract's webPort. The api is the one validator, so these prove only what
// is sent: nothing for an empty field, a number for a number, and the text
// itself otherwise, never NaN or null.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { webPortValue } from './web-port';

describe('webPortValue', () => {
  // TC-1090-01
  test('empty or whitespace-only text means no port', () => {
    for (const t of ['', '  ', '\t']) assert.equal(webPortValue(t), undefined, JSON.stringify(t));
  });

  // TC-1090-02
  test('a typed number is sent as a number', () => {
    const cases: Array<[string, number]> = [
      ['8080', 8080],
      [' 443 ', 443],
      ['65535', 65535],
    ];
    for (const [t, want] of cases) {
      const got = webPortValue(t);
      assert.strictEqual(got, want);
      assert.equal(typeof got, 'number');
    }
  });

  // TC-1090-03
  test('numbers out of range are passed through unchanged for the api to refuse', () => {
    const cases: Array<[string, number]> = [
      ['0', 0],
      ['-1', -1],
      ['80.5', 80.5],
      ['70000', 70000],
    ];
    for (const [t, want] of cases) assert.strictEqual(webPortValue(t), want);
  });

  // TC-1090-04
  test('text that is not a number is sent as the trimmed text, never NaN or null', () => {
    const cases: Array<[string, string]> = [
      ['abc', 'abc'],
      [' abc ', 'abc'],
      ['1e400', '1e400'],
      ['Infinity', 'Infinity'],
    ];
    for (const [t, want] of cases) {
      const r = webPortValue(t);
      assert.strictEqual(r, want);
      assert.ok(!JSON.stringify({ webPort: r }).includes('null'), `null on the wire for ${t}`);
    }
  });
});
