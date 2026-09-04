// The enroll form's advertise-route check, executed. The wording is asserted
// because it is shared with the api (mesh.ValidateAdvertiseRoutes): the
// operator must read one message whichever side catches it.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { canonicalCIDR, parseAdvertiseRoutes, validateAdvertiseRoute } from './cidr';

describe('canonicalCIDR', () => {
  test('masks host bits across prefix lengths', () => {
    assert.equal(canonicalCIDR('192.168.1.149/24').network, '192.168.1.0/24'); // the bench case
    assert.equal(canonicalCIDR('192.168.1.0/24').network, '192.168.1.0/24');
    assert.equal(canonicalCIDR('10.1.37.9/20').network, '10.1.32.0/20'); // mask inside an octet
    assert.equal(canonicalCIDR('172.16.200.7/12').network, '172.16.0.0/12');
    assert.equal(canonicalCIDR('192.168.1.149/32').network, '192.168.1.149/32'); // its own network
    assert.equal(canonicalCIDR('203.0.113.7/0').network, '0.0.0.0/0');
    assert.equal(canonicalCIDR('255.255.255.255/8').network, '255.0.0.0/8'); // sign bit stays unsigned
  });

  test('refuses what is not an IPv4 CIDR, naming the value', () => {
    for (const bad of ['', '192.168.1.0', '192.168.1.0/33', '192.168.256.0/24', 'lan', ' 192.168.1.0/24']) {
      const { network, error } = canonicalCIDR(bad);
      assert.equal(network, undefined, bad);
      assert.match(error ?? '', /not an IPv4 CIDR/, bad);
      assert.ok((error ?? '').includes(`"${bad}"`), `${bad}: error should quote the value`);
    }
  });

  test('refuses IPv6 (LOCKED decision #9)', () => {
    assert.match(canonicalCIDR('fd7a:115c:a1e0::/48').error ?? '', /IPv4-only/);
  });
});

describe('validateAdvertiseRoute', () => {
  test('a host address is refused with the network named, not rewritten', () => {
    assert.equal(
      validateAdvertiseRoute('192.168.1.149/24'),
      'advertise route "192.168.1.149/24" is a host address, not a network — advertise 192.168.1.0/24',
    );
  });

  test('a canonical network passes', () => {
    assert.equal(validateAdvertiseRoute('192.168.1.0/24'), null);
    assert.equal(validateAdvertiseRoute('10.1.32.0/20'), null);
    assert.equal(validateAdvertiseRoute('0.0.0.0/0'), null);
  });
});

describe('parseAdvertiseRoutes', () => {
  test('splits, trims and drops empties', () => {
    assert.deepEqual(parseAdvertiseRoutes(' 10.0.0.0/8, 192.168.1.0/24 ,'), {
      routes: ['10.0.0.0/8', '192.168.1.0/24'],
      error: null,
    });
    assert.deepEqual(parseAdvertiseRoutes(''), { routes: [], error: null });
  });

  test('reports the first bad entry and still lists the routes', () => {
    const r = parseAdvertiseRoutes('10.0.0.0/8, 10.1.37.9/20');
    assert.deepEqual(r.routes, ['10.0.0.0/8', '10.1.37.9/20']);
    assert.ok(r.error?.includes('"10.1.37.9/20"') && r.error.includes('10.1.32.0/20'), r.error ?? '');
  });
});
