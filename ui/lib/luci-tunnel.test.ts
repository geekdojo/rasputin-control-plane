// The SSH tunnel command the Advanced tab hands the operator. The exact string
// is asserted because the operator pastes it into a shell: a wrong port silently
// forwards to nothing, and an unchecked host would be a command they run.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  LUCI_LOCAL_PORT,
  LUCI_REMOTE_PORT,
  isSafeTunnelHost,
  luciLocalUrl,
  luciTunnelCommand,
} from './luci-tunnel';

describe('luciTunnelCommand', () => {
  test('forwards the local port to LuCI on the firewall loopback', () => {
    assert.equal(
      luciTunnelCommand('fw.lan'),
      `ssh -L ${LUCI_LOCAL_PORT}:127.0.0.1:${LUCI_REMOTE_PORT} root@fw.lan`,
    );
  });

  test('the far end is 127.0.0.1 on the firewall, never the firewall LAN address', () => {
    const cmd = luciTunnelCommand('192.168.1.1') ?? '';
    assert.match(cmd, /:127\.0\.0\.1:/);
    assert.ok(!cmd.includes(':192.168.1.1:'), 'the forward target must be loopback');
    assert.ok(cmd.endsWith('root@192.168.1.1'), cmd);
  });

  test('accepts a bracketed IPv6 literal, the form ssh wants', () => {
    assert.equal(
      luciTunnelCommand('[fd7a:115c:a1e0::1]'),
      `ssh -L ${LUCI_LOCAL_PORT}:127.0.0.1:${LUCI_REMOTE_PORT} root@[fd7a:115c:a1e0::1]`,
    );
  });

  test('trims surrounding whitespace', () => {
    assert.equal(luciTunnelCommand('  fw.lan \n'), luciTunnelCommand('fw.lan'));
  });

  test('honours an explicit local port', () => {
    assert.equal(
      luciTunnelCommand('fw.lan', 18443),
      `ssh -L 18443:127.0.0.1:${LUCI_REMOTE_PORT} root@fw.lan`,
    );
  });

  test('refuses a host that is empty or carries anything but a hostname or IP', () => {
    for (const bad of [
      '',
      '   ',
      'fw.lan; rm -rf /',
      'fw.lan && curl evil.example',
      '$(id)',
      '`id`',
      'fw.lan | tee /tmp/x',
      'root@fw.lan',
      'http://fw.lan/',
      'fw.lan/luci',
      'fw.lan:80',
      'fw lan',
      "fw'lan",
      '-oProxyCommand=id',
      'fd7a:115c::1', // unbracketed IPv6: ssh would read ::1 as a port
    ]) {
      assert.equal(luciTunnelCommand(bad), null, `should refuse ${JSON.stringify(bad)}`);
      assert.equal(isSafeTunnelHost(bad.trim()), false, `should refuse ${JSON.stringify(bad)}`);
    }
  });

  test('refuses a local port that is not a usable TCP port', () => {
    for (const bad of [0, -1, 65536, 1.5, Number.NaN]) {
      assert.equal(luciTunnelCommand('fw.lan', bad), null, `should refuse port ${bad}`);
    }
  });
});

describe('luciLocalUrl', () => {
  test('points at the near end of the tunnel, not the firewall', () => {
    assert.equal(luciLocalUrl(), `http://127.0.0.1:${LUCI_LOCAL_PORT}/`);
    assert.equal(luciLocalUrl(18443), 'http://127.0.0.1:18443/');
  });
});
