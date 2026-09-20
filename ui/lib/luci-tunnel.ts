// Reaching the firewall's native admin UI (LuCI) over an SSH tunnel.
//
// The firewall's web server listens on the firewall's own loopback interface,
// so there is no LAN URL to link to: the operator forwards a local port to it
// over SSH and browses the local end. This module builds that command so the
// UI never has to assemble a shell string inline, and so the rules below are
// testable on their own.
//
// The command is built for the operator to paste into THEIR terminal, so the
// host is checked before it is interpolated. Today `host` is typed by the
// operator into the Advanced tab and nothing else reaches it, but the Advanced
// tab already carries a note that host derivation becomes automatic once
// `primaryLanIp` lands on Node — on that day this value starts arriving from a
// node, and a value that could carry `;` or a backtick would be a command the
// operator pastes and runs. Refusing anything that is not a hostname or an IP
// literal keeps that door shut now rather than later.

/** Port LuCI listens on, on the firewall's loopback interface. */
export const LUCI_REMOTE_PORT = 80;

/** Local port the SSH tunnel's near end is bound to. Arbitrary; high enough not to need root. */
export const LUCI_LOCAL_PORT = 8080;

/** Account the operator uses for the firewall's SSH escape hatch. */
export const LUCI_SSH_USER = 'root';

// A DNS hostname or dotted-quad: letters, digits, dots, dashes and underscores,
// starting and ending alphanumeric. Deliberately narrow — no whitespace, no
// shell metacharacters, no scheme, no path, no user@ prefix, no port suffix.
const HOSTNAME_OR_IPV4 = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

// A bracketed IPv6 literal, the form ssh itself wants: ssh root@[fd00::1].
const BRACKETED_IPV6 = /^\[[0-9A-Fa-f:]+\]$/;

/**
 * True when `host` is safe to interpolate into the tunnel command: a DNS
 * hostname, an IPv4 address, or a bracketed IPv6 literal, and nothing else.
 */
export function isSafeTunnelHost(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  return HOSTNAME_OR_IPV4.test(host) || BRACKETED_IPV6.test(host);
}

/**
 * The `ssh -L` command that forwards `localPort` on this machine to LuCI on the
 * firewall's loopback interface, or null when `host` is empty or is not a host
 * this module will put in a shell command.
 */
export function luciTunnelCommand(host: string, localPort: number = LUCI_LOCAL_PORT): string | null {
  const h = host.trim();
  if (!isSafeTunnelHost(h)) return null;
  if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) return null;
  return `ssh -L ${localPort}:127.0.0.1:${LUCI_REMOTE_PORT} ${LUCI_SSH_USER}@${h}`;
}

/** The address to open once the tunnel from `luciTunnelCommand` is up. */
export function luciLocalUrl(localPort: number = LUCI_LOCAL_PORT): string {
  return `http://127.0.0.1:${localPort}/`;
}
