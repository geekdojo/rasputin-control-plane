// Rendering for ADR-0006 Decision 12: the privilege a catalog tile declares,
// turned into something an owner can consent to.
//
// The GRANT STRINGS are a contract, not copy. tileschema derives them from the
// tile's compose and refuses the tile if the declaration does not cover them
// (`tileschema/privilege.go`), so this file must never invent one — it only
// translates. An unrecognised grant falls through to a readable rendering of
// the raw string rather than being dropped: a privilege nobody prints is
// exactly the failure Decision 12 exists to end.

export type PrivilegeTier = 'routine' | 'elevated' | 'host-trusting';

export interface TilePrivilege {
  tier?: PrivilegeTier;
  dockerSocket?: boolean;
  grants?: string[];
  why?: string;
}

export const TIER_RANK: Record<PrivilegeTier, number> = {
  routine: 0,
  elevated: 1,
  'host-trusting': 2,
};

export const AMBER = '#facc15';
export const RED = '#f87171';

export interface TierCopy {
  label: string;
  color: string;
  /** One line for the badge tooltip and the drawer heading. */
  summary: string;
  /** The "what does this mean" body — teaching, not warning. */
  explainer: string;
}

// A homelab product should TEACH at this moment rather than only warn. Each
// explainer answers the three questions an owner actually has: what it means,
// why an honest app would ask, and what is still true if it turns out to be
// dishonest.
export const TIER_COPY: Record<PrivilegeTier, TierCopy> = {
  routine: {
    label: 'ROUTINE',
    color: AMBER,
    summary: 'Stays inside its own container.',
    explainer:
      'This app runs in an ordinary container. It can reach its own files and the network you give it, and nothing else on the node. This is what almost every app in the catalog looks like.',
  },
  elevated: {
    label: 'ELEVATED',
    color: AMBER,
    summary: 'Reaches past its own container, but cannot take over the node.',
    explainer:
      'This app asked for something outside its container — a piece of hardware, a folder on the node, a network capability. Plenty of honest apps need this: a Zigbee dongle, a media library on a disk, a VPN client that manages its own routes. It still cannot become root on the node, and everything it can reach is listed above, derived from the app’s own compose file and covered by the catalog signature.',
  },
  'host-trusting': {
    label: 'HOST-TRUSTING',
    color: RED,
    summary: 'Effectively root on this node.',
    explainer:
      'This app can do what the node’s administrator can do. Some of the best self-hosted software genuinely needs this — Home Assistant discovers devices by sharing the node’s network and talking to USB radios, and it is the most-requested app in this category. But a host-trusting app you do not trust is not contained by anything: assume it can read any file on the node and change how it boots. Install it because you trust who publishes it, not because the app is popular.',
  },
};

/** The tier a tile declares. Absent means routine — every tile published before Decision 12. */
export function tierOf(p: TilePrivilege | undefined): PrivilegeTier {
  return p?.tier ?? 'routine';
}

export function isRoutine(p: TilePrivilege | undefined): boolean {
  return tierOf(p) === 'routine';
}

// Capabilities most likely to appear, in the owner's words. Anything not here
// renders as the bare capability name, which is still honest.
const CAP_COPY: Record<string, string> = {
  NET_ADMIN: 'configure this node’s networking',
  NET_RAW: 'send and inspect raw network packets',
  NET_BIND_SERVICE: 'listen on low-numbered ports',
  SYS_TIME: 'change the node’s clock',
  SYS_NICE: 'change process scheduling priority',
  SYS_ADMIN: 'perform administrative kernel operations — close to full root',
  SYS_MODULE: 'load kernel modules',
  SYS_RAWIO: 'access hardware I/O and raw memory directly',
  SYS_PTRACE: 'inspect and control other processes',
  DAC_READ_SEARCH: 'read any file it can reach, ignoring permissions',
  DAC_OVERRIDE: 'read and write any file it can reach, ignoring permissions',
  BPF: 'load programs into the kernel',
  MKNOD: 'create device files',
  CHOWN: 'change file ownership',
  SETUID: 'switch to another user',
  SETGID: 'switch to another group',
  AUDIT_WRITE: 'write to the kernel audit log',
};

const FLAT_COPY: Record<string, string> = {
  privileged: 'run with every container restriction switched off',
  'host-network': 'use this node’s network directly, with no isolation of its own',
  'host-pid-ipc': 'see every other process running on this node',
  'docker-socket': 'control the container runtime — start, stop and inspect any container, including its own',
  'docker-data-root': 'read and write the container runtime’s storage, which holds every container’s files',
  'userns-host': 'run as this node’s real root user, not a remapped one',
  'seccomp-unconfined': 'make any system call, with the kernel’s syscall filter switched off',
  'apparmor-unconfined': 'run with the kernel’s access-control policy switched off',
  'selinux-disabled': 'run with SELinux labelling switched off',
};

const PREFIX_COPY: { prefix: string; render: (v: string) => string }[] = [
  { prefix: 'cap:', render: (v) => CAP_COPY[v] ?? `use the ${v} kernel capability` },
  { prefix: 'bind:', render: (v) => `read and write ${v} on this node` },
  { prefix: 'device:', render: (v) => `use the hardware at ${v}` },
  { prefix: 'reserved-device:', render: (v) => `reserve hardware: ${v}` },
  { prefix: 'group:', render: (v) => `join this node’s "${v}" group` },
  { prefix: 'security-opt:', render: (v) => `set the container security option ${v}` },
  { prefix: 'userns:', render: (v) => `use the "${v}" user-namespace mode` },
  { prefix: 'volumes-from:', render: (v) => `inherit every mount belonging to ${v}` },
  { prefix: 'namespace-join:', render: (v) => `join the namespace ${v}` },
  { prefix: 'cgroup-parent:', render: (v) => `attach to the cgroup ${v}` },
];

/** grantLabel turns one contract grant into a sentence an owner reads. */
export function grantLabel(grant: string): string {
  const flat = FLAT_COPY[grant];
  if (flat) return flat;
  for (const { prefix, render } of PREFIX_COPY) {
    if (grant.startsWith(prefix)) return render(grant.slice(prefix.length));
  }
  // Never dropped. A grant this build does not recognise is still a privilege
  // the tile takes, and showing the raw string beats showing nothing.
  return grant;
}
