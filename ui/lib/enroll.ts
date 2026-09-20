// Node-enrollment helpers for the "Add node" flow.
//
// This file no longer RENDERS a seed. The api does, with the one renderer
// (proto.RenderSeed) that rasputin-provision also uses, and returns the
// finished file on the mint response. What is left here is what belongs in the
// browser: the node-name rule the wizard checks before submitting, the
// operator-SSH-key mirror, the image the operator should flash, and the
// one-liner they paste on their own laptop.

// The DEV-BOX control-plane name, and the pre-ADR-0003 default. Per ADR-0003 a
// cluster is reached at `<cluster-id>.local`, and only the api knows the id —
// it arrives as `SetupState.clusterHostname`, empty on a dev box.
//
// The seed's own bus URL and cluster-id fallbacks moved to the api with the
// renderer (proto.NATSURLFor, proto.DefaultClusterID): the values a NODE is
// told are decided in one place now. What is left here is the address of the
// control plane as the OPERATOR'S LAPTOP reaches it, for the flash one-liner's
// curl — a different question with a different answer, which is why it stays
// in the browser.

export function cpBaseFor(clusterHostname: string): string {
  const h = clusterHostname.trim();
  return `https://${h || 'rasputin.local'}`;
}

// Roles a user can add from the UI. The controlplane self-registers, so it's
// never an "add a node" path. `firewall` IS addable, on its own branch: it's a
// distinct, x86-only image. Since the firewall seed moved onto a basic-data FAT
// (labeled RASPUTIN-FW, like the OS node's RASPUTIN-OS), a blank board takes the
// SAME flash.sh one-liner the compute/storage nodes use (firewallFlashCommand).
// See renderFirewallSeed.
export type AddableRole = 'compute' | 'storage' | 'firewall';

// Target CPU architecture for a new node's OS image. The node OS is one image
// per arch with the role selected at runtime (via the seed), so arch is
// independent of role — a single arm64 image serves a compute, storage, or
// controlplane node alike. The firewall is a separate, x86-only image on its
// own enrollment branch (renderFirewallSeed) — this arch type covers only the
// OS-node path.
export type NodeArch = 'amd64' | 'arm64';

// Per-arch board SKU + display copy. The public image asset names and the
// release manifest's `compatible` string both key off the SKU, so the SKUs
// ('n100', 'rpi') are frozen artifact identifiers — NOT descriptions of what
// the image runs on. Do not read a support claim out of them.
//
// What each image actually supports, which is what the blurbs must say:
//
//   amd64 / `n100` — a generic upstream x86_64 kernel booted by GRUB over
//     UEFI. Broad: any 64-bit UEFI machine with a wired Intel or Realtek NIC.
//     The N100 is the tested example, not the boundary. UEFI is the one hard
//     requirement, and a legacy-BIOS box fails by simply never booting, with
//     nothing to tell the operator why — hence it is in the blurb.
//
//   arm64 / `rpi` — a Raspberry Pi image: the Pi's own bootloader and a
//     Pi-fork kernel. It boots a Pi and nothing else. The blurb said
//     'Raspberry Pi / ARM64' until 2026-08-29, which read as a general arm64
//     claim we cannot honour — a Radxa or Orange Pi owner would pick ARM64,
//     flash, and get a board that never boots. Say "Raspberry Pi" and stop.
//
// Tested hardware, with the evidence behind each row:
// https://rasputin.geekdojo.com/docs/hardware/
export const NODE_ARCHES: { value: NodeArch; sku: string; label: string; blurb: string }[] = [
  { value: 'amd64', sku: 'n100', label: 'AMD64', blurb: 'Intel / AMD, UEFI boot' },
  { value: 'arm64', sku: 'rpi', label: 'ARM64', blurb: 'Raspberry Pi' },
];

// skuForArch maps an arch to the board SKU used in image asset names
// (rasputin-os-<sku>-<version>.img.xz). Defaults to the amd64/n100 SKU.
export function skuForArch(arch: NodeArch): string {
  return arch === 'arm64' ? 'rpi' : 'n100';
}

// validateSSHKey normalizes + validates an operator-pasted OpenSSH public key.
// Empty is valid — images bake no SSH key at all, so "no key" simply means a
// console/UI-only node.
//
// THE RULE IS setup.ValidOperatorSSHKey, in Go (methodology §5.1,
// geekdojo/geekdojo-brain#545). This is a mirror, because a browser cannot
// call it, and a mirror nobody executes is exactly how the three copies that
// preceded it drifted — this one, rasputin-provision's resolveSSHKey and the
// api's, each carrying a comment asking the next reader to keep all three in
// sync. rasputin-provision and the api now call the Go rule directly, and this
// mirror is pinned to it by operator-ssh-key-vectors.json, which both test
// suites execute. Change the rule and this regexp together, or a build fails.
//
// The character exclusions are not redundant with the pattern: the comment
// field is free text, and the rendered seed line is read by a shell.
const SSH_KEY_RE =
  /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9-]+(@[a-z0-9.-]+)?) [A-Za-z0-9+/=]+( \S.*)?$/;

// validOperatorSSHKey mirrors setup.ValidOperatorSSHKey exactly: one trimmed
// line, no character a shell would act on, and a recognised algorithm.
export function validOperatorSSHKey(key: string): boolean {
  if (/["$\\`\n\r]/.test(key)) return false;
  return SSH_KEY_RE.test(key);
}

export function validateSSHKey(input: string): { key: string; error?: string } {
  const key = input.trim();
  if (key === '') return { key: '' };
  if (/[\n\r]/.test(key)) return { key, error: 'paste a single key line (one key only)' };
  if (/["$\\`]/.test(key)) {
    return { key, error: 'the key must not contain ", $, \\ or ` characters' };
  }
  if (!validOperatorSSHKey(key)) {
    return {
      key,
      error:
        'that doesn’t look like an SSH public key — expected something like "ssh-ed25519 AAAA… you@laptop"',
    };
  }
  return { key };
}

// The seed renderers that used to live here are gone.
//
// There were four: these two and buildrootSeed / openwrtSeed in
// rasputin-provision, all writing the same keys in the same order, each with
// its own idea of which values needed quoting. The duplication cost real
// enrollments twice on the same function — RASPUTIN_NATS_URL hardcoded to
// rasputin.local (control-plane #70), and RASPUTIN_CLUSTER_ID omitted
// entirely, which pinned a UI-enrolled firewall to a cluster name nothing on
// the LAN answered to, silently.
//
// There is now one renderer, proto.RenderSeed. The api runs it and returns the
// finished file on the mint response (MintedBusToken.seed); the wizard shows
// and downloads that verbatim. Methodology §5.6 and §7 4.2,
// geekdojo/geekdojo-brain#540.

// OS_RELEASES_URL is the OS source repo whose public Releases hold the node OS
// images, read directly since the repos went public (ADR-0002). The add-node
// wizard links here so a new node is flashed with the *same* build the cluster
// runs. (Interim: a direct release link. The per-cluster image/storefront
// delivery is a deferred Phase-2 item — token-provisioning-pipeline §6 — and
// would replace this URL.)
const OS_RELEASES_URL = 'https://github.com/geekdojo/rasputin-os';

export interface NodeImage {
  version: string;
  asset: string;
  downloadUrl: string;
  releaseUrl: string;
}

// nodeImageFor builds the public download for the node OS image at a given
// version + architecture — pass the cluster's OS version so a new node matches
// it, and the arch the operator is flashing for. Returns null when the version
// is unknown (the wizard then falls back to generic guidance).
//
// This is a LINK, not a verification: it is derived from the version string
// alone and knows no checksum. The wizard pairs it with the control plane's
// node-image descriptor (getNodeImage), which carries the sha256 out of the
// release's SIGNED manifest plus the manifest itself, so a person flashing by
// hand can check the download without leaving the page
// (geekdojo/geekdojo-brain#527).
export function nodeImageFor(
  osVersion: string | undefined | null,
  arch: NodeArch = 'amd64',
): NodeImage | null {
  const v = (osVersion ?? '').trim();
  if (!v) return null;
  // The OS source repo tags bare CalVer (ADR-0002 — no os- mirror prefix).
  const tag = v;
  const asset = `rasputin-os-${skuForArch(arch)}-${v}.img.xz`;
  return {
    version: v,
    asset,
    downloadUrl: `${OS_RELEASES_URL}/releases/download/${tag}/${asset}`,
    releaseUrl: `${OS_RELEASES_URL}/releases/tag/${tag}`,
  };
}

// seedToB64 base64-encodes the seed for the flasher's RASPUTIN_SEED_B64 env var.
// UTF-8-safe: btoa() throws on any char outside Latin1, and the seed's comment
// line carries an em dash (and a node name could hold other non-ASCII) — so
// encode to UTF-8 bytes first, then base64 those. flash.sh's `base64 -d`
// reproduces the exact bytes. Falls back to Buffer under SSR/test where btoa is
// absent; the browser path uses btoa.
function seedToB64(seed: string): string {
  if (typeof btoa === 'function') {
    const bytes = new TextEncoder().encode(seed);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  // Node-only fallback (SSR / tests). Declared as the narrow shape actually
  // used rather than `any`, so a typo in this branch — which no browser run
  // ever exercises — is still a compile error.
  const g = globalThis as unknown as {
    Buffer?: { from(s: string, enc: string): { toString(enc: string): string } };
  };
  if (!g.Buffer) throw new Error('seedToB64: neither btoa nor Buffer is available');
  return g.Buffer.from(seed, 'utf8').toString('base64');
}

// flashCommand builds the single line the operator pastes on their laptop to
// flash + enroll a new node ("plug in the drive, run this"). The control plane
// serves the secret-free flasher at /flash.sh; the node's seed — the only
// secret — rides along as a base64 env var (never in a URL). The script
// downloads the cluster's image, verifies its checksum, flashes the drive,
// writes the seed AND reads it back to confirm it landed, then ejects. We pin
// the control-plane host to its stable mDNS name so the command is identical
// regardless of how the operator reached this UI (IP vs name). The arch selects
// which image the flasher pulls (RASPUTIN_ARCH → /api/cluster/node-image?arch=);
// it's only added to the line for non-default (arm64) so amd64 commands are
// unchanged.
export function flashCommand(seed: string, arch: NodeArch, cpBase: string): string {
  const archEnv = arch !== 'amd64' ? `RASPUTIN_ARCH=${arch} ` : '';
  return `curl -fsSL ${cpBase}/flash.sh | sudo ${archEnv}RASPUTIN_SEED_B64='${seedToB64(seed)}' bash`;
}

// firewallFlashCommand builds the one-liner that flashes + enrolls a BLANK
// firewall board — the DIY / bare-drive case, the firewall counterpart of
// flashCommand. It's the SAME secret-free flasher (/flash.sh) with the SAME
// seed-rides-as-base64 contract; the flasher reads RASPUTIN_NODE_ROLE=firewall
// from the seed and pulls the x86-only firewall image (so no arch env) and
// seeds the RASPUTIN-FW FAT, all off that one role field — there is no
// firewall-specific flag on the line. The scp + apply-seed path
// (firewallApplyCommand) stays for a pre-imaged unit that's already running
// with your key; this is for a board with a blank drive.
export function firewallFlashCommand(seed: string, cpBase: string): string {
  return `curl -fsSL ${cpBase}/flash.sh | sudo RASPUTIN_SEED_B64='${seedToB64(seed)}' bash`;
}

// clusterPrefixOf derives the "<cluster>-" id prefix every node shares, from the
// existing inventory: the longest common prefix, trimmed back to the last '-'.
// Returns '' when there's no shared dash-delimited prefix (then suggestions are
// bare "<role><n>", which the user can edit).
export function clusterPrefixOf(ids: string[]): string {
  if (ids.length === 0) return '';
  let lcp = ids[0];
  for (let k = 1; k < ids.length; k++) {
    const id = ids[k];
    let i = 0;
    while (i < lcp.length && i < id.length && lcp[i] === id[i]) i++;
    lcp = lcp.slice(0, i);
    if (lcp === '') break;
  }
  const cut = lcp.lastIndexOf('-');
  return cut >= 0 ? lcp.slice(0, cut + 1) : '';
}

// NODE_ID_RULE is the node-name rule in words, for the wizard's hint.
export const NODE_ID_RULE =
  'use lowercase letters, digits and hyphens only, at most 63 characters, not starting or ending with a hyphen';

// validNodeId mirrors busauth.ValidNodeID (tileschema.ValidDNSLabel) in the api:
// a node id is a lowercase RFC 1123 DNS label — the first label of the node's
// FQDN, and exactly one token of every bus subject it is scoped to. The api
// rejects (never rewrites) anything else with a 400, so the wizard checks the
// same rule before minting and says why instead of failing on submit.
export function validNodeId(id: string): boolean {
  return id.length >= 1 && id.length <= 63 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(id);
}

// suggestNodeId proposes the next free "<prefix><role><n>" id, matching the
// rasputin-provision auto-naming convention and skipping any id already taken
// (live nodes or pending enrollments). The prefix comes from existing ids, so
// it is only used when the result is a valid node id (an inventory with an
// older non-conforming name, or a very long shared prefix, would otherwise
// suggest a name the api refuses); the fallback "<role><n>" is always valid.
export function suggestNodeId(prefix: string, role: AddableRole, taken: Set<string>): string {
  const withPrefix = nextFreeNodeId(prefix, role, taken);
  return validNodeId(withPrefix) ? withPrefix : nextFreeNodeId('', role, taken);
}

function nextFreeNodeId(prefix: string, role: AddableRole, taken: Set<string>): string {
  const re = new RegExp(`^${escapeRe(prefix + role)}(\\d+)$`);
  let max = 0;
  for (const id of taken) {
    const m = id.match(re);
    if (m) max = Math.max(max, parseInt(m[1], 10));
  }
  let n = max + 1;
  let candidate = `${prefix}${role}${n}`;
  while (taken.has(candidate)) candidate = `${prefix}${role}${++n}`;
  return candidate;
}

// downloadSeed triggers a browser download of the enrollment file. The default
// filename `rasputin-seed.env` is what an OS node's firstboot expects on the
// boot partition, so the user can drop it straight on without renaming; the
// firewall path passes `seed.env` (the name apply-seed / the scp command
// expect).
export function downloadSeed(contents: string, filename: string = 'rasputin-seed.env'): void {
  const blob = new Blob([contents], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
