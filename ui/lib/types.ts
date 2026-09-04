// `ArchiveKeyPayload` is defined where it is MINTED (lib/archive-key.ts), not
// here: it is the one wire type this UI produces with crypto rather than
// transcribes from Go, and keeping the shape next to the ceremony is what stops
// a field being added to one and not the other. Type-only import — no runtime
// coupling, and no WASM pulled into modules that just want a Node type.
import type { ArchiveKeyPayload } from './archive-key';

export type JobStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'cancelled';

export type StepStatus =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'compensated';

export interface Job {
  id: string;
  kind: string;
  spec: unknown;
  status: JobStatus;
  createdBy: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  parentId?: string;
  error?: string;
}

export interface JobStep {
  jobId: string;
  seq: number;
  name: string;
  status: StepStatus;
  startedAt?: string;
  finishedAt?: string;
  attempt: number;
  result?: unknown;
  error?: string;
}

export interface JobEvent {
  id?: number; // present on REST replies, absent on the wire
  type: string;
  jobId: string;
  ts: string;
  data?: unknown;
}

export type NodeRole = 'controlplane' | 'firewall' | 'compute' | 'storage';
export type NodeStatus = 'online' | 'stale' | 'offline';
export type InventoryChange =
  | 'added'
  | 'online'
  | 'stale'
  | 'offline'
  | 'updated'
  | 'removed';

/**
 * Agent boot-time snapshot of the persistent data partition (/var/lib/rasputin).
 * growpart is the outcome keyword from the rasputin-os breadcrumb log:
 * grown | already-full | deferred-trial | skipped | failed. Absent from
 * pre-storage agents.
 */
export interface NodeStorage {
  persistentTotalBytes: number;
  persistentFreeBytes: number;
  growpart?: string;
}

export interface Node {
  id: string;
  role: NodeRole;
  hostname: string;
  agentVersion: string;
  imageVersion?: string;
  /** CPU architecture: "amd64" | "arm64". Empty/undefined if a pre-arch agent never reported it. */
  architecture?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  storage?: NodeStorage;
  firstSeen: string;
  lastSeen: string;
  /**
   * LAN liveness ONLY — derived from the agent heartbeat, which travels over
   * the LAN and never touches the tailnet. A node can be `online` here and not
   * be on the mesh at all. Never label this simply "online"; say online how.
   */
  status: NodeStatus;
  /**
   * Tailnet membership — independent of `status`, different failure mode.
   * `undefined` means UNDETERMINED (no mesh service, or no reconcile yet), and
   * must never be rendered as healthy. See geekdojo/geekdojo-brain#202.
   */
  mesh?: MeshMembership;
}

/**
 * A node's tailnet membership, deliberately separate from NodeStatus.
 * Named MeshMembershipState, not MeshState: `MeshState` is already the
 * reconcile-state of the mesh service as a whole, and conflating "is this node
 * on the tailnet" with "has the mesh config converged" is the exact kind of
 * two-facts-one-name error that produced #202.
 */
export type MeshMembershipState = 'joined' | 'absent' | 'unknown';

export interface MeshMembership {
  state: MeshMembershipState;
  /**
   * Headscale's last-seen. Meaningful mainly when `state` is 'absent' — it
   * answers "how long has this been broken?". Not refreshed while a node stays
   * connected, so for a joined node it is the moment it connected.
   */
  lastSeen?: string;
  /** The 100.64.0.x address; absent when not enrolled. */
  tailnetIP?: string;
}

export interface InventoryChangeEvent {
  change: InventoryChange;
  node: Node;
  ts: string;
}

// ----- Bus join tokens (node enrollment) ---------------------------------

// BusTokenInfo is the secret-free view of a bus join token (GET /api/bus/tokens
// — no plaintext, ever). A token bound to a node id (nodeId set) that is not
// revoked and whose node hasn't registered in inventory yet is a *pending
// enrollment* — the new node has been issued a credential but hasn't booted and
// joined. id is the token_hash, the stable handle for revoke.
export interface BusTokenInfo {
  id: string;
  label: string;
  nodeId?: string;
  createdAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

// MintedBusToken is the one-shot reply from POST /api/bus/tokens. token is the
// plaintext join credential — shown once and unrecoverable afterward (same
// model as mesh pre-auth keys). It goes into the new node's enrollment seed.
export interface MintedBusToken {
  id: string;
  label: string;
  nodeId: string;
  token: string;
}

// FlashableImage is the public, verifiable image descriptor returned by the
// cluster image endpoints (GET /api/cluster/node-image and
// /api/cluster/firewall-image): an anonymous download URL plus the sha256 to
// check it against. The Add-node / Add-firewall wizard links the exact image
// to flash from it.
export interface FlashableImage {
  version: string;
  architecture: string;
  url: string;
  sha256: string;
  image: string;
}

export type FirewallIntentKind = 'port_forward' | 'firewall_rule' | 'wan_config';
export type PortForwardProto = 'tcp' | 'udp' | 'tcpudp';

export type FirewallRuleProto = 'tcp' | 'udp' | 'tcpudp' | 'icmp' | 'igmp' | 'any';
export type FirewallRuleTarget = 'accept' | 'reject' | 'drop';

export type WANProto = 'dhcp' | 'static' | 'pppoe';

export interface WANConfigSpec {
  proto: WANProto;
  // dhcp
  hostname?: string;
  // static
  ip?: string;
  gateway?: string;
  dns?: string[];
  // pppoe
  username?: string;
  secret?: string;
  service?: string;
  comment?: string;
}

export interface FirewallRuleSpec {
  src: string; // zone, required
  dest?: string; // zone, "" = INPUT chain (to firewall itself)
  srcIp?: string;
  srcPort?: string;
  destIp?: string;
  destPort?: string;
  proto?: FirewallRuleProto;
  target: FirewallRuleTarget;
  log?: boolean;
  comment?: string;
}

export interface PortForwardSpec {
  wanPort: number;
  lanHost: string;
  lanPort: number;
  protocol: PortForwardProto;
  comment?: string;
}

export interface FirewallIntent {
  id: string;
  kind: FirewallIntentKind;
  name: string;
  enabled: boolean;
  // Narrow by `kind` at the use site (see PreAuthKeySpec / SubnetRouteSpec
  // pattern on MeshIntent).
  spec: PortForwardSpec | FirewallRuleSpec | WANConfigSpec;
  createdAt: string;
  updatedAt: string;
}

export interface FirewallNodeState {
  nodeId: string;
  intentHash: string;
  observedHash: string;
  lastApplied?: string;
  lastReconciled?: string;
  // True when the firewall agent's observed state diverges from what we last
  // pushed (hand-edit on the box). Surfaced as the DRIFT chip state.
  drift: boolean;
  // True when the user has intents that haven't been Applied yet — the
  // compiled hash of current intents differs from what was last pushed.
  // Surfaced as the PENDING chip state. Drift dominates pending when both.
  pending: boolean;
}

export type FirewallChange = 'applied' | 'drift' | 'in_sync' | 'reconciled';

export interface FirewallChangeEvent {
  nodeId: string;
  change: FirewallChange;
  intentHash?: string;
  observedHash?: string;
  ts: string;
}

export interface MetricPoint {
  ts: string;
  value: number;
}

export interface MetricSeries {
  nodeId: string;
  from: string;
  to: string;
  series: Record<string, MetricPoint[]>;
}

export type AppStatus =
  | 'stopped'
  | 'deploying'
  | 'running'
  | 'stopping'
  | 'failed'
  | 'unknown';

export type AppChange = 'deploying' | 'stopping' | 'deployed' | 'stopped' | 'failed' | 'deleted';

export interface App {
  id: string;
  name: string;
  composeYaml: string;
  targetNode: string;
  // Host port the reverse proxy fronts (0/absent = none — a page-less app).
  // Seeded from the catalog tile's web port at install. See app-access.md.
  publishedPort?: number;
  // The app serves HTTPS on publishedPort, so the proxy dials its upstream over
  // TLS. Copied from the tile's web port at install (#387).
  webTls?: boolean;
  // Catalog tile id this app was installed from ('' / absent = custom compose).
  sourceTile?: string;
  // Whether the app is LAN-exposed (ADR-0004 §9). Default false: tailnet-only —
  // reachable at the bare <app>.<cluster-id>.internal name. When true it also
  // gets the <app>.lan.<cluster-id>.internal name. LAN is always an explicit
  // opt-in (no install-form toggle yet — see app-access.md).
  exposeLan?: boolean;
  lastStatus: AppStatus;
  lastDetail?: string;
  lastDeployed?: string;
  lastStopped?: string;
  lastStatusAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AppChangeEvent {
  appId: string;
  change: AppChange;
  status: AppStatus;
  detail?: string;
  ts: string;
}

// ----- App catalog (curated first-party tiles) ----------------------------

export type CatalogCollection = 'essentials' | 'show-off' | 'everyday' | 'dongle';

export interface CatalogPort {
  name: string;
  container: number;
  published: number;
  protocol?: 'tcp' | 'udp';
  // The port serving this app's web UI — the one the node-local reverse proxy
  // fronts and the one OPEN points at. Absent on every port means the app has
  // no page (a database, a game server), which is a declared shape rather than
  // an omission (ADR-0006 Decision 13). Renamed from `primary` in #387.
  web?: boolean;
  // The app speaks HTTPS on this port, so the proxy's upstream leg must too.
  // Declared because the port number does not imply it. Affects the
  // proxy→container leg only; what the operator opens is https either way.
  tls?: boolean;
}

export type { PrivilegeTier, TilePrivilege } from './privilege';

// One tile the control plane refused out of an otherwise-valid bundle
// (ADR-0006 Decision 7, #162), and why.
export interface TileRejection {
  id: string;
  reason: string;
}

// Provenance of the catalog currently in effect (GET /api/catalog/_status).
export interface CatalogStatus {
  version: number;
  // "fetched" = adopted from a signed published bundle; "embedded" = the floor
  // baked into this image, i.e. nothing has ever been adopted.
  source: 'fetched' | 'embedded' | string;
  tiles: number;
  // NULL until a poll has COMPLETED, and null is NOT "checked, found nothing".
  // A cluster that has never reached the internet must not look identical to
  // one that is up to date — that was #149's failure mode in the updates panel
  // and this field exists so the catalog cannot repeat it.
  lastChecked: string | null;
  lastError?: string;
  note?: string;
  rejectedTiles?: TileRejection[];
}
import type { TilePrivilege } from './privilege';

export interface CatalogTile {
  id: string;
  name: string;
  tagline: string;
  description?: string;
  collection: CatalogCollection;
  // Functional category powering the filter chips (media, network, ai, …).
  category?: string;
  // '' / 'available' = installable; 'preview' = shown but coming soon.
  status?: 'available' | 'preview';
  arch: 'both' | 'arm64' | 'amd64';
  placementHint?: '' | 'any' | 'prefer-x86' | 'prefer-arm64';
  ramFloorMB: number;
  needsHardware?: string;
  needsFeedKey?: string[];
  exposureDefault: 'lan-only' | 'tailnet' | 'public';
  ports: CatalogPort[];
  website?: string;
  icon?: string;
  // One-line first-run guidance shown after deploy.
  postInstall?: string;
  // What the tile's compose stack takes, declared by the publisher and checked
  // against the derived facts before the bundle is signed (ADR-0006 Decision
  // 12). Absent means routine — every tile published before 2026-08-22.
  privilege?: TilePrivilege;
  // Capabilities a reader must understand to load this tile (Decision 7).
  requires?: string[];
  // Present only on the single-tile detail response, not the list.
  composeYaml?: string;
}

// ----- App volumes (geekdojo/geekdojo-brain#399) ----------------------------

// VolumeCapture is when a volume was last captured into a backup generation
// that is still on the target. Absent (null) on the wire means never.
export interface VolumeCapture {
  generationId: string;
  at: string;
  runJobId?: string;
}

// AppVolume is one of an installed app's volumes as the uninstall prompt lists
// it: the tile's compose name, docker's name for it, its §4.2 class, and its
// backup state.
export interface AppVolume {
  name: string;
  dockerName: string;
  backup: 'critical' | 'state' | 'cache' | 'bulk' | string;
  quiesce?: string;
  lastCaptured: VolumeCapture | null;
}

// AppVolumesResponse is GET /api/apps/{id}/volumes.
export interface AppVolumesResponse {
  appId: string;
  appName: string;
  tileId?: string;
  // Which catalog classified the volumes — the same string the catalog status
  // reports.
  catalog?: string;
  // false: the volumes could not be listed (custom app, tile not in the live
  // catalog, no live catalog). `note` says which.
  classified: boolean;
  note?: string;
  // Why every volume reads "never", when that is the case.
  backupNote?: string;
  volumes: AppVolume[];
}

// OrphanVolume is a rasp_<appId>_* volume on a node whose appId has no row in
// the apps ledger — data an earlier uninstall left behind.
export interface OrphanVolume {
  nodeId: string;
  name: string;
  appId: string;
  volume: string;
  sizeBytes: number;
  createdAt: string;
  inUse: boolean;
  // From the backup manifest, when one ever recorded this volume; the app row
  // is gone, so the manifest is the only place its name and class survive.
  appName?: string;
  tileId?: string;
  backup?: string;
  lastCaptured: VolumeCapture | null;
}

// OrphanVolumesResponse is GET /api/volumes/orphans.
export interface OrphanVolumesResponse {
  volumes: OrphanVolume[];
  nodesAsked: number;
  unreachable: { nodeId: string; reason: string }[];
  backupNote?: string;
}

// VolumeRefusal is one name the reclaim declined, with the reason.
export interface VolumeRefusal {
  name: string;
  reason: string;
}

// ReclaimResponse is POST /api/volumes/orphans/reclaim.
export interface ReclaimResponse {
  nodeId: string;
  ok: boolean;
  detail?: string;
  removed: string[];
  refused: VolumeRefusal[];
}

// ----- Updates ------------------------------------------------------------

export type UpdateSlot = 'a' | 'b' | 'unknown';

export type UpdateChange =
  | 'started'
  | 'downloaded'
  | 'installed'
  | 'committed'
  | 'rolled_back'
  | 'failed';

export interface Bundle {
  sha256: string;
  version: string;
  compatible: string;
  architecture: string;
  description: string;
  buildDate: string;
  sizeBytes: number;
  signedBy: string;
  uploadedAt: string;
  uploadedBy: string;
}

// How the api verifies OS update bundles right now. `unavailable` is not a
// softer `enforced`: with no trust root the api REFUSES every bundle rather
// than accepting it unchecked, and the banner has to say which one it is.
export type BundleTrustMode = 'enforced' | 'unavailable' | 'dev-permissive';

export interface BundleList {
  trustConfigured: boolean;
  trustMode: BundleTrustMode;
  bundles: Bundle[];
}

// "Check for Updates" — per-component report from POST /api/updates/check.
export type UpdateStatus =
  | 'up_to_date'
  | 'update_available'
  | 'no_release'
  // The comparison says up to date, but a node's version is UNCONFIRMED —
  // inventory is holding a value an update outcome told us not to trust
  // (ADR-0005 Decision 4). Distinct from 'unknown', which means we could not
  // compare at all. The row's note names the node(s).
  | 'needs_attention'
  | 'unknown';

/**
 * One architecture's deployable artifact within a release, and whether this
 * cluster has it staged. `neededBy` is how many nodes would take it — zero
 * means the cluster has no hardware of that arch, so a missing artifact is
 * not a problem worth flagging.
 */
export interface ArtifactStatus {
  architecture: string;
  compatible: string;
  bundleSha256: string;
  assetName?: string;
  sizeBytes?: number;
  staged: boolean;
  neededBy: number;
}

/** One architecture's outcome from POST /api/updates/pull. */
export interface PullArtifactResult {
  architecture: string;
  compatible: string;
  assetName: string;
  sha256?: string;
  created?: boolean;
  error?: string;
}

/**
 * Reply from POST /api/updates/pull. `staged` and `failed` together always
 * cover every deployable artifact in the release, so a partial pull (HTTP 207)
 * is distinguishable from a complete one without re-checking.
 */
export interface PullResult {
  component: string;
  version: string;
  channel: string;
  staged: PullArtifactResult[];
  failed?: PullArtifactResult[];
  bundle?: Bundle;
}

export interface ComponentUpdate {
  component: string; // "os" | "fw" | "cp"
  label: string;
  channel: string;
  installed: string;
  latest: string;
  status: UpdateStatus;
  kind: string; // "raucb" | "sysupgrade" | "info"
  deployable: boolean;
  bundleSha256?: string;
  assetName?: string;
  sizeBytes?: number;
  signedBy?: string;
  /** True only when every artifact the fleet NEEDS is staged — see `artifacts`. */
  staged?: boolean;
  /** One entry per architecture in the release. A release is one artifact per
   *  arch, so a single `staged` bool cannot describe a mixed-arch cluster. */
  artifacts?: ArtifactStatus[];
  manualInstructions?: string;
  note?: string;
  // Software that ships inside this component's image (e.g. the control-plane
  // binary inside the OS) — shown as a display-only detail line, never with its
  // own update status.
  // What is RUNNING inside this component's image, not what the offered
  // release carries — see releases.ComponentStatus.Running.
  running?: { label: string; version: string }[];
  error?: string;
}

export interface UpdateCheckResult {
  channel: string;
  checkedAt: string;
  components: ComponentUpdate[];
}

export type NodeUpdateStatus =
  | 'in_progress'
  | 'committed'
  | 'rolled_back'
  | 'failed';

export interface NodeUpdate {
  jobId: string;
  nodeId: string;
  bundleSha256: string;
  fromSlot: UpdateSlot;
  toSlot: UpdateSlot;
  fromVersion: string;
  toVersion: string;
  // Conjuncts of the verify contract that could not be EVALUATED for this
  // update — an agent that reported no boot identity, or no image version
  // (ADR-0005 Decision 3). Not failures: the update passed on what could be
  // checked. They exist so a green row that means less than the green row
  // beside it says so.
  unverifiedBoot?: boolean;
  unverifiedVersion?: boolean;
  status: NodeUpdateStatus;
  startedAt: string;
  finishedAt?: string;
  error?: string;
}

export interface UpdateChangeEvent {
  nodeId: string;
  jobId: string;
  bundleId?: string;
  change: UpdateChange;
  fromSlot?: UpdateSlot;
  toSlot?: UpdateSlot;
  version?: string;
  reason?: string;
  ts: string;
}

// ----- System update -----------------------------------------------------

export type SystemUpdateChange =
  | 'planned'
  | 'node_started'
  | 'node_succeeded'
  | 'node_failed'
  /** The GATE's verdict for one (tier, arch) pair — whether that
   *  architecture's fan-out is authorised. Distinct from the canary node's own
   *  `node_succeeded` / `node_failed`, which says only what happened to that
   *  one node. ADR-0005 Decisions 6 + 11. */
  | 'canary_passed'
  | 'canary_failed'
  /** A tier's failure budget was reached and the cascade stopped starting new
   *  nodes there. Its own event because "we stopped on purpose" and "it ran
   *  out of nodes" otherwise look identical in a grid of not-attempted rows. */
  | 'budget_spent'
  | 'completed'
  | 'aborted';

/**
 * Why a node was left out of a system.update plan. Three of these are the plan
 * working as designed; `no-artifact-for-arch` is a node left behind, and a run
 * containing one fails its parent job however green the per-node grid looks
 * (ADR-0005 Decision 11). Never render them as one undifferentiated "skipped".
 */
export type SkipReason =
  | 'excluded'
  | 'offline'
  | 'firewall-sku'
  | 'no-artifact-for-arch';

export interface SkippedNode {
  nodeId: string;
  reason: SkipReason;
  detail?: string;
  /** The node's role and the SKU it WOULD have taken. A skipped node is still
   *  a row of the same report as a target; leaving its dimensions blank makes
   *  the grid read as broken rather than as a deliberate omission. Absent on
   *  jobs recorded before these were carried, and `compatible` is absent when
   *  the node's arch has no known artifact — not knowing IS the finding. */
  tier?: NodeRole;
  compatible?: string;
}

/**
 * What happened to ONE planned target. `not-attempted` is the third value that
 * makes the report honest: under best-effort fan-out every target IS attempted,
 * so a target that was not is a node the run deliberately stopped short of —
 * the canary gate aborted before it — and rendering that as a failure sends an
 * operator to look at a machine that is fine.
 */
export type NodeOutcome = 'succeeded' | 'failed' | 'not-attempted';

/** One row of the per-node results grid. */
export interface NodeResult {
  nodeId: string;
  outcome: NodeOutcome;
  tier?: NodeRole;
  /** Release SKU of the artifact this node took — the arch, in practice. */
  compatible?: string;
  canary?: boolean;
  childJobId?: string;
  detail?: string;
}

export interface SystemUpdateCounts {
  total: number;
  succeeded: number;
  failed: number;
  skipped: number;
  /** Planned targets the run never started. Distinct from `failed` (something
   *  happened to the node) and from `skipped` (decided at plan time). */
  notAttempted?: number;
  /** Subset of `skipped` that nobody asked for. Non-zero means the run did not
   *  do what UPDATE ALL says on the button. */
  stranded?: number;
}

/** One node the plan would update, in planned order, flagged if it is the
 *  canary for its (tier, arch) pair. */
export interface PlanTarget {
  nodeId: string;
  tier: NodeRole;
  compatible: string;
  canary: boolean;
}

/** Read-only resolution of a system.update spec — what the cascade WOULD run,
 *  no job submitted. Powers the pre-flight drawer (#95). */
export interface SystemUpdatePlan {
  bundleVersion: string;
  component?: string;
  targets: PlanTarget[];
  skipped: SkippedNode[];
  /** The node hosting the api, when the plan updates it too (#56). Set only
   *  when it is actually a target — absent means this run does not touch it. */
  selfNodeId?: string;
}

export interface SystemUpdateChangeEvent {
  parentJobId: string;
  change: SystemUpdateChange;
  nodeId?: string;
  childJobId?: string;
  bundleId?: string;
  detail?: string;
  /** The node's role, which is also the unit the cascade advances in:
   *  compute → storage → controlplane → firewall. On `node_*` and `canary_*`. */
  tier?: NodeRole;
  /** Release SKU of the artifact this node is receiving — the arch, in
   *  practice. The canary is scoped per arch, so a canary verdict is only ever
   *  a claim about one of them. */
  compatible?: string;
  /** True when this `node_*` event belongs to a canary rather than a fan-out
   *  target. */
  canary?: boolean;
  counts?: SystemUpdateCounts;
  /** Per-node skip reasons, carried on `planned` and `completed`. */
  skipped?: SkippedNode[];
  /** The per-node grid, on `completed`: one row per planned target, in planned
   *  order. Skipped nodes are not in here — they are in `skipped`, with a
   *  reason, because "never a target" and "a target that failed" are different
   *  rows of the same report. */
  results?: NodeResult[];
  ts: string;
}

// ----- Mesh ---------------------------------------------------------------

export type MeshIntentKind = 'preauth_key' | 'subnet_route';

export interface PreAuthKeySpec {
  user: string;
  reusable: boolean;
  ephemeral: boolean;
  expiresIn: string;
  tags?: string[];
  deviceHint?: string;
}

export interface SubnetRouteSpec {
  nodeId: string;
  cidr: string;
}

export interface MeshIntent {
  id: string;
  kind: MeshIntentKind;
  name: string;
  enabled: boolean;
  spec: PreAuthKeySpec | SubnetRouteSpec;
  hsId?: string;
  hsValue?: string;
  createdAt: string;
  updatedAt: string;
}

export interface MeshDevice {
  hsId: string;
  user: string;
  hostname: string;
  tailnetIp: string;
  tags: string[];
  advertisedRoutes: string[];
  rasputinNodeId?: string;
  kind: 'rasputin' | 'user';
  firstSeen: string;
  lastSeen: string;
  /** Rasputin devices only: how the mesh CA the node's agent reports trusting compares with the api's current one. */
  trust?: MeshDeviceTrust;
}

/**
 * A node's trust reading. "stale": the node trusts a different CA (or none) —
 * the next mesh.reconcile re-delivers the current one. "unreported": the agent
 * has not said what it trusts (older agent); left alone.
 */
export interface MeshDeviceTrust {
  nodeId: string;
  state: 'current' | 'stale' | 'unreported';
  /** What the node reported: a sha256 fingerprint, or "none". Never a PEM. */
  fingerprint?: string;
  agentPredatesField?: boolean;
}

export interface MeshState {
  intentHash: string;
  observedHash: string;
  lastApplied?: string;
  lastReconciled?: string;
  drift: boolean;
  pending: boolean;
}

export interface MeshStateEnvelope {
  /**
   * "headscale" (real), "mock" (a dev fixture, explicitly requested), or
   * "unavailable" (no real backend could be resolved and none was substituted).
   *
   * "unavailable" exists because `auto` used to fall through to the mock, which
   * mints keys and reports invented 100.64.0.x tailnet addresses — a control
   * plane claiming a mesh that does not exist. Anything that renders this must
   * treat BOTH non-"headscale" values as "these addresses are not real".
   */
  backend: string;
  loginServer: string;
  defaultUser: string;
  // Backend omits the field when RASPUTIN_HEADPLANE_URL is unset; we treat
  // its presence as the signal to show the Advanced → Headplane tab content.
  headplaneUrl?: string;
  state: MeshState;
}

export type MeshChange =
  | 'applied'
  | 'in_sync'
  | 'drift'
  | 'reconciled'
  | 'node_enrolled'
  | 'node_left'
  | 'key_created'
  | 'key_expired'
  | 'user_device_seen';

export interface MeshChangeEvent {
  scope: string;
  change: MeshChange;
  intentHash?: string;
  observedHash?: string;
  detail?: string;
  nodeId?: string;
  tailnetId?: string;
  ts: string;
}

// ----- BMC ----------------------------------------------------------------

export type BMCPowerVerb = 'on' | 'off' | 'cycle' | 'reset' | 'status';
export type BMCPowerState = 'on' | 'off' | 'unknown';

// One entry of the served supported-backends list (Settings picker).
export interface BMCBackendInfo {
  kind: string;
  label: string;
  status: 'available' | 'planned';
}

// The cluster's current BMC selection, sanitized (write-only fields
// like the bitscope unlock never round-trip; unlockSet marks presence).
export interface BMCConfigView {
  backend: string; // '' = off
  hostNodeId?: string;
  config?: Record<string, unknown>;
  pinnedNode?: string;
}

export interface BMCState {
  targetNodeId: string;
  powerState: BMCPowerState;
  lastCmd?: string;
  lastCmdAt?: string;
  lastCmdResult?: string;
  updatedAt: string;
}

export type BMCChange =
  | 'powered_on'
  | 'powered_off'
  | 'cycled'
  | 'reset_sent'
  | 'sol_opened'
  | 'sol_closed';

export interface BMCChangeEvent {
  targetNodeId: string;
  change: BMCChange;
  state?: BMCPowerState;
  sessionId?: string;
  detail?: string;
  ts: string;
}

// ----- Setup wizard -------------------------------------------------------

export interface SetupStep {
  id: string;
  title: string;
  done: boolean;
  required: boolean;
  detail?: string;
}

// Deployment topology chosen in the wizard. '' = not yet picked. The values
// are a backend contract (setup.mode) — see the api setup package.
export type DeploymentMode = '' | 'router' | 'lan_peer' | 'sub_segment';

export interface SetupState {
  steps: SetupStep[];
  completed: boolean;
  completedAt?: string;
  installName: string;
  hasUsers: boolean;
  trustConfigured: boolean;
  meshEnrolled: boolean;
  selfNodeId: string;
  // Chosen deployment mode ('' until picked).
  mode: DeploymentMode;
  // Whether a firewall-capable node is registered — i.e. whether the router
  // and sub-segment modes are offerable.
  firewallCapable: boolean;
  // "<cluster-id>.local" per ADR-0003 — the host every minted seed's NATS URL
  // dials and the base the flash one-liner curls. EMPTY on a dev box; the UI
  // falls back to its own defaults then (see enroll.ts natsURLFor/cpBaseFor).
  clusterHostname: string;
  // The bare cluster id ("home1") — seeds carry it as RASPUTIN_CLUSTER_ID.
  clusterId: string;
}

// DNS forwarding (AA-11 / ADR-0004 §10) — the control plane can answer DNS for
// the whole LAN: internal names authoritatively, everything else forwarded on.
// GET/POST /api/settings/dns-forwarding.
export interface DNSForwarding {
  enabled: boolean;
  // Operator-configured upstream ("" = auto: inherit the CP's DHCP resolver,
  // else a public fallback).
  upstream: string;
  // What the running forwarder actually forwards to now.
  effectiveUpstream: string;
  // effectiveUpstream is the public default because no safe upstream was found.
  fellBack: boolean;
  // The control plane's LAN IP + MAC — where to point the router's DNS, and the
  // MAC to reserve so that address survives reboots.
  controlPlaneIp: string;
  controlPlaneMac: string;
}

// Alerts — surfaced by the v0 server-side aggregator at GET /api/alerts.
// Mirror of proto/alerts.go. v0 is binary severity (no INFO tier); INFO-
// level signals live in their own affordances. Drill-through uses
// (relatedKind, relatedId).
export type AlertSeverity = 'warn' | 'crit';
// 'rule' is the source for Slice 1.5 persisted alerts that arrive from
// vmalert. The aggregator-derived sources (node/job/app/setup/security)
// carry their lifecycle in code; rule alerts can be acked/dismissed.
// 'security' is a standing posture concern (v0: bus auth off) — cluster-
// wide, no drill-through target.
export type AlertSource = 'node' | 'job' | 'app' | 'setup' | 'security' | 'rule';
export type AlertRelatedKind = 'node' | 'job' | 'app';

export interface Alert {
  id: string;
  severity: AlertSeverity;
  source: AlertSource;
  title: string;
  detail?: string;
  since: string;
  relatedKind?: AlertRelatedKind;
  relatedId?: string;
  // Slice 1.5 — only meaningful for source=rule.
  acked?: boolean;
  ackedAt?: string;
}

// ObsState is the lifecycle reported by GET /api/obs/status.
//
// Prefer this over deriving from enabled+healthy. `enabled && healthy` looks
// equivalent but silently folds "starting" into "off" — and a cold enable
// spends minutes pulling ~500 MB, so that window is exactly when the
// operator is staring at the thing they just switched on.
export type ObsState = 'off' | 'starting' | 'on';

// ObsStatus mirrors api/internal/obs/status.go's Snapshot. Returned by
// GET /api/obs/status.
export interface ObsStatus {
  // enabled is the operator's stored opt-in — NOT "charts will render".
  // It stays true for the whole cold-start pull. Read `state` for that.
  enabled: boolean;
  state: ObsState;
  healthy: boolean;
  vmBaseUrl?: string;
  lastWriteOk?: string;
  lastError?: string;
  lokiBaseUrl?: string;
  // grafanaUrl is the api-relative path to the embedded Grafana — set
  // to "/observability/" when the proxy is active. The UI uses this as
  // the iframe src; the api's reverse proxy handles auth.
  grafanaUrl?: string;
}

// ObsSeriesMetric — keys accepted by GET /api/obs/series ?metric=. The
// server maps each to a PromQL expression; the UI never has to think
// about the underlying metric names. Keep in sync with the SeriesKey
// constants in api/internal/obs/series.go.
export type ObsSeriesMetric = 'cpu' | 'mem' | 'mem_bytes' | 'disk' | 'load1';

export interface ObsSeriesPoint {
  ts: string; // RFC3339; Date.parse() friendly
  value: number;
}

// ObsSeries is what GET /api/obs/series returns — a single chart-shaped
// {nodeId, metric, points[]} bundle. The shim sizes step automatically
// for the requested range so points.length is ~120 regardless of window.
export interface ObsSeries {
  nodeId: string;
  metric: ObsSeriesMetric;
  unit: 'percent' | 'bytes' | 'load';
  range: string; // Go duration, echoed back
  step: string;
  points: ObsSeriesPoint[];
}

// ----- Backup targets (design/storage.md §4.8) ----------------------------
//
// Mirrors proto/storage.go and api/internal/storage/types.go. The picker's
// shape is `api/internal/api.backupCandidate`: everything the agent reported,
// verbatim, plus the api-minted `wipeToken`.

/**
 * How a candidate disk is attached. Reported so the operator can recognise
 * "the 2 TB USB one" in a picker — and for nothing else. It is NOT a safety
 * signal: §4.8's point is that an internal NVMe is as legitimate a backup
 * target as a USB disk, and the boot medium can be either.
 */
export type StorageTransport = 'usb' | 'nvme' | 'sata' | 'mmc' | 'virtual' | 'unknown';

/** One partition on a candidate disk — §4.8's "current contents". */
export interface StoragePartition {
  devicePath: string;
  partUuid?: string;
  fsType?: string;
  label?: string;
  sizeBytes: number;
  /** Non-empty when mounted right now. */
  mountpoint?: string;
}

/** The contents of a disk's `.rasputin-backup-set.json` marker. */
export interface StorageBackupSet {
  markerVersion: number;
  clusterId?: string;
  partUuid?: string;
  /** Identifies the §4.6 KEYPAIR these generations need. Never key material. */
  keyId?: string;
  /** Names the wrapping construction of the blobs below. */
  keyAlg?: string;
  /**
   * The §4.6 X25519 PUBLIC key, base64url of 32 raw bytes, in clear.
   *
   * Not a secret, and that is the amendment of 2026-09-02: it is everything an
   * unattended `backup.run` needs to seal a new generation, so the controlplane
   * stores no secret at all. Absent on any disk claimed under the earlier
   * symmetric design — which is how such a disk is recognised.
   */
  publicKey?: string;
  /**
   * §4.6's two SEALED copies of the PRIVATE key, carried by the disk itself.
   *
   * Ciphertext. Each is the X25519 private key under AES-256-GCM, its
   * key-encryption key derived in a browser from the operator's passphrase
   * (Argon2id) or from the recovery code (HKDF-SHA-256). They are on the disk
   * because §4.6's whole constraint is that the key cannot live on the
   * controlplane — which means a REPLACEMENT controlplane, adopting this disk
   * with an empty database, finds the sealed key here and can ask the operator
   * to open it.
   *
   * `lib/archive-key.ts`'s unlockArchiveKey is the only thing that opens them,
   * and it never returns what it recovers.
   */
  wrappedByPassphrase?: string;
  wrappedByRecoveryCode?: string;
  label?: string;
  createdAt: string;
  /** Retained archive generations the agent could see (§4.4 keeps four). */
  generations?: number;
}

/** One whole disk the operator could choose. */
export interface BackupCandidate {
  /** The kernel name AT THIS MOMENT. A handle for issuing the claim, never an identity. */
  devicePath: string;
  model?: string;
  serial?: string;
  wwn?: string;
  sizeBytes: number;
  transport: StorageTransport;
  removable: boolean;
  partitions?: StoragePartition[];
  hasBackupSet: boolean;
  backupSet?: StorageBackupSet;
  /** Holds the currently-mounted boot/persistent partitions. Rendered, never hidden. */
  protected: boolean;
  /** Operator-facing prose naming the mount that protects it. Do not parse. */
  protectedReason?: string;
  /** What the operator's confirmation binds to; re-derived by the agent before it writes. */
  fingerprint: string;
  /** Neither WWN nor serial reported, so two identical sticks can fingerprint alike. */
  identityWeak?: boolean;
  /**
   * Present ONLY when the disk is genuinely eligible to be wiped —
   * `hasBackupSet && !protected`. Its ABSENCE is the answer, not an omission:
   * with nothing to put in the field there is no wipe control to render.
   */
  wipeToken?: string;
}

export interface BackupCandidatesResponse {
  ok: boolean;
  backend: string; // "blockdev" or "mock"
  candidates: BackupCandidate[];
  /** The fingerprints are only as fresh as this. */
  ts: string;
}

/** Every value except 'pending' is terminal. */
export type BackupTargetStatus = 'pending' | 'claimed' | 'replaced' | 'failed';

/** One row of the backup_targets ledger. Wrapped key blobs are never in it. */
export interface BackupTarget {
  jobId: string;
  nodeId: string;
  label?: string;
  /** THE identifier for a claimed target, minted at format time. */
  partUuid?: string;
  /** Recorded for the operator's benefit only — nothing resolves a target by it. */
  devicePath?: string;
  mountPath?: string;
  fsType?: string;
  sizeBytes?: number;
  fingerprint?: string;
  keyId?: string;
  keyAlg?: string;
  /**
   * The §4.6 X25519 public key. Exposed, unlike the wrappings, because it is
   * not a secret and because #290's `backup.run` needs exactly this to seal a
   * generation.
   */
  publicKey?: string;
  /** Both §4.6 wrappings of the private key are on file, without exposing either. */
  hasWrappedKeys: boolean;
  adopted?: boolean;
  wiped?: boolean;
  status: BackupTargetStatus;
  createdAt: string;
  /** Absent means still running. */
  claimedAt?: string;
  error?: string;
}

/**
 * Every value except 'running' is terminal. A row still 'running' after its job
 * has finished is the #53 bug — a failed run rendering as one still in progress.
 */
export type BackupRunStatus = 'running' | 'succeeded' | 'failed';

/**
 * The scope of a generation (design/storage.md §4.5) — the generation's REACH.
 *
 * `full` is what this build writes: the control-plane database, the mesh CA
 * and Headscale state, PLUS every volume classed `critical` or `state` of
 * every installed app on EVERY node — each sealed on the node that hosts it
 * and landed as its own member of the generation through the api's ingest
 * endpoint. Reach is not outcome: `complete` says whether a run actually
 * captured everything, and `appVolumesFailed` on a `failed` row counts the
 * volumes it tried to take and could not (§4.4: failed, not skipped).
 *
 * `identity-only` and `controlplane-local` are what earlier builds wrote and
 * are still readable on disk.
 */
export type BackupScope = 'identity-only' | 'controlplane-local' | 'full';

/** One row of the backup_runs ledger. Carries no key material — a digest is not one. */
export interface BackupRun {
  jobId: string;
  /** The backup_targets row this run wrote to. The target's identity is partUuid. */
  targetJobId?: string;
  partUuid?: string;
  nodeId?: string;
  /** 'scheduled' or 'manual' — which producer (§4.1) started this run. */
  reason?: string;
  scope?: BackupScope;
  generationId?: string;
  keyId?: string;
  /** SHA-256 over the SEALED archive. The only thing that verifies it without a custody secret. */
  digest?: string;
  sizeBytes?: number;
  /** How many app volumes went into the archive. A number, so "none" is visible rather than absent. */
  appVolumesCaptured: number;
  /** How many CLASSIFIED volumes did NOT. The other half of the sentence — "2 of 3". */
  appVolumesSkipped: number;
  /**
   * Of those, how many the run TRIED to take and could not — a node offline
   * at backup time, an agent that refused, an upload that did not land.
   * Non-zero is a `failed` row with the volumes named in `error`. Absent from
   * rows written by earlier builds.
   */
  appVolumesFailed?: number;
  /** True only when every classified volume in the cluster was captured. */
  complete: boolean;
  /** A caveat on a run that is not failed — skipped volumes, or an app left down. */
  warning?: string;
  generationsKept?: number;
  generationsPruned?: number;
  status: BackupRunStatus;
  startedAt: string;
  /** Absent means still running. */
  finishedAt?: string;
  error?: string;
}

/** GET /api/backup/runs. */
export interface BackupRunsResponse {
  runs: BackupRun[];
  /**
   * The most recent SUCCESSFUL run, or null when there has never been one.
   * Null is a real answer and must render as one: "no backup has ever
   * succeeded" is not "the last one was a while ago".
   */
  lastSuccess: BackupRun | null;
  /** What an archive from this build contains. */
  scope: BackupScope;
  /** The prose caveat, authored api-side so every surface says the same words. */
  scopeWarning: string;
  /** §4.4's retained generation count. */
  retain: number;
}

/** GET/PUT /api/backup/schedule — §4.1's "weekly by default, overridable per installation". */
export interface BackupSchedule {
  /** The SCHEDULE's on/off switch. "Back up now" still works when it is off. */
  enabled: boolean;
  /** Cadence as a Go duration string, e.g. "168h". */
  every?: string;
  /** The resolved cadence in seconds — what the scheduler will actually do. */
  everySeconds: number;
  /** When the next scheduled run becomes due, or null when off / never run. */
  nextDue: string | null;
  defaultEvery: string;
  minEvery: string;
  maxEvery: string;
}

/**
 * §4.8's second, separate choice. A nested object carrying an api-minted token
 * rather than a boolean, because a boolean is one typo or one mis-bound
 * checkbox from destroying the only copy of an archive.
 */
export interface WipeConfirmation {
  token: string;
}

/**
 * Body of POST /api/backup/targets. Decoded with DisallowUnknownFields, so any
 * field not listed here is a 400 — including anything key-shaped.
 */
export interface ClaimBackupTargetRequest {
  nodeId: string;
  devicePath: string;
  fingerprint: string;
  label?: string;
  /** This cluster already has a claimed target and this one supersedes it. */
  replace?: boolean;
  /** Take the existing backup set over AS IT STANDS. Mutually exclusive with wipe. */
  adopt?: boolean;
  /** Destroy the existing backup set. Mutually exclusive with adopt. */
  wipe?: WipeConfirmation;
  /**
   * The §4.6 key material: the public key in clear and the private key already
   * wrapped under both custody paths. The private key is never plaintext here —
   * see lib/archive-key.ts.
   */
  archiveKey?: ArchiveKeyPayload;
}

// ----- Restore-before-first-boot (design/storage.md §4.5, #291) --------------
//
// GET /api/restore/candidates and POST /api/restore are open only while no
// operator exists; GET /api/backup/restores is the authenticated record.

/** One app volume named in a restore record: present in the generation (member set) or absent from it (reason set). */
export interface AppVolumeMention {
  name: string;
  class?: string;
  nodeId?: string;
  member?: string;
  sizeBytes?: number;
  reason?: string;
}

/** One generation on a candidate disk, as its clear-text manifest describes it. */
export interface RestoreGeneration {
  id: string;
  createdAt: string;
  scope?: BackupScope;
  complete: boolean;
  keyId?: string;
  clusterId?: string;
  manifestVersion: number;
  archiveBytes: number;
  identityEntries: number;
  /** App volumes the generation HOLDS — which this phase does NOT restore. */
  appVolumesPresent: AppVolumeMention[];
  /** Classified volumes the run did not capture, with the reason. */
  appVolumesAbsent: AppVolumeMention[];
  restorable: boolean;
  problem?: string;
}

/** One attached disk carrying a Rasputin backup set. */
export interface RestoreCandidate {
  nodeId: string;
  devicePath: string;
  model?: string;
  serial?: string;
  sizeBytes: number;
  transport: StorageTransport;
  removable: boolean;
  /** The disk's own marker: identifiers, the public key, and the two wrapped copies the browser unwraps. */
  marker?: StorageBackupSet;
  generations: RestoreGeneration[];
  restorable: boolean;
  problem?: string;
}

/** GET /api/restore/candidates. */
export interface RestoreCandidatesResponse {
  nodeId: string;
  /** THIS box's cluster id — the archive's must match for the restored passkeys to work. */
  clusterId: string;
  candidates: RestoreCandidate[];
  ts: string;
}

export interface RestoredEntry {
  path: string;
  sizeBytes: number;
  sha256: string;
  note?: string;
}

export interface NotRestoredItem {
  path: string;
  reason: string;
}

/** The record of one restore this cluster came back from. Never carries key material. */
export interface RestoreReport {
  id: string;
  phase: string;
  generationId: string;
  generationCreatedAt: string;
  clusterId?: string;
  keyId?: string;
  scope?: BackupScope;
  complete: boolean;
  manifestVersion: number;
  partUuid: string;
  sourceLabel?: string;
  nodeId: string;
  sealedDigest: string;
  sealedBytes: number;
  restored: RestoredEntry[];
  notRestored: NotRestoredItem[];
  /** PRESENT AND NOT RESTORED by an identity restore: app volumes are phase 2's own action. */
  appVolumesPresent: AppVolumeMention[];
  appVolumesAbsent: AppVolumeMention[];
  /** A phase-2 (app-volumes) report's own: which app, the job, and every volume considered. */
  jobId?: string;
  appId?: string;
  appName?: string;
  appVolumes?: AppVolumeRestoreRecord[];
  warning: string;
  preparedAt: string;
  appliedAt?: string;
  recordedAt?: string;
  /** Identity restores: the mesh-CA re-delivery the restore kicked once the mesh came up; absent until then. */
  trustRedelivery?: TrustRedeliveryRecord;
}

/** What the post-restore reconcile found: which enrolled nodes were re-delivered the restored mesh CA, and which had not yet said what they trust. */
export interface TrustRedeliveryRecord {
  checkedAt: string;
  caFingerprint?: string;
  redelivered: string[];
  stale: string[];
  current: string[];
  unreported: string[];
  skipped?: Record<string, number>;
  detail?: string;
}

// ----- Restoring one app's data (design/storage.md §4.5 phase 2, #291) -------

/** One volume of an app restore: restored, or failed/skipped with its reason and the restart facts. */
export interface AppVolumeRestoreRecord {
  app: string;
  appId?: string;
  volume: string;
  class?: string;
  node?: string;
  capturedFrom?: string;
  member?: string;
  restored: boolean;
  failed: boolean;
  reason?: string;
  sizeBytes?: number;
  sha256?: string;
  fileCount?: number;
  consistency?: string;
  wasRunning: boolean;
  stopped: boolean;
  downtimeMillis?: number;
  appRestored: boolean;
  restoreDetail?: string;
  previousKept?: string;
}

/** One of an app's volumes as one generation holds it, with the plan's verdict for it today. */
export interface AppRestoreVolumeView {
  volume: string;
  class: string;
  sizeBytes: number;
  fileCount: number;
  capturedFrom?: string;
  consistency?: string;
  restorable: boolean;
  reason?: string;
}

/** One generation as it concerns one app. */
export interface AppRestoreGeneration {
  id: string;
  createdAt: string;
  ageHuman: string;
  scope?: BackupScope;
  complete: boolean;
  keyId?: string;
  volumes: AppRestoreVolumeView[];
  /** "appId", or "tile+name" when the app was reinstalled since the backup. */
  matchedBy: string;
  restorable: boolean;
  problem?: string;
}

/** GET /api/apps/{id}/restore-sources. */
export interface AppRestoreSources {
  appId: string;
  appName: string;
  tileId?: string;
  installed: boolean;
  nodeId?: string;
  nodeOnline: boolean;
  target?: BackupTarget;
  /** The disk's marker: identifiers, the public key, the two wrapped copies the browser unwraps. */
  marker?: StorageBackupSet;
  declaredVolumes: { name: string; backup: string; quiesce: string }[];
  generations: AppRestoreGeneration[];
  problem?: string;
}

/** POST /api/apps/{id}/restore. The private key transits ONCE, over TLS, for one restore. */
export interface AppRestoreRequest {
  partUuid: string;
  generationId: string;
  keyId: string;
  /** base64url of the 32-byte X25519 private key. */
  privateKey: string;
  volumes?: string[];
}

/** POST /api/apps/{id}/restore's 202: the job that carries the restore. */
export interface AppRestoreResponse {
  job: Job;
  detail: string;
}

/** POST /api/restore. The private key transits ONCE, over TLS, for one restore. */
export interface RestoreStartRequest {
  partUuid: string;
  generationId: string;
  keyId: string;
  /** base64url of the 32-byte X25519 private key. */
  privateKey: string;
}

/** POST /api/restore's 202. */
export interface RestoreStartResponse {
  report: RestoreReport;
  /** The api is exiting so the unit restarts it onto the restored identity. */
  restarting: boolean;
  detail: string;
}
