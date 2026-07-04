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
  firstSeen: string;
  lastSeen: string;
  status: NodeStatus;
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

export type AppChange = 'deployed' | 'stopped' | 'failed' | 'deleted';

export interface App {
  id: string;
  name: string;
  composeYaml: string;
  targetNode: string;
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

export interface BundleList {
  trustConfigured: boolean;
  bundles: Bundle[];
}

// "Check for Updates" — per-component report from POST /api/updates/check.
export type UpdateStatus =
  | 'up_to_date'
  | 'update_available'
  | 'no_release'
  | 'unknown';

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
  staged?: boolean;
  manualInstructions?: string;
  note?: string;
  // Software that ships inside this component's image (e.g. the control-plane
  // binary inside the OS) — shown as a display-only detail line, never with its
  // own update status.
  bundled?: { label: string; version: string }[];
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
  | 'completed'
  | 'aborted';

export interface SystemUpdateCounts {
  total: number;
  succeeded: number;
  failed: number;
  skipped: number;
}

export interface SystemUpdateChangeEvent {
  parentJobId: string;
  change: SystemUpdateChange;
  nodeId?: string;
  childJobId?: string;
  bundleId?: string;
  detail?: string;
  counts?: SystemUpdateCounts;
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
}

// Alerts — surfaced by the v0 server-side aggregator at GET /api/alerts.
// Mirror of proto/alerts.go. v0 is binary severity (no INFO tier); INFO-
// level signals live in their own affordances. Drill-through uses
// (relatedKind, relatedId).
export type AlertSeverity = 'warn' | 'crit';
// 'rule' is the source for Slice 1.5 persisted alerts that arrive from
// vmalert. The aggregator-derived sources (node/job/app/setup) carry
// their lifecycle in code; rule alerts can be acked/dismissed.
export type AlertSource = 'node' | 'job' | 'app' | 'setup' | 'rule';
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

// ObsStatus mirrors api/internal/obs/status.go's Snapshot. Returned by
// GET /api/obs/status. enabled=false means the obs stack is off
// (RASPUTIN_OBS_ENABLED not set) and the UI should render an "enable
// observability" CTA instead of dashboards.
export interface ObsStatus {
  enabled: boolean;
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
