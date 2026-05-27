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
  | 'updated';

export interface Node {
  id: string;
  role: NodeRole;
  hostname: string;
  agentVersion: string;
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

export type FirewallIntentKind = 'port_forward';
export type PortForwardProto = 'tcp' | 'udp' | 'tcpudp';

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
  spec: PortForwardSpec; // future: union with other spec types
  createdAt: string;
  updatedAt: string;
}

export interface FirewallNodeState {
  nodeId: string;
  intentHash: string;
  observedHash: string;
  lastApplied?: string;
  lastReconciled?: string;
  drift: boolean;
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
}

export interface MeshStateEnvelope {
  backend: string;
  loginServer: string;
  defaultUser: string;
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

export interface SetupState {
  steps: SetupStep[];
  completed: boolean;
  completedAt?: string;
  installName: string;
  hasUsers: boolean;
  trustConfigured: boolean;
  meshEnrolled: boolean;
  selfNodeId: string;
}
