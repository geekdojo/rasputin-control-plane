import type {
  Alert,
  App,
  AppChangeEvent,
  BMCChangeEvent,
  BMCPowerVerb,
  BMCState,
  Bundle,
  BundleList,
  FirewallChangeEvent,
  FirewallIntent,
  FirewallNodeState,
  InventoryChangeEvent,
  Job,
  JobEvent,
  JobStep,
  MeshChangeEvent,
  MeshDevice,
  MeshIntent,
  MeshStateEnvelope,
  MetricSeries,
  Node,
  NodeUpdate,
  ObsSeries,
  ObsSeriesMetric,
  ObsStatus,
  PortForwardSpec,
  SetupState,
  SystemUpdateChangeEvent,
  UpdateChangeEvent,
} from './types';

// In dev, next.config.mjs sets NEXT_PUBLIC_API_BASE to http://localhost:8080
// so the browser hits the api directly (cross-origin same-site, cookies sent
// because SameSite=Lax + CORS Allow-Credentials).
// In production, BASE is empty and the UI uses same-origin relative paths.
const BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

async function jsonFetch<T>(input: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${input}`, {
    credentials: 'include',
    ...init,
  });
  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      detail = body?.error ? `: ${body.error}` : '';
    } catch {
      // ignore body parse failure
    }
    throw new Error(`${input} → ${res.status}${detail}`);
  }
  return (await res.json()) as T;
}

export type MetricsRange = '5m' | '15m' | '1h' | '6h' | '24h';

export function getMetrics(
  nodeId: string,
  range: MetricsRange = '15m',
  names?: string[],
): Promise<MetricSeries> {
  const params = new URLSearchParams({ range });
  if (names && names.length > 0) params.set('metric', names.join(','));
  return jsonFetch<MetricSeries>(`/api/metrics/${nodeId}?${params}`);
}

export function createJob(kind: string, spec: unknown): Promise<Job> {
  return jsonFetch<Job>('/api/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind, spec }),
  });
}

export async function listJobs(limit = 50): Promise<Job[]> {
  return (await jsonFetch<Job[] | null>(`/api/jobs?limit=${limit}`)) ?? [];
}

export async function listSteps(jobId: string): Promise<JobStep[]> {
  return (await jsonFetch<JobStep[] | null>(`/api/jobs/${jobId}/steps`)) ?? [];
}

export async function listEvents(jobId: string): Promise<JobEvent[]> {
  return (await jsonFetch<JobEvent[] | null>(`/api/jobs/${jobId}/events`)) ?? [];
}

// openJobsWS subscribes to rasputin.job.> live events. Returns a close fn.
export function openJobsWS(onEvent: (ev: JobEvent) => void): () => void {
  return openWS<JobEvent>('/ws/jobs', onEvent);
}

export async function listNodes(): Promise<Node[]> {
  return (await jsonFetch<Node[] | null>('/api/nodes')) ?? [];
}

export interface NodeRemovalImpact {
  nodeId: string;
  appIds: string[];
  meshDeviceHsId?: string;
  hasFirewallState: boolean;
}

// getNodeRemovalImpact previews what a DELETE /api/nodes/{id} would
// cascade to. Read-only; safe to call from the confirm dialog while the
// user is still deciding.
export async function getNodeRemovalImpact(id: string): Promise<NodeRemovalImpact> {
  return jsonFetch<NodeRemovalImpact>(`/api/nodes/${encodeURIComponent(id)}/removal-impact`);
}

// deleteNode removes a node from inventory and cascades app deployments,
// mesh enrollment, and firewall state. Returns the impact summary so the
// caller can show "removed N apps" feedback. There is no v1 blocklist —
// a re-registering agent will re-appear in inventory.
export async function deleteNode(id: string): Promise<NodeRemovalImpact> {
  return jsonFetch<NodeRemovalImpact>(`/api/nodes/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

// openInventoryWS subscribes to rasputin.inventory.> change events.
export function openInventoryWS(
  onEvent: (ev: InventoryChangeEvent) => void,
): () => void {
  return openWS<InventoryChangeEvent>('/ws/inventory', onEvent);
}

// ----- Alerts -------------------------------------------------------------

// listAlerts returns the current snapshot of active alerts. The Slice
// 1.5 work added a live /ws/alerts push topic that lands AlertChangeEvt
// records; the alerts page can subscribe via openAlertsWS when it wants
// faster-than-poll updates. Aggregator-derived alerts (node/job/app/
// setup) still piggyback on inventory + job WS like before.
export async function listAlerts(): Promise<Alert[]> {
  return (await jsonFetch<Alert[] | null>('/api/alerts')) ?? [];
}

// ackAlert / dismissAlert are valid only for source=rule entries
// (Slice 1.5 persisted alerts). Aggregator-derived entries don't carry
// ack state — their lifecycle is computed-on-read.
export function ackAlert(id: string): Promise<Alert> {
  return jsonFetch<Alert>(`/api/alerts/${encodeURIComponent(id)}/ack`, { method: 'POST' });
}
export function dismissAlert(id: string): Promise<Alert> {
  return jsonFetch<Alert>(`/api/alerts/${encodeURIComponent(id)}/dismiss`, { method: 'POST' });
}

// openAlertsWS subscribes to AlertChangeEvt push notifications.
// Returns a close fn (matches openJobsWS / openInventoryWS shape).
export function openAlertsWS(onChange: (raw: unknown) => void): () => void {
  return openWS<unknown>('/ws/alerts', onChange);
}

// ----- Observability ------------------------------------------------------

// getObsStatus returns the current obs-stack snapshot. The handler
// always 200s — `enabled: false` means RASPUTIN_OBS_ENABLED wasn't set
// at startup, NOT that the call failed. The UI uses this to render an
// "enable observability" CTA on /metrics rather than 404-style errors.
export async function getObsStatus(): Promise<ObsStatus> {
  return jsonFetch<ObsStatus>('/api/obs/status');
}

// getObsSeries fetches a chart-shaped {ts, value}[] for one node + one
// metric over a Go-duration range. The api caps range at 24h and sizes
// step automatically so a "30m" and a "24h" call both return ~120
// points — the UI doesn't have to think about resolution. Returns an
// empty points array when no samples landed yet (cold start).
export function getObsSeries(
  nodeId: string,
  metric: ObsSeriesMetric,
  range: string = '30m',
): Promise<ObsSeries> {
  const params = new URLSearchParams({
    node: nodeId,
    metric,
    range,
  });
  return jsonFetch<ObsSeries>(`/api/obs/series?${params}`);
}

// ----- Firewall -----------------------------------------------------------

export async function listIntents(): Promise<FirewallIntent[]> {
  return (await jsonFetch<FirewallIntent[] | null>('/api/firewall/intents')) ?? [];
}

export function createIntent(input: {
  kind: 'port_forward';
  name: string;
  enabled?: boolean;
  spec: PortForwardSpec;
}): Promise<FirewallIntent> {
  return jsonFetch<FirewallIntent>('/api/firewall/intents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export function updateIntent(
  id: string,
  patch: { name?: string; enabled?: boolean; spec?: PortForwardSpec },
): Promise<FirewallIntent> {
  return jsonFetch<FirewallIntent>(`/api/firewall/intents/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  });
}

export async function deleteIntent(id: string): Promise<void> {
  const res = await fetch(`${BASE}/api/firewall/intents/${id}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`deleteIntent: ${res.status}`);
  }
}

export async function listFirewallState(): Promise<FirewallNodeState[]> {
  return (await jsonFetch<FirewallNodeState[] | null>('/api/firewall/state')) ?? [];
}

export function applyFirewall(): Promise<Job> {
  return jsonFetch<Job>('/api/firewall/apply', { method: 'POST' });
}

export function reconcileFirewall(): Promise<Job> {
  return jsonFetch<Job>('/api/firewall/reconcile', { method: 'POST' });
}

export function openFirewallWS(
  onEvent: (ev: FirewallChangeEvent) => void,
): () => void {
  return openWS<FirewallChangeEvent>('/ws/firewall', onEvent);
}

// ----- Apps ---------------------------------------------------------------

export async function listApps(): Promise<App[]> {
  return (await jsonFetch<App[] | null>('/api/apps')) ?? [];
}

export function createApp(input: {
  name: string;
  composeYaml: string;
  targetNode: string;
}): Promise<App> {
  return jsonFetch<App>('/api/apps', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export async function deleteApp(id: string): Promise<void> {
  const res = await fetch(`${BASE}/api/apps/${id}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`deleteApp: ${res.status}`);
  }
}

export function deployApp(id: string): Promise<Job> {
  return jsonFetch<Job>(`/api/apps/${id}/deploy`, { method: 'POST' });
}

export function stopApp(id: string): Promise<Job> {
  return jsonFetch<Job>(`/api/apps/${id}/stop`, { method: 'POST' });
}

export function openAppsWS(
  onEvent: (ev: AppChangeEvent) => void,
): () => void {
  return openWS<AppChangeEvent>('/ws/apps', onEvent);
}

// ----- Updates ------------------------------------------------------------

export async function listBundles(): Promise<BundleList> {
  const r = await jsonFetch<BundleList | null>('/api/bundles');
  return r ?? { trustConfigured: false, bundles: [] };
}

export async function uploadBundle(file: File): Promise<Bundle> {
  const res = await fetch(`${BASE}/api/bundles`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: file,
  });
  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      detail = body?.error ? `: ${body.error}` : '';
    } catch {
      // ignore
    }
    throw new Error(`uploadBundle → ${res.status}${detail}`);
  }
  return (await res.json()) as Bundle;
}

export async function deleteBundle(sha256: string): Promise<void> {
  const res = await fetch(`${BASE}/api/bundles/${sha256}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`deleteBundle → ${res.status}`);
  }
}

export function createUpdate(input: {
  nodeId: string;
  bundleSha256: string;
}): Promise<Job> {
  return jsonFetch<Job>('/api/updates', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export async function listUpdates(
  nodeId?: string,
  limit = 50,
): Promise<NodeUpdate[]> {
  const params = new URLSearchParams();
  if (nodeId) params.set('nodeId', nodeId);
  params.set('limit', String(limit));
  return (
    (await jsonFetch<NodeUpdate[] | null>(`/api/updates?${params}`)) ?? []
  );
}

export function openUpdatesWS(
  onEvent: (ev: UpdateChangeEvent) => void,
): () => void {
  return openWS<UpdateChangeEvent>('/ws/updates', onEvent);
}

// createSystemUpdate kicks off a system.update saga. Returns the parent
// job; per-node child jobs are spawned by the saga and visible at
// /api/jobs?parentId=<parent.id>.
export function createSystemUpdate(input: {
  bundleSha256: string;
  excludeNodes?: string[];
}): Promise<Job> {
  return jsonFetch<Job>('/api/updates/system', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

// listChildJobs returns the children of a given parent job (used for the
// system update per-node rollup).
export async function listChildJobs(parentId: string): Promise<Job[]> {
  return (
    (await jsonFetch<Job[] | null>(
      `/api/jobs?parentId=${encodeURIComponent(parentId)}`,
    )) ?? []
  );
}

// openSystemUpdatesWS subscribes to system-wide update lifecycle events.
export function openSystemUpdatesWS(
  onEvent: (ev: SystemUpdateChangeEvent) => void,
): () => void {
  return openWS<SystemUpdateChangeEvent>('/ws/updates/system', onEvent);
}

// ----- Mesh ---------------------------------------------------------------

export async function getMeshState(): Promise<MeshStateEnvelope> {
  return jsonFetch<MeshStateEnvelope>('/api/mesh/state');
}

export async function listMeshDevices(): Promise<MeshDevice[]> {
  return (await jsonFetch<MeshDevice[] | null>('/api/mesh/devices')) ?? [];
}

export async function deleteMeshDevice(hsId: string): Promise<void> {
  const res = await fetch(`${BASE}/api/mesh/devices/${encodeURIComponent(hsId)}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`deleteMeshDevice → ${res.status}`);
  }
}

export async function listMeshKeys(): Promise<MeshIntent[]> {
  return (await jsonFetch<MeshIntent[] | null>('/api/mesh/keys')) ?? [];
}

export function createMeshKey(input: {
  name: string;
  deviceHint?: string;
  reusable?: boolean;
  ephemeral?: boolean;
  expiresIn?: string;
  tags?: string[];
}): Promise<MeshIntent> {
  return jsonFetch<MeshIntent>('/api/mesh/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export async function deleteMeshKey(id: string): Promise<void> {
  const res = await fetch(`${BASE}/api/mesh/keys/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`deleteMeshKey → ${res.status}`);
  }
}

export async function listMeshRoutes(): Promise<MeshIntent[]> {
  return (await jsonFetch<MeshIntent[] | null>('/api/mesh/routes')) ?? [];
}

export function createMeshRoute(input: {
  name: string;
  nodeId: string;
  cidr: string;
}): Promise<MeshIntent> {
  return jsonFetch<MeshIntent>('/api/mesh/routes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export async function deleteMeshRoute(id: string): Promise<void> {
  const res = await fetch(`${BASE}/api/mesh/routes/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`deleteMeshRoute → ${res.status}`);
  }
}

export function applyMesh(): Promise<Job> {
  return jsonFetch<Job>('/api/mesh/apply', { method: 'POST' });
}

export function reconcileMesh(): Promise<Job> {
  return jsonFetch<Job>('/api/mesh/reconcile', { method: 'POST' });
}

export function enrollMeshNode(
  nodeId: string,
  advertiseRoutes?: string[],
): Promise<Job> {
  return jsonFetch<Job>(`/api/mesh/enroll/${encodeURIComponent(nodeId)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ advertiseRoutes: advertiseRoutes ?? [] }),
  });
}

export function openMeshWS(
  onEvent: (ev: MeshChangeEvent) => void,
): () => void {
  return openWS<MeshChangeEvent>('/ws/mesh', onEvent);
}

// ----- BMC ----------------------------------------------------------------

export async function listBMCStates(): Promise<BMCState[]> {
  return (await jsonFetch<BMCState[] | null>('/api/bmc')) ?? [];
}

export async function getBMCStatus(nodeId: string): Promise<BMCState> {
  return jsonFetch<BMCState>(
    `/api/bmc/${encodeURIComponent(nodeId)}/status`,
  );
}

// bmcPower kicks off a bmc.power job for the given target + verb.
// Verb 'status' is a read-only refresh that updates the persisted state.
export function bmcPower(nodeId: string, verb: BMCPowerVerb): Promise<Job> {
  return jsonFetch<Job>(
    `/api/bmc/${encodeURIComponent(nodeId)}/power/${verb}`,
    { method: 'POST' },
  );
}

export function openBMCWS(
  onEvent: (ev: BMCChangeEvent) => void,
): () => void {
  return openWS<BMCChangeEvent>('/ws/bmc', onEvent);
}

// bmcSOLURL returns the absolute ws:// or wss:// URL for the SOL endpoint.
// Used by the console page to construct a WebSocket directly.
export function bmcSOLURL(nodeId: string): string {
  return wsURL(`/ws/bmc/${encodeURIComponent(nodeId)}/sol`);
}

// ----- Setup wizard -------------------------------------------------------

// GET /api/setup/state is intentionally unauthenticated — the wizard runs
// before the first passkey exists. Returns no secrets.
export async function getSetupState(): Promise<SetupState> {
  return jsonFetch<SetupState>('/api/setup/state');
}

export function setInstallName(name: string): Promise<SetupState> {
  return jsonFetch<SetupState>('/api/setup/install-name', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
}

export function setupEnrollSelf(): Promise<Job> {
  return jsonFetch<Job>('/api/setup/mesh', { method: 'POST' });
}

export function completeSetup(): Promise<SetupState> {
  return jsonFetch<SetupState>('/api/setup/complete', { method: 'POST' });
}

// ----- WebSocket plumbing -------------------------------------------------

// openWS opens a resilient WebSocket: logs lifecycle events, parses each
// frame as T, calls onEvent. On unexpected close it reconnects with
// exponential backoff (capped at 30s). Returns a close function that stops
// reconnects.
function openWS<T>(path: string, onEvent: (ev: T) => void): () => void {
  let ws: WebSocket | null = null;
  let closed = false;
  let backoff = 1000;
  const url = wsURL(path);

  const connect = () => {
    if (closed) return;
    ws = new WebSocket(url);
    ws.onopen = () => {
      console.info(`ws open ${path}`);
      backoff = 1000; // reset
    };
    ws.onmessage = (m) => {
      try {
        onEvent(JSON.parse(m.data) as T);
      } catch (err) {
        console.error(`ws parse ${path}`, err);
      }
    };
    ws.onerror = (e) => console.warn(`ws error ${path}`, e);
    ws.onclose = (e) => {
      if (closed) return;
      console.warn(`ws closed ${path} (code=${e.code} reason=${e.reason}); reconnecting in ${backoff}ms`);
      setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 30_000);
    };
  };

  connect();

  return () => {
    closed = true;
    if (ws) ws.close();
  };
}

function wsURL(path: string): string {
  if (BASE.startsWith('http')) {
    return BASE.replace(/^http/, 'ws') + path;
  }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}${path}`;
}
