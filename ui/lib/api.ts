import type {
  Alert,
  App,
  AppVolumesResponse,
  AppRestoreRequest,
  AppRestoreResponse,
  AppRestoreSources,
  OrphanVolumesResponse,
  ReclaimResponse,
  BackupCandidatesResponse,
  BackupRunsResponse,
  BackupSchedule,
  BackupTarget,
  ClaimBackupTargetRequest,
  BusTokenInfo,
  CatalogStatus,
  FlashableImage,
  MintedBusToken,
  AppChangeEvent,
  BMCChangeEvent,
  BMCBackendInfo,
  BMCConfigView,
  BMCPowerVerb,
  BMCState,
  Bundle,
  BundleList,
  CatalogTile,
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
  FirewallRuleSpec,
  PortForwardSpec,
  PullResult,
  RestoreCandidatesResponse,
  RestoreReport,
  RestoreStartRequest,
  RestoreStartResponse,
  WANConfigSpec,
  DeploymentMode,
  DNSForwarding,
  SetupState,
  SystemUpdateChangeEvent,
  SystemUpdatePlan,
  UpdateChangeEvent,
  UpdateCheckResult,
} from './types';
import { parseComposeResponse, type ComposeChangeBody, type ComposeOutcome } from './compose-change';

// In dev, next.config.mjs sets NEXT_PUBLIC_API_BASE to http://localhost:8080
// so the browser hits the api directly (cross-origin same-site, cookies sent
// because SameSite=Lax + CORS Allow-Credentials).
// In production, BASE is empty and the UI uses same-origin relative paths.
const BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

// ApiError is what jsonFetch throws for a non-2xx reply. The message is the
// same `${path} → ${status}: ${detail}` string it always was — everything that
// renders `String(e)` is unchanged — and the status rides along as a field so
// a caller that has to tell "this job does not exist" (404) from "the api is
// down" can do so without parsing the message.
export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** True when `e` is a jsonFetch failure with HTTP status 404. */
export function isNotFound(e: unknown): boolean {
  return e instanceof ApiError && e.status === 404;
}

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
    throw new ApiError(`${input} → ${res.status}${detail}`, res.status);
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

export function getJob(jobId: string): Promise<Job> {
  return jsonFetch<Job>(`/api/jobs/${encodeURIComponent(jobId)}`);
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
  // Every mesh device bound to the node; more than one is a duplicate
  // binding, and removal deletes them all.
  meshDeviceHsIds?: string[];
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
  onOpen?: () => void,
): () => void {
  return openWS<InventoryChangeEvent>('/ws/inventory', onEvent, onOpen);
}

// ----- Bus join tokens (node enrollment) ---------------------------------

// listBusTokens returns the secret-free token ledger. The node screen uses it
// to surface pending enrollments — bound, unrevoked tokens whose node hasn't
// come online yet.
export async function listBusTokens(): Promise<BusTokenInfo[]> {
  return (await jsonFetch<BusTokenInfo[] | null>('/api/bus/tokens')) ?? [];
}

// mintBusToken mints a join token bound to nodeId and returns the plaintext
// ONCE. The operator seeds it into the new node's enrollment file; it's
// unrecoverable afterward. Registers the binding in the live controlplane
// immediately — the node is accepted the moment it boots, no restart.
// The response carries the RENDERED seed: the api builds it with the one
// renderer (proto.RenderSeed) that rasputin-provision uses, rather than the UI
// assembling a second copy from the token and the pin.
//
// sshAuthorizedKey is the operator public key that seed carries. Pass it
// explicitly — including '' for a console/UI-only node — so the seed reflects
// what the operator typed for THIS node rather than whatever key is saved.
export function mintBusToken(
  label: string,
  nodeId: string,
  sshAuthorizedKey: string,
): Promise<MintedBusToken> {
  return jsonFetch<MintedBusToken>('/api/bus/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label, nodeId, sshAuthorizedKey }),
  });
}

// getFirewallImage resolves the latest firewall image (public download URL +
// checksum) for the Add-firewall flow. Unlike the OS node image, the firewall
// is a separate x86-only image on its own release cadence, so this returns the
// newest published build rather than one tied to the cluster's OS version.
// Returns null when the control plane can't resolve one (no release yet / no
// update channel configured) so the wizard can fall back to generic guidance.
export async function getFirewallImage(): Promise<FlashableImage | null> {
  try {
    return await jsonFetch<FlashableImage>('/api/cluster/firewall-image');
  } catch {
    return null;
  }
}

// getNodeImage resolves the OS image a NEW node should be flashed with — the
// cluster's own version, for the given architecture — with its full sha256 and,
// when the release is signed, who signed it (geekdojo/geekdojo-brain#527).
//
// The Add-node wizard's automatic path never needed this (flash.sh asks the
// same endpoint itself), but the MANUAL path did: it linked a download and told
// the operator to "verify against the checksum in the release's manifest",
// which is a checksum they then had to go and find. Returns null when the
// control plane cannot resolve one, so the wizard falls back as before.
export async function getNodeImage(arch: string): Promise<FlashableImage | null> {
  try {
    return await jsonFetch<FlashableImage>(`/api/cluster/node-image?arch=${encodeURIComponent(arch)}`);
  } catch {
    return null;
  }
}

// revokeBusToken cancels a token by id — used to cancel a pending enrollment
// that was never finished. Revoking also closes any live bus connection the
// token authenticated; DELETE returns 200 with {id, disconnected} (the count of
// connections closed), which this caller does not need.
export async function revokeBusToken(id: string): Promise<void> {
  const res = await fetch(`${BASE}/api/bus/tokens/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    throw new Error(`revokeBusToken → ${res.status}`);
  }
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

// getObsStatus returns the current obs-stack snapshot. The handler always
// 200s — `state: 'off'` means the operator hasn't turned observability on,
// NOT that the call failed.
export async function getObsStatus(): Promise<ObsStatus> {
  return jsonFetch<ObsStatus>('/api/obs/status');
}

// enableObs turns observability on. Async by necessity: a first enable pulls
// ~500 MB, so the api returns a Job rather than blocking the request. Follow
// it on /tasks, or poll getJob — see the obs.enable saga in
// api/internal/obs/jobs.go.
export function enableObs(): Promise<Job> {
  return jsonFetch<Job>('/api/obs/enable', { method: 'POST' });
}

// disableObs turns observability off and stops the stack. Recorded history
// survives — the containers stop but their volumes stay — so re-enabling
// later comes back with the past still in it.
export function disableObs(): Promise<Job> {
  return jsonFetch<Job>('/api/obs/disable', { method: 'POST' });
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

// LogEntry is the flattened, UI-facing shape of one Loki log line.
// Loki returns streams + values; we decode both into this shape so the
// drawer's Logs tab can render a single sorted list without thinking
// about LogQL response shapes.
export interface LogEntry {
  ts: string; // ISO8601 (RFC3339); derived from Loki's ns timestamp
  container: string; // empty if absent on the stream
  composeService?: string;
  stream?: string; // "stdout" | "stderr"
  line: string;
  // raw labels for debugging — kept off the hot render path
  labels: Record<string, string>;
}

interface LogsParams {
  // node label filter — accepted by the api but Loki today only
  // ships logs from the controlplane host. Forward-compat; safe to
  // always pass.
  node?: string;
  container?: string;
  grep?: string;
  // Pre-built LogQL — bypass the composed form. Power-user only.
  query?: string;
  // Go duration, defaults to "1h" server-side. We pin to the
  // drawer's range selector.
  range?: string;
  limit?: number;
}

// getObsLogs queries Loki via the api shim and decodes the streams
// response into a flat, ts-desc-sorted list. Returns [] when no entries
// matched the filter — caller renders that as "no logs in range" rather
// than treating it as an error.
export async function getObsLogs(p: LogsParams): Promise<LogEntry[]> {
  const params = new URLSearchParams();
  if (p.query) params.set('query', p.query);
  if (p.node) params.set('node', p.node);
  if (p.container) params.set('container', p.container);
  if (p.grep) params.set('grep', p.grep);
  if (p.limit) params.set('limit', String(p.limit));
  if (p.range) {
    // Loki wants RFC3339 start/end. Range is operator-shorthand —
    // do the math here so the api shim stays Loki-agnostic.
    const end = new Date();
    const ms = parseRangeMs(p.range);
    const start = new Date(end.getTime() - ms);
    params.set('start', start.toISOString());
    params.set('end', end.toISOString());
  }
  type LokiResp = {
    status: string;
    data: {
      resultType: string;
      result: Array<{
        stream: Record<string, string>;
        values: Array<[string, string]>;
      }>;
    };
  };
  const resp = await jsonFetch<LokiResp>(`/api/obs/logs?${params}`);
  const entries: LogEntry[] = [];
  for (const stream of resp.data.result ?? []) {
    const labels = stream.stream ?? {};
    for (const [nsStr, line] of stream.values ?? []) {
      const ns = Number(nsStr);
      const ms = Number.isFinite(ns) ? Math.floor(ns / 1_000_000) : Date.now();
      entries.push({
        ts: new Date(ms).toISOString(),
        container: labels.container ?? '',
        composeService: labels.compose_service,
        stream: labels.stream,
        line,
        labels,
      });
    }
  }
  entries.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
  return entries;
}

// ObsContainer mirrors api/internal/obs/containers.go's Container.
// CPU is fractional cores; mem is bytes; restarts is the cAdvisor
// start-time proxy (see backend doc).
export interface ObsContainer {
  name: string;
  image: string;
  cpuCores: number;
  memBytes: number;
  restarts: number;
}

// getObsContainers returns the cAdvisor-derived container table for
// the given node. Today the result is always the controlplane's set
// regardless of node (Alloy only ships from there); Slice 1.2b changes
// that without a UI shape change.
export async function getObsContainers(nodeId: string): Promise<ObsContainer[]> {
  const params = new URLSearchParams({ node: nodeId });
  return (await jsonFetch<ObsContainer[] | null>(`/api/obs/containers?${params}`)) ?? [];
}

function parseRangeMs(r: string): number {
  // Tiny Go-duration parser. Handles s|m|h|d suffixes — enough for the
  // RANGES the drawer exposes. Falls back to 1h on parse failure.
  const m = /^(\d+)(s|m|h|d)$/.exec(r.trim());
  if (!m) return 60 * 60 * 1000;
  const n = Number(m[1]);
  switch (m[2]) {
    case 's':
      return n * 1000;
    case 'm':
      return n * 60 * 1000;
    case 'h':
      return n * 60 * 60 * 1000;
    case 'd':
      return n * 24 * 60 * 60 * 1000;
  }
  return 60 * 60 * 1000;
}

// ----- Firewall -----------------------------------------------------------

export async function listIntents(): Promise<FirewallIntent[]> {
  return (await jsonFetch<FirewallIntent[] | null>('/api/firewall/intents')) ?? [];
}

// Discriminated union so the spec type is checked against `kind` at the call
// site (TS narrows correctly).
export type CreateIntentInput =
  | { kind: 'port_forward'; name: string; enabled?: boolean; spec: PortForwardSpec }
  | { kind: 'firewall_rule'; name: string; enabled?: boolean; spec: FirewallRuleSpec }
  | { kind: 'wan_config'; name: string; enabled?: boolean; spec: WANConfigSpec };

export function createIntent(input: CreateIntentInput): Promise<FirewallIntent> {
  return jsonFetch<FirewallIntent>('/api/firewall/intents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export function updateIntent(
  id: string,
  patch: { name?: string; enabled?: boolean; spec?: PortForwardSpec | FirewallRuleSpec | WANConfigSpec },
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
  // Opt the app into LAN reachability (ADR-0004 §9). Absent → tailnet-only.
  exposeLan?: boolean;
}): Promise<App> {
  return jsonFetch<App>('/api/apps', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

// deleteApp runs the app.delete saga (stop the deployment, then remove the
// record) and returns the job. Removal is async — the row disappears on the
// `deleted` change event once the stop completes.
//
// deleteVolumes is the operator's answer to "Delete volumes?" on the uninstall
// confirmation (geekdojo/geekdojo-brain#399), as the exact names of the volumes
// they were shown. Empty — the default, and what a caller that passes nothing
// sends — keeps every one of the app's volumes on the node, anonymous ones
// included, and they are then listed as orphans. A list must be exactly the
// app's volumes on its node, as getAppVolumes(id, { onNode: true }) lists them:
// deleting data removes every volume the app ever had (#413), so the api
// refuses a name the app does not have (400) and a list that leaves one out
// (409).
export function deleteApp(id: string, opts?: { deleteVolumes: string[] }): Promise<Job> {
  if (!opts || opts.deleteVolumes.length === 0) return jsonFetch<Job>(`/api/apps/${id}`, { method: 'DELETE' });
  return jsonFetch<Job>(`/api/apps/${id}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deleteVolumes: opts.deleteVolumes }),
  });
}

// getAppVolumes lists an app's volumes by class with when each was last
// captured into a retained backup generation — the uninstall prompt's facts.
// onNode also asks the app's node which volumes it holds for the app: the
// exact names a delete with data sends.
export function getAppVolumes(id: string, opts?: { onNode: boolean }): Promise<AppVolumesResponse> {
  return jsonFetch<AppVolumesResponse>(`/api/apps/${id}/volumes${opts?.onNode ? '?onNode=1' : ''}`);
}

// listOrphanVolumes lists rasp_<appId>_* volumes, and the anonymous volumes an
// agent recorded for an app, on every reachable node whose appId has no row in
// the apps ledger.
export function listOrphanVolumes(): Promise<OrphanVolumesResponse> {
  return jsonFetch<OrphanVolumesResponse>('/api/volumes/orphans');
}

// reclaimOrphanVolumes removes the named orphan volumes on one node. The api
// refuses an offline node (409), a live app's volume or a malformed name (400)
// before anything reaches the agent.
export function reclaimOrphanVolumes(nodeId: string, names: string[]): Promise<ReclaimResponse> {
  return jsonFetch<ReclaimResponse>('/api/volumes/orphans/reclaim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nodeId, names }),
  });
}

export function deployApp(id: string): Promise<Job> {
  return jsonFetch<Job>(`/api/apps/${id}/deploy`, { method: 'POST' });
}

// putAppCompose is PUT /api/apps/{id}/compose — every compose change: upgrade
// ({"source":"catalog"}), custom edit ({"composeYaml"}), re-apply by hash
// ({"sha256"}), each optionally with deleteVolumes (geekdojo/geekdojo-brain#414).
//
// It does not throw on a refusal, unlike jsonFetch: 200 (no-op) and 202 (job)
// are different successes, and the 409 dropped-volume answer carries a body
// the caller has to read. Only a network failure throws. The body can hold a
// custom compose, which may inline secrets: it is sent and nothing else — not
// logged, not kept.
export async function putAppCompose(id: string, body: ComposeChangeBody): Promise<ComposeOutcome> {
  const res = await fetch(`${BASE}/api/apps/${encodeURIComponent(id)}/compose`, {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    parsed = undefined;
  }
  return parseComposeResponse(res.status, parsed);
}

// ---- App catalog (curated first-party tiles) ----

export async function listCatalog(): Promise<CatalogTile[]> {
  return (await jsonFetch<CatalogTile[] | null>('/api/catalog')) ?? [];
}

export function getCatalogTile(id: string): Promise<CatalogTile> {
  return jsonFetch<CatalogTile>(`/api/catalog/${id}`);
}

// installCatalogApp declares an app from a tile (compose + primary port seeded
// from the tile); it does not deploy — call deployApp with the returned app id.
export function installCatalogApp(
  id: string,
  input: {
    targetNode: string;
    name?: string;
    exposeLan?: boolean;
    /**
     * §4.4's install-time acknowledgement (#299): the operator has read that
     * this tile's critical data will not be backed up until a target is
     * claimed. Required — the api answers 409 without it — only when the tile
     * declares a critical volume and backups are unconfigured.
     */
    acknowledgeNoBackup?: boolean;
  }
): Promise<App> {
  return jsonFetch<App>(`/api/catalog/${id}/install`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

// getCatalogStatus reports where the catalog in effect came from: its version,
// whether it was fetched or is still the embedded floor, when the last poll
// COMPLETED (null = never), and any tiles this build refused.
export function getCatalogStatus(): Promise<CatalogStatus> {
  return jsonFetch<CatalogStatus>('/api/catalog/_status');
}

// refreshCatalog asks the poller to check now. Fire-and-forget: the api answers
// 202 with NO BODY and the fetch runs in the background, so the caller re-reads
// _status to learn what happened.
//
// Raw fetch rather than jsonFetch, which unconditionally parses the response
// body. Against a bodyless 202 that throws "Unexpected end of JSON input" — so
// the request succeeds, the poller runs, and the UI reports a failure for it
// anyway. Found on e3bench 2026-08-23, the first time this ran against the real
// api; tsc, eslint and next build all pass on the broken version, because none
// of them execute a response. Same shape as revokeBusToken and the other
// no-body callers.
export async function refreshCatalog(): Promise<void> {
  const res = await fetch(`${BASE}/api/catalog/_refresh`, {
    method: 'POST',
    credentials: 'include',
  });
  if (!res.ok) {
    throw new Error(`refreshCatalog → ${res.status}`);
  }
}

// setAppExposure flips an installed app's LAN reachability in place (#197).
// Before this route, revoking LAN access meant DELETING the app — for a tile
// with volumes, choosing between the LAN and its data. Returns the updated
// record; `leafWarning` is present when the exposure change persisted but the
// proxy's TLS leaf could not be re-shipped yet (the rotation sweep retries).
export function setAppExposure(id: string, exposeLan: boolean): Promise<App & { leafWarning?: string }> {
  return jsonFetch<App & { leafWarning?: string }>(`/api/apps/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ exposeLan }),
  });
}

export function stopApp(id: string): Promise<Job> {
  return jsonFetch<Job>(`/api/apps/${id}/stop`, { method: 'POST' });
}

export function openAppsWS(
  onEvent: (ev: AppChangeEvent) => void,
  onOpen?: () => void,
): () => void {
  return openWS<AppChangeEvent>('/ws/apps', onEvent, onOpen);
}

// ----- Updates ------------------------------------------------------------

export async function listBundles(): Promise<BundleList> {
  const r = await jsonFetch<BundleList | null>('/api/bundles');
  return r ?? { trustConfigured: false, trustMode: 'unavailable', bundles: [] };
}

export interface UploadBundleInput {
  artifact: File;
  /** The detached CMS signature published beside the artifact (`<artifact>.sig`). */
  signature: File;
  version: string;
  architecture: string;
  compatible: string;
  description?: string;
}

/** POST /api/bundles takes the artifact AND its detached signature. The order
 *  of the parts is part of the contract: the api reads the signature first so
 *  an unusable one costs a kilobyte instead of the whole artifact, and it
 *  streams the artifact straight to disk once it has everything else. */
export async function uploadBundle(input: UploadBundleInput): Promise<Bundle> {
  const form = new FormData();
  form.append('signature', input.signature);
  form.append('version', input.version);
  form.append('architecture', input.architecture);
  form.append('compatible', input.compatible);
  if (input.description) form.append('description', input.description);
  form.append('artifact', input.artifact);
  const res = await fetch(`${BASE}/api/bundles`, {
    method: 'POST',
    credentials: 'include',
    // No explicit Content-Type: the browser sets multipart/form-data with the
    // boundary it generated, and overriding it makes the body unparseable.
    body: form,
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

// checkForUpdates asks the control plane to compare installed component
// versions against the latest releases on the configured channel. No bytes
// are downloaded — only the small release manifests are fetched.
export function checkForUpdates(channel?: string): Promise<UpdateCheckResult> {
  return jsonFetch<UpdateCheckResult>('/api/updates/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(channel ? { channel } : {}),
  });
}

// pullUpdate downloads EVERY deployable artifact for a component — one per
// architecture — into the local bundle store so the Deploy / Update-all flow
// can distribute it. Each arch is attempted independently: the reply lists
// what staged and what didn't, and a partial pull answers HTTP 207 rather
// than throwing, so callers must check `failed` and not just the promise.
export function pullUpdate(component: string, channel?: string): Promise<PullResult> {
  return jsonFetch<PullResult>('/api/updates/pull', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ component, ...(channel ? { channel } : {}) }),
  });
}

// createSystemUpdate kicks off a system.update saga. Returns the parent
// job; per-node child jobs are spawned by the saga and visible at
// /api/jobs?parentId=<parent.id>.
// Pass `version` (+ optional `component`, default "os") for a FLEET update —
// the plan then resolves the right per-arch bundle for each node, so a mixed
// arm64/amd64 cluster updates completely. Pass `bundleSha256` for a targeted
// run against one specific artifact. Exactly one of the two.
export function createSystemUpdate(input: {
  version?: string;
  component?: string;
  bundleSha256?: string;
  excludeNodes?: string[];
  /** Override the canary pick for a (tier, arch) pair. The plan otherwise
   *  takes the first target in planned order. At most one per pair, each must
   *  be a planned target, and never the controlplane or the firewall — the
   *  plan rejects the run rather than quietly canarying somebody else. */
  canaryNodes?: string[];
  /** How many nodes of one TIER update at once — `4` or `"20%"`, default 4.
   *  Always clamped to `min(k, max(1, tierSize - 1))`. tierSize includes the
   *  canary, so the clamp does not hold a node back: at the default 4, every
   *  post-canary node in a tier of five or fewer starts at once. `1` is the old
   *  serial cascade exactly. */
  maxInFlight?: number | string;
  /** How many nodes of one TIER may fail before the cascade stops STARTING new
   *  ones — `3` or `"15%"`, default `"15%"`. In-flight nodes finish. An
   *  absolute `0` means unlimited; a percentage that rounds to zero floors to
   *  1, because a percentage is a request for a proportionate brake and never
   *  a request to remove it. */
  maxFailures?: number | string;
  /** Hold each tier's fan-out this long after its canaries pass. Defaults to
   *  0 and is expected to stay there; the health battery that gates mark-good
   *  is already synchronous. Max 3600. */
  canarySoakSeconds?: number;
}): Promise<Job> {
  return jsonFetch<Job>('/api/updates/system', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

// previewSystemUpdatePlan resolves what a system.update WOULD do — ordered
// targets, per-arch canary picks, reasoned skips — without submitting a job.
// Same body as createSystemUpdate; powers the pre-flight drawer (#95).
export function previewSystemUpdatePlan(input: {
  version?: string;
  component?: string;
  bundleSha256?: string;
  excludeNodes?: string[];
  canaryNodes?: string[];
}): Promise<SystemUpdatePlan> {
  return jsonFetch<SystemUpdatePlan>('/api/updates/system/plan', {
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

// PATCH /api/mesh/keys/{id} — only name + deviceHint are editable. user /
// reusable / tags / expiresIn are bound at mint and rejected with 400 if sent.
export function updateMeshKey(
  id: string,
  patch: { name?: string; deviceHint?: string },
): Promise<MeshIntent> {
  return jsonFetch<MeshIntent>(`/api/mesh/keys/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  });
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

export function updateMeshRoute(
  id: string,
  patch: { name?: string; enabled?: boolean; nodeId?: string; cidr?: string },
): Promise<MeshIntent> {
  return jsonFetch<MeshIntent>(`/api/mesh/routes/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
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

// getBMCBackends returns the platform's supported-backends list — the
// Settings picker renders this served data, never a hardcoded copy.
export function getBMCBackends(): Promise<BMCBackendInfo[]> {
  return jsonFetch<BMCBackendInfo[]>('/api/bmc/backends');
}

// getBMCConfig returns the current selection (sanitized: the bitscope
// unlock is write-only and surfaced as unlockSet).
export function getBMCConfig(): Promise<BMCConfigView> {
  return jsonFetch<BMCConfigView>('/api/bmc/config');
}

// setBMCConfig submits a bmc.configure job; settings persist only after
// the host agent acks the push. kind '' / 'none' turns BMC off.
export function setBMCConfig(req: { kind: string; hostNodeId?: string; config?: unknown }): Promise<Job> {
  return jsonFetch<Job>('/api/bmc/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
}

export type BMCProbeSlot = {
  slot: number;
  powered: boolean;
  hostname?: string;
  nodeId?: string;
  detail?: string;
};

export type BMCProbeResult = {
  ok: boolean;
  slots?: BMCProbeSlot[];
  endpoint?: string;
  // pin is the device pin for the key the board presented — the same encoding
  // as the cluster bus pin ("sha256/" + base64). It replaced a cert-DER
  // fingerprint: the board's web UI displays no fingerprint to compare
  // against, so there was nothing the second form bought.
  pin?: string;
  identified?: boolean;
  certSubject?: string;
  detail?: string;
};

// probeBMC asks the BMC-host agent to find a board and capture the key it
// presents. Runs before any backend is configured and needs no credentials —
// it exists so Settings can offer discovery instead of asking for an IP and a
// pin the operator would have to go and read out of openssl themselves.
//
// `pin` carries back the pin the operator has already accepted; the agent
// sends credentials only when the board is still presenting that key.
export function probeBMC(req: { kind?: string; endpoint?: string; user?: string; pass?: string; pin?: string }): Promise<BMCProbeResult> {
  return jsonFetch<BMCProbeResult>('/api/bmc/probe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
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

// DNS forwarding (AA-11) — whether the CP answers DNS for the whole LAN, and the
// upstream it forwards non-internal lookups to.
export function getDNSForwarding(): Promise<DNSForwarding> {
  return jsonFetch<DNSForwarding>('/api/settings/dns-forwarding');
}

export function setDNSForwarding(input: { enabled: boolean; upstream: string }): Promise<DNSForwarding> {
  return jsonFetch<DNSForwarding>('/api/settings/dns-forwarding', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

export function setInstallName(name: string): Promise<SetupState> {
  return jsonFetch<SetupState>('/api/setup/install-name', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
}

// Persist the deployment-mode choice. Throws on 400 (invalid) or 412 (a
// firewall-running mode was picked with no firewall node registered) —
// callers surface the message.
export function setDeploymentMode(mode: DeploymentMode): Promise<SetupState> {
  return jsonFetch<SetupState>('/api/setup/mode', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode }),
  });
}

export function setupEnrollSelf(): Promise<Job> {
  return jsonFetch<Job>('/api/setup/mesh', { method: 'POST' });
}

// ----- Operator SSH key -----------------------------------------------------

// The one operator SSH public key the Add-node wizard prefills. It is written
// into the seeds of nodes enrolled from now on and changes nothing on nodes
// already enrolled. `key` is '' when none is saved; `captured: false` means
// never set (the wizard remembers the key used on the next enrollment);
// `ignoredKeys` counts extra keys left by the old list UI, which have no
// effect and are dropped by the next save or clear.
export type OperatorKey = { key: string; captured: boolean; ignoredKeys: number };

export function getOperatorKey(): Promise<OperatorKey> {
  return jsonFetch<OperatorKey>('/api/enroll/operator-key');
}

// Replaces the saved key, or clears it with ''. A clear is an explicit "don't
// prefill" and sticks.
export function setOperatorKey(key: string): Promise<OperatorKey> {
  return jsonFetch<OperatorKey>('/api/enroll/operator-key', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
}

// ----- Console root password (geekdojo/geekdojo-brain#587, dec #558) ------
//
// The password root uses at a node's console. Nothing here ever carries the
// password or its hash: `hashId` NAMES the stored password so the UI can say
// which one a node holds, and that is all the api will hand out.

// One node's delivery record.
export type ConsoleRootNode = {
  nodeId: string;
  status: 'applied' | 'pending' | 'failed';
  // The password this node holds, by id; '' when it holds none we know of.
  hashId?: string;
  detail?: string;
  jobId?: string;
  updatedAt: string;
  // Whether hashId is the password currently stored.
  current: boolean;
};

export type ConsoleRootStatus = {
  set: boolean;
  hashId?: string;
  setAt?: string;
  nodes: ConsoleRootNode[];
};

export type ConsoleRootSaved = {
  hashId: string;
  // The push job applying it, when one was submitted.
  jobId?: string;
  // Set when the password was saved but the push could not start. The
  // password IS saved — offer the re-apply action, don't ask for a retype.
  pushError?: string;
};

export function getConsoleRootPassword(): Promise<ConsoleRootStatus> {
  return jsonFetch<ConsoleRootStatus>('/api/console/root-password');
}

// Stores the password (hashed api-side) and, unless push is false, submits
// the job that applies it to every node.
export function setConsoleRootPassword(password: string, push = true): Promise<ConsoleRootSaved> {
  return jsonFetch<ConsoleRootSaved>('/api/console/root-password', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password, push }),
  });
}

// Re-applies the stored password to every node. Re-runnable.
export function pushConsoleRootPassword(): Promise<ConsoleRootSaved> {
  return jsonFetch<ConsoleRootSaved>('/api/console/root-password/push', { method: 'POST' });
}

export function completeSetup(): Promise<SetupState> {
  return jsonFetch<SetupState>('/api/setup/complete', { method: 'POST' });
}

// ----- Backup targets (design/storage.md §4.8) ----------------------------

// listBackupCandidates lists every whole disk on a node, PROTECTED ONES
// INCLUDED. Read-only — it mutates nothing here or on the agent, and it is a
// plain RPC rather than a job because an operator cannot choose from a list
// only a running job could produce.
//
// Omitting nodeId lets the api default to the node hosting it, which on an
// appliance is where the backup disk almost always is.
export function listBackupCandidates(nodeId?: string): Promise<BackupCandidatesResponse> {
  const q = nodeId ? `?${new URLSearchParams({ nodeId })}` : '';
  return jsonFetch<BackupCandidatesResponse>(`/api/backup/candidates${q}`);
}

// listBackupTargets returns every claim attempt, newest first — failures
// included, which is the point of keeping them: "the claim you started an hour
// ago was refused because that disk holds the boot partition" is the most
// useful thing this view says.
export async function listBackupTargets(): Promise<BackupTarget[]> {
  return (await jsonFetch<BackupTarget[] | null>('/api/backup/targets')) ?? [];
}

// claimBackupTarget submits the backup.target.claim saga. THIS IS THE CALL
// THAT CAN FORMAT A DISK — every §4.8 refusal is evaluated inside the saga, in
// order, before the one destructive step runs.
//
// `archiveKey` carries §4.6's public key in clear and its private key already
// wrapped when it gets here (lib/archive-key.ts). No private key or passphrase
// can reach this function: there is no parameter for one, and the api decodes
// with DisallowUnknownFields so an invented field would be a 400 rather than a
// secret in the job ledger.
export function claimBackupTarget(req: ClaimBackupTargetRequest): Promise<Job> {
  return jsonFetch<Job>('/api/backup/targets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
}

// ----- Backup runs (design/storage.md §4.1) -------------------------------

// listBackupRuns returns the run ledger, failures INCLUDED, plus the last
// successful run and the scope caveat.
//
// The wrapper is not ceremony: §4.4 requires a failed backup to be loud, and
// the two things that make it loud — "when did one last actually succeed" and
// "what does an archive from this build even contain" — are not derivable from
// a page of recent rows.
export function listBackupRuns(limit?: number): Promise<BackupRunsResponse> {
  const q = limit ? `?${new URLSearchParams({ limit: String(limit) })}` : '';
  return jsonFetch<BackupRunsResponse>(`/api/backup/runs${q}`);
}

// startBackupRun is §4.1's on-demand "Back up now". It submits the SAME saga
// the weekly schedule submits, with the same refusals in the same order —
// there is no express path for a manual run, because the checks it would skip
// are the ones that stop a backup filling the disk it protects.
//
// A 409 means one is already running.
export function startBackupRun(): Promise<Job> {
  return jsonFetch<Job>('/api/backup/runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
}

// getBackupSchedule reads the cadence and the retention depth;
// setBackupSchedule writes both. A cadence change takes effect on the
// scheduler's next check rather than at the next api restart; a retention
// change on the next run's prune. The PUT body is the whole setting — send
// every field, or the ones left out revert to their defaults.
export function getBackupSchedule(): Promise<BackupSchedule> {
  return jsonFetch<BackupSchedule>('/api/backup/schedule');
}

export type BackupScheduleRequest = { enabled: boolean; every?: string; retain?: number };

export function setBackupSchedule(req: BackupScheduleRequest): Promise<BackupSchedule> {
  return jsonFetch<BackupSchedule>('/api/backup/schedule', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
}

// ----- WebSocket plumbing -------------------------------------------------

// openWS opens a resilient WebSocket: logs lifecycle events, parses each
// frame as T, calls onEvent. On unexpected close it reconnects with
// exponential backoff (capped at 30s). Returns a close function that stops
// reconnects.
//
// onOpen fires on every (re)connect — callers use it to RE-FETCH the current
// state, so any events missed while the socket was down (a reconnect gap, a
// laptop sleep, a proxy idle-timeout) are caught up instead of leaving the UI
// stale until the next event.
function openWS<T>(path: string, onEvent: (ev: T) => void, onOpen?: () => void): () => void {
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
      onOpen?.();
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

// ----- Restore-before-first-boot (design/storage.md §4.5, #291) ------------

// listRestoreCandidates lists the disks beside this controlplane that carry a
// Rasputin backup set, with their generations. Open only while no operator
// exists — 409 afterwards, for the life of the installation.
export function listRestoreCandidates(): Promise<RestoreCandidatesResponse> {
  return jsonFetch<RestoreCandidatesResponse>('/api/restore/candidates');
}

// startRestore prepares a restore of one generation's identity set and asks
// the api to restart onto it. Callers do not build this request by hand — see
// lib/restore.ts, which is the only path that holds the private key, and
// only for the duration of this call.
export function startRestore(req: RestoreStartRequest): Promise<RestoreStartResponse> {
  return jsonFetch<RestoreStartResponse>('/api/restore', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
}

// listRestores is the record of every restore this cluster came back from,
// newest first. Authenticated.
export async function listRestores(): Promise<RestoreReport[]> {
  return (await jsonFetch<RestoreReport[] | null>('/api/backup/restores')) ?? [];
}

// ----- Restoring one app's data (design/storage.md §4.5 phase 2, #291) -------

// getAppRestoreSources lists the generations on the backup target that hold
// this app's volumes, with the disk's wrapped key for the browser to open.
export function getAppRestoreSources(id: string): Promise<AppRestoreSources> {
  return jsonFetch<AppRestoreSources>(`/api/apps/${id}/restore-sources`);
}

// startAppRestore submits the restore of one app's data from one generation.
// Callers do not build this request by hand — see lib/app-restore.ts, which
// is the only path that holds the private key, and only for this call.
export function startAppRestore(id: string, req: AppRestoreRequest): Promise<AppRestoreResponse> {
  return jsonFetch<AppRestoreResponse>(`/api/apps/${id}/restore`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
}
