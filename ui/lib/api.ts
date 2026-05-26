import type {
  App,
  AppChangeEvent,
  FirewallChangeEvent,
  FirewallIntent,
  FirewallNodeState,
  InventoryChangeEvent,
  Job,
  JobEvent,
  JobStep,
  MetricSeries,
  Node,
  PortForwardSpec,
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

// openInventoryWS subscribes to rasputin.inventory.> change events.
export function openInventoryWS(
  onEvent: (ev: InventoryChangeEvent) => void,
): () => void {
  return openWS<InventoryChangeEvent>('/ws/inventory', onEvent);
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
