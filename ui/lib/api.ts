import type {
  FirewallChangeEvent,
  FirewallIntent,
  FirewallNodeState,
  InventoryChangeEvent,
  Job,
  JobEvent,
  JobStep,
  Node,
  PortForwardSpec,
} from './types';

// Empty string = use the Next.js dev rewrite (next.config.mjs) which proxies
// /api/* and /ws/* to rasputin-api on :8080. Override with NEXT_PUBLIC_API_BASE
// (e.g. "http://localhost:8080") to hit the api directly.
const BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

async function jsonFetch<T>(input: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${input}`, init);
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

function openWS<T>(path: string, onEvent: (ev: T) => void): () => void {
  const url = wsURL(path);
  const ws = new WebSocket(url);
  ws.onmessage = (m) => {
    try {
      onEvent(JSON.parse(m.data) as T);
    } catch (err) {
      console.error(`ws parse ${path}`, err);
    }
  };
  ws.onerror = (e) => console.warn(`ws error ${path}`, e);
  return () => ws.close();
}

function wsURL(path: string): string {
  if (BASE.startsWith('http')) {
    return BASE.replace(/^http/, 'ws') + path;
  }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}${path}`;
}
