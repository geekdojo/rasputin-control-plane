// Break-glass repair (geekdojo/geekdojo-brain#321): the /login page's repair
// link, and the /repair page's calls. The page renders only what the api
// lists: GET /api/repair/ways without a session, GET /api/repair/state with
// one. A repair session's cookie is HttpOnly; nothing here reads it.

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

/** The repair link's sentence on /login. */
export const REPAIR_LINK_SENTENCE = 'Administrator, and sign-in is broken? Use a repair code.';

/** The /repair page's WHAT HAPPENS NEXT sentence (ui.md §6). */
export function whatHappensNext(signInAt: string): string {
  return `Once sign-in is running, sign in normally at ${signInAt}.`;
}

/** Whether host is an IPv4 or IPv6 address rather than a name. */
export function isIPLiteral(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '');
  if (h.includes(':')) return /^[0-9a-f:.]+(%.+)?$/i.test(h);
  const parts = h.split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/**
 * Whether /login offers the repair link: while sign-in isn't ready, or when
 * the console was reached by its address, where sign-in can't work.
 */
export function repairLinkShown(ready: boolean, hostname: string): boolean {
  return !ready || isIPLiteral(hostname);
}

/** One way to make a repair code on this control plane. */
export interface RepairWay {
  id: string;
  text: string;
  command: string;
}

/** GET /api/repair/ways. */
export interface RepairWays {
  signInAt: string;
  ways: RepairWay[];
  urls: string[];
}

/** One thing the session may do now. */
export interface RepairAction {
  id: string;
  kind: string;
  label: string;
  enabled: boolean;
  reason?: string;
}

/** One job the session submitted. */
export interface RepairJob {
  id: string;
  kind: string;
  status: string;
  finished: boolean;
  error?: string;
}

/** GET /api/repair/state. */
export interface RepairState {
  sentence: string;
  ready: boolean;
  signInAt: string;
  actions: RepairAction[];
  jobs: RepairJob[];
}

/** A refused call's sentence. */
export class RepairError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'include',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let msg = `The control plane answered ${res.status}.`;
    try {
      const b = await res.json();
      if (typeof b?.error === 'string') msg = b.error;
    } catch {
      // the status sentence stands
    }
    throw new RepairError(msg, res.status);
  }
  return (await res.json()) as T;
}

/** The live repair session's state, or null when there is none. */
export async function getRepairState(): Promise<RepairState | null> {
  try {
    return await call<RepairState>('GET', '/api/repair/state');
  } catch (e) {
    if (e instanceof RepairError && e.status === 401) return null;
    throw e;
  }
}

/** Whether this browser holds a live repair session. */
export async function repairSessionLive(): Promise<boolean> {
  try {
    return (await getRepairState()) !== null;
  } catch {
    return false;
  }
}

export function getRepairWays(): Promise<RepairWays> {
  return call<RepairWays>('GET', '/api/repair/ways');
}

/** Redeems a typed code; the code travels only in the body. */
export async function redeemRepairCode(code: string): Promise<void> {
  await call('POST', '/api/auth/break-glass', { code });
}

export async function endRepairSession(): Promise<void> {
  await call('POST', '/api/repair/end');
}

/** Submits identity.restart for the session. */
export async function restartSignIn(): Promise<void> {
  await call('POST', '/api/repair/restart');
}
