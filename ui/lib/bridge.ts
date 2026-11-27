// The move's bridge (geekdojo/geekdojo-brain#1005, ui.md §5.4): a passkey
// from before the update, checked by the api against the old passkeys, gives
// a single-use grant to choose the account's first password and email. This
// module runs the passkey ceremony in the browser and makes the bridge's API
// calls; the pages that use it are /login (the offer), /login/bridge (CHOOSE
// A PASSWORD) and /settings (the pre-update prompt).

import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

/** The /login offer's words. */
export const BRIDGE_OFFER = 'Signed in here before this update? Continue with your passkey';
/** The pre-update session's prompt on /settings. */
export const PRE_UPDATE_PROMPT = "Rasputin's sign-in changed. Set your password now; this session ends within seven days.";
/** CHOOSE A PASSWORD's page. */
export const BRIDGE_CHOOSER = '/login/bridge';
/** Where a person signs in with their new password. */
export const SIGN_IN_PATH = '/api/auth/signin';

/** The sentence when the browser's passkey step ends without an answer. */
export const CEREMONY_CANCELLED = "The passkey step didn't finish. Try again.";
/** The sentence when the api's answer couldn't be read. */
export const BRIDGE_UNREACHABLE = "Rasputin couldn't be reached. Try again shortly.";

/** GET /api/auth/bridge: the offer, and the browser's own live grant. */
export interface BridgeState {
  offered: boolean;
  name?: string;
  previousName?: string;
  signInOrigin?: string;
}

/** A refusal the api answered: its status, stable code and sentence. */
export interface BridgeRefusal {
  status: number;
  code: string;
  error: string;
}

export type BridgeResult = { ok: true; next: string } | { ok: false; refusal: BridgeRefusal };

function field(body: unknown, key: string): string | undefined {
  if (body && typeof body === 'object' && key in body) {
    const v = (body as Record<string, unknown>)[key];
    return typeof v === 'string' ? v : undefined;
  }
  return undefined;
}

async function readJSON(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return undefined;
  }
}

async function post(path: string, body?: unknown): Promise<BridgeResult> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    return { ok: false, refusal: { status: 0, code: 'unreachable', error: BRIDGE_UNREACHABLE } };
  }
  const data = await readJSON(res);
  if (res.ok) return { ok: true, next: field(data, 'next') ?? '' };
  return {
    ok: false,
    refusal: { status: res.status, code: field(data, 'code') ?? '', error: field(data, 'error') ?? BRIDGE_UNREACHABLE },
  };
}

/** Reads the offer and this browser's grant. A failed read throws. */
export async function getBridge(): Promise<BridgeState> {
  const res = await fetch(`${BASE}/api/auth/bridge`, { credentials: 'include' });
  if (!res.ok) throw new Error(`/api/auth/bridge → ${res.status}`);
  return (await res.json()) as BridgeState;
}

/**
 * Runs the ceremony: begin, the browser's passkey step, finish. On success
 * the browser holds the grant's cookie and next is CHOOSE A PASSWORD.
 */
export async function runBridgeCeremony(): Promise<BridgeResult> {
  let res: Response;
  try {
    res = await fetch(`${BASE}/api/auth/bridge/begin`, { method: 'POST', credentials: 'include' });
  } catch {
    return { ok: false, refusal: { status: 0, code: 'unreachable', error: BRIDGE_UNREACHABLE } };
  }
  const options = await readJSON(res);
  if (!res.ok) {
    return {
      ok: false,
      refusal: { status: res.status, code: field(options, 'code') ?? '', error: field(options, 'error') ?? BRIDGE_UNREACHABLE },
    };
  }
  let assertion: unknown;
  try {
    const optionsJSON = (options as { publicKey: PublicKeyCredentialRequestOptionsJSON }).publicKey;
    assertion = await startAuthentication({ optionsJSON });
  } catch {
    return { ok: false, refusal: { status: 0, code: 'cancelled', error: CEREMONY_CANCELLED } };
  }
  return post('/api/auth/bridge/finish', assertion);
}

/** Sets the first password and email under this browser's grant. */
export function setFirstPassword(password: string, email: string): Promise<BridgeResult> {
  return post('/api/auth/bridge/password', { password, email });
}
