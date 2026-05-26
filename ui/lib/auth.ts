import {
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

export interface CurrentUser {
  id: string;
  name: string;
  displayName: string;
  createdAt: string;
  lastLoginAt?: string;
}

export interface AuthStatus {
  hasUsers: boolean;
  userCount: number;
  user?: CurrentUser;
}

async function jsonFetch<T>(input: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${input}`, {
    credentials: 'same-origin',
    ...init,
  });
  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      if (body?.error) detail = `: ${body.error}`;
    } catch {
      // ignore
    }
    const err: AuthError = new Error(`${input} → ${res.status}${detail}`);
    err.status = res.status;
    throw err;
  }
  return (await res.json()) as T;
}

export interface AuthError extends Error {
  status?: number;
}

export function getStatus(): Promise<AuthStatus> {
  return jsonFetch<AuthStatus>('/api/auth/status');
}

export async function getMe(): Promise<CurrentUser | null> {
  try {
    return await jsonFetch<CurrentUser>('/api/auth/me');
  } catch (e) {
    const err = e as AuthError;
    if (err.status === 401) return null;
    throw e;
  }
}

export async function logout(): Promise<void> {
  await fetch(`${BASE}/api/auth/logout`, {
    method: 'POST',
    credentials: 'same-origin',
  });
}

// go-webauthn returns { publicKey: { ... } }; SimpleWebAuthn wants the inner
// publicKey object as optionsJSON.
function unwrapPublicKey(opts: unknown): Record<string, unknown> {
  const o = opts as { publicKey?: Record<string, unknown> };
  return (o.publicKey ?? (opts as Record<string, unknown>));
}

export async function registerPasskey(
  name: string,
  displayName?: string,
): Promise<CurrentUser> {
  const opts = await jsonFetch<unknown>('/api/auth/register/begin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, displayName: displayName ?? name }),
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const credential = await startRegistration({ optionsJSON: unwrapPublicKey(opts) as any });
  return jsonFetch<CurrentUser>('/api/auth/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
  });
}

export async function loginWithPasskey(): Promise<CurrentUser> {
  const opts = await jsonFetch<unknown>('/api/auth/login/begin', {
    method: 'POST',
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const credential = await startAuthentication({ optionsJSON: unwrapPublicKey(opts) as any });
  return jsonFetch<CurrentUser>('/api/auth/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
  });
}
