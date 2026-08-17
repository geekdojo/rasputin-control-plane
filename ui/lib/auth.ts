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
    credentials: 'include',
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
    credentials: 'include',
  });
}

// The option shapes SimpleWebAuthn accepts, derived from the functions
// themselves rather than imported.
//
// PublicKeyCredentialCreationOptionsJSON lives in @simplewebauthn/types, which
// @simplewebauthn/browser does NOT re-export — importing it would mean naming a
// transitive dependency, and a version skew between the two would then be ours
// to notice. Reading the types off the functions costs no dependency and tracks
// the library automatically: if an upgrade reshapes the options, these reshape
// with it and any mismatch below becomes a compile error rather than a failure
// at the authenticator prompt.
type RegistrationOptions = Parameters<typeof startRegistration>[0]['optionsJSON'];
type AuthenticationOptions = Parameters<typeof startAuthentication>[0]['optionsJSON'];

// go-webauthn returns { publicKey: { ... } }; SimpleWebAuthn wants the inner
// publicKey object as optionsJSON.
//
// The cast at each call site is unavoidable — this data arrives off the network
// as `unknown` and nothing here validates its shape. What the cast should NOT
// be is `any`, which switches off checking for everything downstream of it.
// Casting to the specific option type keeps the rest of the call checked.
// Runtime validation of the server's response would be a genuine improvement
// and is deliberately not attempted here.
function unwrapPublicKey(opts: unknown): unknown {
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
  const credential = await startRegistration({ optionsJSON: unwrapPublicKey(opts) as RegistrationOptions });
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
  const credential = await startAuthentication({ optionsJSON: unwrapPublicKey(opts) as AuthenticationOptions });
  return jsonFetch<CurrentUser>('/api/auth/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
  });
}
