const BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

/**
 * The signed-in person (GET /api/auth/me): their account's subject, sign-in
 * name and console roles. preUpdate is set only for a session from before
 * the sign-in update (geekdojo/geekdojo-brain#1005); needsPassword says its
 * account has not chosen its first password yet.
 */
export interface CurrentUser {
  sub: string;
  name: string;
  roles: string[];
  preUpdate?: { needsPassword: boolean };
}

/**
 * GET /api/auth/status: whether the cluster is at first run (no first
 * administrator claimed and no pre-update operator: firstRun, which offers
 * CREATE THE FIRST ACCOUNT and a restore), whether a sign-in can start now,
 * and the signed-in person when there is one. It never reports how many
 * accounts exist.
 */
export interface AuthStatus {
  firstRun: boolean;
  ready: boolean;
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
