// The browser boundaries the bridge's DOM tests stub
// (geekdojo/geekdojo-brain#1005): the WebAuthn credential API that
// @simplewebauthn/browser calls, and the page navigation.

const enc = (s: string) => new TextEncoder().encode(s).buffer;

/** Stubs PublicKeyCredential and navigator.credentials.get with one assertion. */
export function stubPasskey(): { calls: () => number; fail: () => void; restore: () => void } {
  const g = globalThis as unknown as Record<string, unknown>;
  const nav = globalThis.navigator as unknown as Record<string, unknown>;
  const hadPKC = g.PublicKeyCredential;
  const hadCreds = Object.getOwnPropertyDescriptor(nav, 'credentials');
  let n = 0;
  let failing = false;
  g.PublicKeyCredential = function PublicKeyCredential() {};
  Object.defineProperty(nav, 'credentials', {
    configurable: true,
    value: {
      get: async () => {
        n++;
        if (failing) throw new Error('NotAllowedError');
        return {
          id: 'Y3JlZA',
          rawId: enc('cred'),
          type: 'public-key',
          authenticatorAttachment: 'platform',
          response: { authenticatorData: enc('auth'), clientDataJSON: enc('{}'), signature: enc('sig'), userHandle: enc('handle') },
          getClientExtensionResults: () => ({}),
        };
      },
    },
  });
  return {
    calls: () => n,
    fail: () => {
      failing = true;
    },
    restore: () => {
      g.PublicKeyCredential = hadPKC;
      if (hadCreds) Object.defineProperty(nav, 'credentials', hadCreds);
      else delete nav.credentials;
    },
  };
}

/** Records window.location.assign instead of navigating. */
export function spyNavigation(): { calls: string[]; restore: () => void } {
  const loc = window.location as unknown as Record<string, unknown>;
  const calls: string[] = [];
  Object.defineProperty(loc, 'assign', { configurable: true, writable: true, value: (u: string) => calls.push(String(u)) });
  return {
    calls,
    restore: () => {
      delete loc.assign;
    },
  };
}
