// The browser globals for the component tests, from happy-dom.
//
// This is its own module because every import runs before the body of the
// module that imports it. Registering the globals in dom.ts's body would run
// after react-dom had loaded, and react-dom decides once, at load, whether it
// has a DOM: without one, typing into an input never fires onChange. dom.ts
// imports this module before react-dom. node --test runs each test file in
// its own process, so these globals never reach the lib tests.
import { Window } from 'happy-dom';

export const win = new Window({ url: 'http://localhost/' });
const g = globalThis as unknown as Record<string, unknown>;
// Node 22 has its own fetch, WebSocket, Event and navigator. fetch is stubbed
// per test and WebSocket below; the DOM names come from happy-dom so React
// and the elements agree on one implementation.
for (const key of Object.getOwnPropertyNames(win)) {
  if (key in g && !['navigator', 'Event', 'EventTarget', 'CustomEvent'].includes(key)) continue;
  const value = (win as unknown as Record<string, unknown>)[key];
  Object.defineProperty(g, key, { value, configurable: true, writable: true });
}
Object.defineProperty(g, 'window', { value: win, configurable: true, writable: true });
Object.defineProperty(g, 'document', { value: win.document, configurable: true, writable: true });
g.IS_REACT_ACT_ENVIRONMENT = true;

// The pages open live-update sockets on mount; a test has no api to talk to.
class InertWebSocket {
  onopen: (() => void) | null = null;
  onmessage: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  close(): void {}
}
g.WebSocket = InertWebSocket;
