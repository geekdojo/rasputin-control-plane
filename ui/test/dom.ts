// A browser document for the component tests, and the few helpers they share.
//
// Import this FIRST in a component test: react-dom decides at load time
// whether it has a DOM, so the globals (dom-globals.ts) must exist before
// anything requires it.
//
// happy-dom is the only package this adds (geekdojo/geekdojo-brain#781,
// Bryce 2026-10-30 "Add component tests"). The tests drive React directly
// through react-dom/client and act(), so no testing-library is needed.
import { win } from './dom-globals';
import { act, type ReactElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';

export interface Rendered {
  container: HTMLElement;
  unmount: () => Promise<void>;
}

/** Renders `ui` into a fresh container and lets its mount effects settle. */
export async function render(ui: ReactElement): Promise<Rendered> {
  const container = document.createElement('div');
  document.body.appendChild(container);
  let root: Root | undefined;
  await act(async () => {
    root = createRoot(container);
    root.render(ui);
  });
  await settle();
  return {
    container,
    unmount: async () => {
      await act(async () => root?.unmount());
      container.remove();
    },
  };
}

/** Lets pending promises (stubbed fetches) resolve and React commit. */
export async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
  }
}

/** Types into an input the way a user does, so React's onChange fires. */
export async function type(input: HTMLInputElement, value: string): Promise<void> {
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new win.Event('input', { bubbles: true }) as unknown as Event);
  });
}

/** Clicks an element and lets what it starts settle. */
export async function click(el: Element): Promise<void> {
  await act(async () => {
    (el as HTMLElement).click();
  });
  await settle();
}

/** The button whose visible text or aria-label is exactly `name`. */
export function button(root: ParentNode, name: string): HTMLButtonElement {
  const found = Array.from(root.querySelectorAll('button')).find(
    (b) => b.getAttribute('aria-label') === name || (b.textContent ?? '').trim() === name,
  );
  if (!found) throw new Error(`no button named ${name}`);
  return found as HTMLButtonElement;
}

export interface Call {
  method: string;
  url: string;
  body?: string;
}

export type Route = (call: Call) => Response | undefined;

export function json(status: number, body?: unknown): Response {
  return new Response(status === 204 || body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Stubs fetch with `route`, recording every call. A request no route answers
 * gets 404, so a page's unrelated reads fail quietly the way they would
 * against an api that has nothing for them. Returns the call log and a restore.
 */
export function stubFetch(route: Route): { calls: Call[]; restore: () => void } {
  const real = globalThis.fetch;
  const calls: Call[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const call: Call = {
      method: (init?.method ?? 'GET').toUpperCase(),
      url: String(input),
      body: typeof init?.body === 'string' ? init.body : undefined,
    };
    calls.push(call);
    return route(call) ?? json(404, { error: 'not found' });
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = real) };
}
