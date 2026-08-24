'use client';

// Shared modal chrome for the Drawer / ConfirmModal family.
//
// Every one of these paints a full-viewport scrim (position:fixed; inset:0)
// over the page, but nothing used to tell the browser that the page underneath
// was unavailable. The 18-app bench run (2026-08) showed what that costs: the
// browser agents driving the catalog and the apps table reported that clicking
// a control by its accessibility-tree reference did nothing, over and over,
// and every one of them fell back to pixel coordinates. With a drawer open,
// the card buttons behind it were still in the a11y tree and still in the tab
// order, so a ref-click landed on a covered node or was swallowed by the
// scrim's onClose. A control a synthetic click can't reach is one a screen
// reader or keyboard user can't reach either.
//
// Two things are needed and neither implies the other:
//   - aria-modal="true" on the dialog is what makes Chrome drop everything
//     outside it from the AX tree, so find-by-ref stops matching background
//     controls;
//   - `inert` on the background is what takes those nodes out of the tab
//     order — aria-modal alone leaves Tab walking behind the scrim.
//
// `inert` is inherited by the whole subtree, so the dialog cannot live inside
// the element being inerted. Hence ModalPortal: it hoists the modal into its
// own <body> child, and inerts every sibling of that child.

import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

// ModalPortal renders its children into a host div of its own at the end of
// <body>, and — while `active` — marks every other body child inert. Also puts
// the fixed-position scrim outside any stacking context the page has created.
//
// Nesting works out: a confirm opened over a drawer inerts the drawer's host
// too, and un-inerts it on close.
export function ModalPortal({ active = true, children }: { active?: boolean; children: React.ReactNode }) {
  // The host is built detached during the first client render and attached in
  // the effect below. Null on the server so the static export's prerender pass
  // (which has no document, and no DOM for a portal to aim at) renders nothing.
  //
  // Detached-but-existing matters: it means the children mount in the same
  // commit as this component, so their refs are set before the owning modal's
  // own effect runs and can focus one of them.
  const [host] = useState<HTMLElement | null>(() =>
    typeof document === 'undefined' ? null : document.createElement('div'),
  );

  useEffect(() => {
    if (!host) return;
    host.setAttribute('data-modal-host', '');
    document.body.appendChild(host);
    return () => host.remove();
  }, [host]);

  useEffect(() => {
    if (!host || !active) return;
    // Elements already inert are left alone, so unwinding a nested modal
    // doesn't hand focus back to a layer that is still covered.
    const inerted: HTMLElement[] = [];
    for (const el of Array.from(document.body.children)) {
      if (!(el instanceof HTMLElement) || el === host || el.hasAttribute('inert')) continue;
      el.setAttribute('inert', '');
      inerted.push(el);
    }
    return () => {
      for (const el of inerted) el.removeAttribute('inert');
    };
  }, [host, active]);

  if (!host) return null;
  return createPortal(children, host);
}

export interface ModalChrome {
  /** Attach to whatever should hold focus on open — the close button, or Cancel on a destructive confirm. */
  initialFocusRef: React.RefObject<HTMLElement | null>;
}

// useModalChrome wires what a modal owes the page behind it that ModalPortal
// doesn't: Escape closes, body scroll is locked, focus moves in on open and
// back to the opener on close.
export function useModalChrome({ open, onClose }: { open: boolean; onClose: () => void }): ModalChrome {
  const initialFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    // Whatever had focus when the modal opened is where focus goes back on
    // close. Without this it falls back to <body> and a keyboard operator
    // loses their place in the table they opened the drawer from.
    const opener = document.activeElement as HTMLElement | null;

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);

    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    initialFocusRef.current?.focus();

    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
      // Deferred, and this is load-bearing: ModalPortal's cleanup un-inerts
      // the page AFTER this one runs, and focus() on a node still inside an
      // inert subtree is refused outright — focus stayed on <body> until this
      // was moved off the synchronous commit. The guard keeps it from
      // yanking focus back if something else has already claimed it.
      queueMicrotask(() => {
        if (document.activeElement && document.activeElement !== document.body) return;
        opener?.focus?.();
      });
    };
  }, [open, onClose]);

  return { initialFocusRef };
}
