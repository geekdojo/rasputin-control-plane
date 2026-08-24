'use client';

// Drawer — slide-over panel anchored to the right edge. Used by the
// NodeDetailDrawer on /metrics. Vanilla impl rather than reaching for
// Radix or Vaul (no deps for a dialog we use in one place):
//   - ESC closes
//   - click on the dimmed backdrop closes
//   - body scroll-locks while open
//   - background goes inert + out of the AX tree while open
//   - 200ms slide-in via CSS transform
//   - focus trap is best-effort (we focus the close button on open)
//
// The behaviour itself is shared with kit.tsx's Drawer and ConfirmModal via
// useModalChrome — this file keeps only its own layout and the slide.
//
// Width adapts: 560px on desktop, full-width on narrow viewports. The
// drawer page handles its own internal scroll.

import { X } from 'lucide-react';
import { DIM, FG, HAIR, PANEL } from '../kit';
import { ModalPortal, useModalChrome } from '../modal';
import { MONO } from '../ui-theme';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  headerExtras?: React.ReactNode;
  children: React.ReactNode;
}

export function Drawer({ open, onClose, title, subtitle, headerExtras, children }: DrawerProps) {
  const { initialFocusRef } = useModalChrome({ open, onClose });

  return (
    <ModalPortal active={open}>
      {/* Backdrop — separate from the panel so the slide animation
          doesn't drag the backdrop along. pointer-events toggle so the
          drawer's children don't intercept clicks when it's closed. */}
      <div
        onClick={onClose}
        aria-hidden
        style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(2,8,17,0.55)',
          opacity: open ? 1 : 0,
          pointerEvents: open ? 'auto' : 'none',
          transition: 'opacity 0.2s ease-out',
          zIndex: 50,
        }}
      />
      {/* This panel stays mounted when closed (that is what the slide
          animates from), so it also has to be taken out of the tree when
          closed — otherwise its controls stay tabbable behind the page. */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={title}
        aria-hidden={!open}
        inert={!open}
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 'min(640px, 100vw)',
          background: PANEL,
          borderLeft: `1px solid ${HAIR}`,
          color: FG,
          fontFamily: MONO,
          transform: open ? 'translateX(0)' : 'translateX(100%)',
          transition: 'transform 0.22s ease-out',
          zIndex: 51,
          display: 'flex',
          flexDirection: 'column',
          boxShadow: open ? '-12px 0 32px rgba(0,0,0,0.4)' : 'none',
        }}
      >
        <header
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '14px 18px',
            borderBottom: `1px solid ${HAIR}`,
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <span style={{ fontSize: 12, letterSpacing: '0.08em', color: FG }}>{title}</span>
            {subtitle && (
              <span style={{ fontSize: 9, letterSpacing: '0.1em', color: DIM }}>{subtitle}</span>
            )}
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
            {headerExtras}
            <button
              ref={initialFocusRef as React.RefObject<HTMLButtonElement | null>}
              type="button"
              onClick={onClose}
              aria-label="Close drawer"
              style={{
                background: 'transparent',
                border: 'none',
                color: DIM,
                cursor: 'pointer',
                padding: 4,
                display: 'flex',
              }}
            >
              <X size={16} />
            </button>
          </div>
        </header>
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
          {children}
        </div>
      </aside>
    </ModalPortal>
  );
}
