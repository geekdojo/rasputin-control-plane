'use client';

import { AlertTriangle, X } from 'lucide-react';
import { ModalPortal, useModalChrome } from './modal';
import { MONO } from './ui-theme';

interface ConfirmModalProps {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmModal({
  title,
  message,
  confirmLabel,
  danger = false,
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  // Mounted only while asking, so `open` is constant true. Modal semantics
  // (Escape, inert background, scroll lock, focus in and back) come from
  // useModalChrome — see components/modal.tsx.
  const { initialFocusRef } = useModalChrome({ open: true, onClose: onCancel });
  return (
    <ModalPortal>
      {/* aria-hidden: the scrim is a click target, not content. */}
      <div
        onClick={onCancel}
        aria-hidden
        style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.6)',
          zIndex: 1000,
        }}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        style={{
          position: 'fixed',
          inset: 0,
          margin: 'auto',
          height: 'fit-content',
          zIndex: 1001,
          background: 'var(--rasp-panel)',
          border: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
          padding: '24px',
          width: 340,
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={14} color={danger ? '#f87171' : '#facc15'} />
            <span
              style={{
                color: 'var(--rasp-fg)',
                fontSize: 11,
                fontFamily: MONO,
                letterSpacing: '0.1em',
              }}
            >
              {title}
            </span>
          </div>
          <button
            type="button"
            onClick={onCancel}
            aria-label="Close"
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            <X size={14} color="var(--rasp-dim)" />
          </button>
        </div>

        <div style={{ height: 1, background: 'rgba(var(--rasp-fg-rgb),0.1)' }} />

        <p
          style={{
            color: 'var(--rasp-dim)',
            fontSize: 11,
            fontFamily: MONO,
            lineHeight: 1.6,
            margin: 0,
          }}
        >
          {message}
        </p>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button
            ref={initialFocusRef as React.RefObject<HTMLButtonElement | null>}
            type="button"
            onClick={onCancel}
            style={{
              padding: '7px 16px',
              background: 'transparent',
              border: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
              color: 'var(--rasp-dim)',
              fontSize: 10,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: 'pointer',
            }}
          >
            CANCEL
          </button>
          <button
            type="button"
            onClick={() => {
              onConfirm();
              onCancel();
            }}
            style={{
              padding: '7px 16px',
              background: danger ? 'rgba(248,113,113,0.12)' : 'rgba(250,204,21,0.1)',
              border: `1px solid ${danger ? 'rgba(248,113,113,0.5)' : 'rgba(250,204,21,0.4)'}`,
              color: danger ? '#f87171' : '#facc15',
              fontSize: 10,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: 'pointer',
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </ModalPortal>
  );
}
