import { AlertTriangle, X } from 'lucide-react';
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
  return (
    <div
      onClick={onCancel}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: '#0d1829',
          border: '1px solid rgba(228,230,234,0.18)',
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
                color: '#e4e6ea',
                fontSize: 11,
                fontFamily: MONO,
                letterSpacing: '0.1em',
              }}
            >
              {title}
            </span>
          </div>
          <button
            onClick={onCancel}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            <X size={14} color="#8a9bb5" />
          </button>
        </div>

        <div style={{ height: 1, background: 'rgba(228,230,234,0.1)' }} />

        <p
          style={{
            color: '#8a9bb5',
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
            onClick={onCancel}
            style={{
              padding: '7px 16px',
              background: 'transparent',
              border: '1px solid rgba(228,230,234,0.18)',
              color: '#8a9bb5',
              fontSize: 10,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: 'pointer',
            }}
          >
            CANCEL
          </button>
          <button
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
    </div>
  );
}
