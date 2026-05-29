'use client';

// Shared building blocks for the ported "Cluster Node Management" design.
// Mission-control aesthetic: navy panels, JetBrains Mono, uppercase tracked
// labels, hairline borders, Pantone 172 C accent. Screens stay inline-styled;
// these keep the common pieces consistent across pages.

import type { CSSProperties, ElementType, ReactNode } from 'react';
import { useState } from 'react';
import { ACCENT, accentA, MONO } from './ui-theme';

export const PANEL = '#0d1829';
export const HAIR = 'rgba(228,230,234,0.18)';
export const HAIR_SOFT = 'rgba(228,230,234,0.1)';
export const FG = '#e4e6ea';
export const DIM = '#8a9bb5';

export function PageShell({ children }: { children: ReactNode }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', fontFamily: MONO }}>
      {children}
    </div>
  );
}

export function PageHeader({
  icon: Icon,
  title,
  right,
}: {
  icon?: ElementType;
  title: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '14px 20px',
        borderBottom: `1px solid ${HAIR}`,
        flexShrink: 0,
      }}
    >
      {Icon && <Icon size={14} color={ACCENT} />}
      <span style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.1em' }}>{title}</span>
      {right && <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>{right}</div>}
    </div>
  );
}

export function PageBody({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', ...style }}>{children}</div>;
}

export function SectionLabel({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return (
    <div
      style={{
        color: DIM,
        fontSize: 9,
        fontFamily: MONO,
        letterSpacing: '0.12em',
        padding: '4px 0',
        borderBottom: `1px solid ${HAIR_SOFT}`,
        marginBottom: 10,
        ...style,
      }}
    >
      {children}
    </div>
  );
}

export function Hint({ children, warn = false, style }: { children: ReactNode; warn?: boolean; style?: CSSProperties }) {
  return (
    <p style={{ color: warn ? '#facc15' : DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0, ...style }}>
      {children}
    </p>
  );
}

// Inline code-ish token for embedding identifiers/paths in hint text.
export function Tok({ children }: { children: ReactNode }) {
  return <span style={{ color: FG }}>{children}</span>;
}

type BtnVariant = 'primary' | 'default' | 'danger' | 'ghost';

const BTN_COLORS: Record<BtnVariant, { border: string; bg: string; hover: string; text: string }> = {
  primary: { border: accentA(0.35), bg: accentA(0.08), hover: accentA(0.16), text: ACCENT },
  default: { border: 'rgba(228,230,234,0.22)', bg: 'rgba(228,230,234,0.04)', hover: 'rgba(228,230,234,0.1)', text: FG },
  danger: { border: 'rgba(248,113,113,0.45)', bg: 'rgba(248,113,113,0.07)', hover: 'rgba(248,113,113,0.15)', text: '#f87171' },
  ghost: { border: 'transparent', bg: 'transparent', hover: 'rgba(228,230,234,0.06)', text: DIM },
};

export function Btn({
  variant = 'default',
  small = false,
  disabled = false,
  type = 'button',
  title,
  onClick,
  children,
}: {
  variant?: BtnVariant;
  small?: boolean;
  disabled?: boolean;
  type?: 'button' | 'submit';
  title?: string;
  onClick?: () => void;
  children: ReactNode;
}) {
  const [hover, setHover] = useState(false);
  const c = BTN_COLORS[variant];
  return (
    <button
      type={type}
      disabled={disabled}
      title={title}
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: small ? '4px 8px' : '6px 12px',
        border: `1px solid ${c.border}`,
        background: !disabled && hover ? c.hover : c.bg,
        color: c.text,
        fontSize: small ? 9 : 10,
        fontFamily: MONO,
        letterSpacing: '0.08em',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.4 : 1,
        transition: 'background 0.15s',
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </button>
  );
}

// Status pill — colored text + border, neutral translucent fill (works for any color).
export function Badge({ color = DIM, children }: { color?: string; children: ReactNode }) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 7px',
        border: `1px solid ${color}`,
        color,
        background: 'rgba(255,255,255,0.03)',
        fontSize: 9,
        fontFamily: MONO,
        letterSpacing: '0.08em',
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </span>
  );
}

export const fieldStyle: CSSProperties = {
  background: '#111d30',
  border: `1px solid ${HAIR}`,
  color: FG,
  fontFamily: MONO,
  fontSize: 11,
  padding: '7px 9px',
};

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { style, className, ...rest } = props;
  return <input className={`rasp-field ${className ?? ''}`} style={{ ...fieldStyle, ...style }} {...rest} />;
}

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { style, className, ...rest } = props;
  return (
    <textarea
      className={`rasp-field ${className ?? ''}`}
      style={{ ...fieldStyle, resize: 'vertical', lineHeight: 1.5, ...style }}
      {...rest}
    />
  );
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  const { style, className, children, ...rest } = props;
  return (
    <select className={`rasp-field ${className ?? ''}`} style={{ ...fieldStyle, ...style }} {...rest}>
      {children}
    </select>
  );
}

// Table cell/header styles shared by the data tables.
export const thStyle: CSSProperties = {
  textAlign: 'left',
  padding: '0 16px 6px 0',
  color: DIM,
  fontSize: 9,
  fontFamily: MONO,
  letterSpacing: '0.1em',
  fontWeight: 500,
  borderBottom: `1px solid ${HAIR_SOFT}`,
};

export const tdStyle: CSSProperties = {
  padding: '7px 16px 7px 0',
  color: FG,
  fontSize: 10,
  fontFamily: MONO,
  verticalAlign: 'middle',
};
