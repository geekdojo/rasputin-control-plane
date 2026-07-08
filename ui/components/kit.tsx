'use client';

// Shared building blocks for the ported "Cluster Node Management" design.
// Mission-control aesthetic: navy panels, JetBrains Mono, uppercase tracked
// labels, hairline borders, Pantone 172 C accent. Screens stay inline-styled;
// these keep the common pieces consistent across pages.

import { Check, ChevronDown, Copy, ExternalLink, X } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { CSSProperties, ElementType, ReactNode } from 'react';
import { useState } from 'react';
import { ACCENT, accentA, MONO } from './ui-theme';

export const PANEL = 'var(--rasp-panel)';
export const HAIR = 'rgba(var(--rasp-fg-rgb),0.18)';
export const HAIR_SOFT = 'rgba(var(--rasp-fg-rgb),0.1)';
export const FG = 'var(--rasp-fg)';
export const DIM = 'var(--rasp-dim)';

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

// Horizontal tab strip for sub-routed domain navigation (firewall, mesh, etc.).
// Renders below PageHeader; each tab is a real Next.js route so the URL stays
// the source of truth (bookmarkable, browser-back works, deep-linkable).
//
// Active-state detection picks the LONGEST href that matches the current
// pathname — so when the overview is at `/firewall` and a sibling at
// `/firewall/port-forwards`, only the more-specific one lights up.
export type PageTab = { label: string; href: string; external?: boolean };

export function PageTabs({ tabs }: { tabs: PageTab[] }) {
  const pathname = usePathname() ?? '';
  const activeHref = longestMatch(pathname, tabs);
  return (
    <div
      style={{
        display: 'flex',
        gap: 0,
        padding: '0 20px',
        borderBottom: `1px solid ${HAIR}`,
        flexShrink: 0,
      }}
    >
      {tabs.map((t) => (
        <Tab key={t.href} tab={t} active={t.href === activeHref} />
      ))}
    </div>
  );
}

function Tab({ tab, active }: { tab: PageTab; active: boolean }) {
  const [hover, setHover] = useState(false);
  const color = active ? ACCENT : tab.external ? DIM : '#a4b3cc';
  const base: CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '10px 14px',
    color,
    fontSize: 10,
    fontFamily: MONO,
    letterSpacing: '0.1em',
    background: hover && !active ? 'rgba(var(--rasp-fg-rgb),0.06)' : active ? accentA(0.06) : 'transparent',
    borderBottom: active ? `2px solid ${ACCENT}` : '2px solid transparent',
    textDecoration: 'none',
    cursor: 'pointer',
    transition: 'background 0.15s, color 0.15s',
  };
  if (tab.external) {
    return (
      <a
        href={tab.href}
        target="_blank"
        rel="noopener noreferrer"
        style={base}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
      >
        {tab.label}
        <ExternalLink size={10} />
      </a>
    );
  }
  return (
    <Link
      href={tab.href}
      style={base}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      {tab.label}
    </Link>
  );
}

function longestMatch(pathname: string, tabs: PageTab[]): string | null {
  let best: { href: string; len: number } | null = null;
  for (const t of tabs) {
    if (t.external) continue;
    const matches = pathname === t.href || pathname.startsWith(t.href + '/');
    if (matches && (!best || t.href.length > best.len)) {
      best = { href: t.href, len: t.href.length };
    }
  }
  return best?.href ?? null;
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
  default: { border: 'rgba(var(--rasp-fg-rgb),0.22)', bg: 'rgba(var(--rasp-fg-rgb),0.04)', hover: 'rgba(var(--rasp-fg-rgb),0.1)', text: FG },
  danger: { border: 'rgba(248,113,113,0.45)', bg: 'rgba(248,113,113,0.07)', hover: 'rgba(248,113,113,0.15)', text: '#f87171' },
  ghost: { border: 'transparent', bg: 'transparent', hover: 'rgba(var(--rasp-fg-rgb),0.06)', text: DIM },
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

// Legacy clipboard fallback for NON-secure contexts. navigator.clipboard is
// only exposed over HTTPS or localhost, so on the pre-CA-install /trust page
// (served over plain http://rasputin.local) it's undefined and the async API
// throws. The hidden-textarea + execCommand('copy') path still works over
// plain HTTP — deprecated but universally supported, and this is exactly the
// one surface we're guaranteed to be non-secure on.
function legacyCopy(text: string): boolean {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-9999px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

// Copy-to-clipboard button. Drop this next to ANY value the user is meant
// to copy (auth keys, install commands, sample JSON, IDs). Shows a transient
// "COPIED" state with a check icon. Uses the modern Clipboard API when it's
// available and falls back to execCommand when it isn't (non-secure context —
// the /trust page) or when it rejects; only surfaces "FAILED" if BOTH fail.
export function CopyButton({
  value,
  label = 'COPY',
  title,
  small = true,
}: {
  value: string;
  label?: string;
  title?: string;
  small?: boolean;
}) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  async function handle() {
    let ok = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        ok = true;
      }
    } catch {
      ok = false; // secure API present but rejected — try the legacy path
    }
    if (!ok) ok = legacyCopy(value);
    if (ok) {
      setState('copied');
      setTimeout(() => setState('idle'), 1500);
    } else {
      setState('failed');
      setTimeout(() => setState('idle'), 2500);
    }
  }

  const Icon = state === 'copied' ? Check : Copy;
  const text = state === 'copied' ? 'COPIED' : state === 'failed' ? 'FAILED' : label;
  const variant: BtnVariant = state === 'failed' ? 'danger' : state === 'copied' ? 'primary' : 'default';
  return (
    <Btn variant={variant} small={small} onClick={handle} title={title ?? 'Copy to clipboard'}>
      <Icon size={small ? 10 : 12} /> {text}
    </Btn>
  );
}

// Click-to-flip ON/OFF pill — used for the per-row enable/disable toggle on
// intent tables (firewall rules, port forwards, mesh keys, etc.). Renders as
// a button so it announces as actionable to AT.
export function EnabledToggle({
  enabled,
  onToggle,
  title,
}: {
  enabled: boolean;
  onToggle: () => void;
  title?: string;
}) {
  const [hover, setHover] = useState(false);
  const color = enabled ? '#4ade80' : DIM;
  return (
    <button
      type="button"
      onClick={onToggle}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title={title ?? (enabled ? 'Click to disable' : 'Click to enable')}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        padding: '3px 7px',
        border: `1px solid ${color}`,
        background: hover ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.03)',
        color,
        fontSize: 9,
        fontFamily: MONO,
        letterSpacing: '0.08em',
        cursor: 'pointer',
        transition: 'background 0.15s',
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: color,
          display: 'inline-block',
        }}
      />
      {enabled ? 'ON' : 'OFF'}
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
  background: 'var(--rasp-field-bg)',
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

// appearance:none suppresses the OS-native select chrome (which ignores the
// theme); the chevron is drawn by us so it follows --rasp-dim. paddingRight
// stays after the caller's style spread so custom padding can't crowd it.
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  const { style, className, children, ...rest } = props;
  return (
    <span style={{ position: 'relative', display: 'inline-flex' }}>
      <select
        className={`rasp-field ${className ?? ''}`}
        style={{
          ...fieldStyle,
          appearance: 'none',
          WebkitAppearance: 'none',
          MozAppearance: 'none',
          cursor: 'pointer',
          width: '100%',
          ...style,
          paddingRight: 24,
        }}
        {...rest}
      >
        {children}
      </select>
      <ChevronDown
        size={11}
        style={{ position: 'absolute', right: 7, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none', color: DIM }}
      />
    </span>
  );
}

// Drawer — a right-side slide-over panel with a header (icon + title + close)
// and a scrollable body. Used for catalog install and app detail. The caller
// supplies the body (usually a scroll region + a pinned footer).
export function Drawer({
  title,
  icon,
  onClose,
  children,
}: {
  title: string;
  icon?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div
      onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', justifyContent: 'flex-end', zIndex: 50 }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(560px, 92vw)',
          height: '100%',
          background: 'var(--rasp-bg)',
          borderLeft: `1px solid ${HAIR}`,
          display: 'flex',
          flexDirection: 'column',
          fontFamily: MONO,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 20px', borderBottom: `1px solid ${HAIR}` }}>
          {icon && <span style={{ fontSize: 18 }}>{icon}</span>}
          <span style={{ color: FG, fontSize: 12, letterSpacing: '0.06em' }}>{title}</span>
          <button
            onClick={onClose}
            title="Close"
            style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: DIM, display: 'flex' }}
          >
            <X size={16} />
          </button>
        </div>
        {children}
      </div>
    </div>
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
