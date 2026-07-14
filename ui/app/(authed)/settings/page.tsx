'use client';

// /settings — operator preferences for this control plane. Sections:
//   • Appearance (theme picker)
//   • Deployment mode (post-setup change of setup.mode — the only surface for
//     this once the first-run wizard has completed; the wizard redirects away
//     when setup is done, so without this an operator who picked the wrong mode
//     was stuck. Backend: POST /api/setup/mode, same endpoint the wizard uses.)
//   • Operator SSH key(s) — the cluster-remembered key(s) the Add-node wizard
//     prefills from. Rotation here is forward-only (future seeds only); it
//     never re-keys already-enrolled nodes.
// The Settings icon in the sidebar routes here.

import { Check, Settings as SettingsIcon, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Btn, PageShell, PageHeader, PageBody, SectionLabel, Hint, Input, Tok, DIM, FG, HAIR } from '../../../components/kit';
import { accentA, ACCENT, MONO } from '../../../components/ui-theme';
import { THEMES, useTheme, type ThemeMeta } from '../../../lib/theme';
import { DeploymentModePicker, MODES } from '../../../components/DeploymentModePicker';
import { ConfirmModal } from '../../../components/ConfirmModal';
import { getOperatorKeys, getSetupState, setDeploymentMode, setOperatorKeys } from '../../../lib/api';
import { validateSSHKey } from '../../../lib/enroll';
import type { DeploymentMode, SetupState } from '../../../lib/types';

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();

  return (
    <PageShell>
      <PageHeader icon={SettingsIcon} title="SETTINGS" />
      <PageBody>
        <SectionLabel>APPEARANCE / THEME</SectionLabel>
        <Hint style={{ marginBottom: 16 }}>
          Choose how the control plane looks. Applies instantly and is remembered on this device.
        </Hint>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: 12,
            maxWidth: 880,
          }}
        >
          {THEMES.map((t) => (
            <ThemeCard key={t.id} meta={t} selected={theme === t.id} onSelect={() => setTheme(t.id)} />
          ))}
        </div>

        <div style={{ height: 32 }} />
        <DeploymentModeSection />

        <div style={{ height: 32 }} />
        <OperatorSSHKeySection />
      </PageBody>
    </PageShell>
  );
}

// --- Operator SSH key -------------------------------------------------------

function OperatorSSHKeySection() {
  const [keys, setKeys] = useState<string[] | null>(null);
  const [captured, setCaptured] = useState(false);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getOperatorKeys()
      .then((ok) => {
        setKeys(ok.keys);
        setCaptured(ok.captured);
      })
      .catch((e) => setErr(String(e)));
  }, []);

  async function save(next: string[]) {
    setBusy(true);
    setErr(null);
    try {
      const ok = await setOperatorKeys(next);
      setKeys(ok.keys);
      setCaptured(ok.captured);
      setDraft('');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const draftCheck = validateSSHKey(draft);
  const canAdd = draft.trim() !== '' && !draftCheck.error && !(keys ?? []).includes(draftCheck.key);

  return (
    <>
      <SectionLabel>OPERATOR SSH KEY</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        The SSH <em>public</em> key(s) this cluster remembers for you — the Add-node wizard prefills
        from the first one so you aren&apos;t re-asked on every enrollment. Changes apply to{' '}
        <em>future</em> enrollments only; nodes already running keep the key they were seeded with.
      </Hint>

      {keys === null && !err && <Hint>Loading…</Hint>}
      {err && <Hint warn style={{ marginBottom: 12 }}>{err}</Hint>}

      {keys !== null && (
        <div style={{ maxWidth: 720 }}>
          {keys.length === 0 && (
            <Hint style={{ marginBottom: 12 }}>
              {captured
                ? 'No key stored. The wizard won’t prefill until one is added here or used in an enrollment.'
                : 'No key captured yet — the first Add-node enrollment that uses a key stores it here automatically.'}
            </Hint>
          )}
          {keys.map((k) => (
            <div
              key={k}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 10px',
                border: `1px solid ${HAIR}`,
                marginBottom: 8,
              }}
            >
              <span
                style={{
                  flex: 1,
                  color: FG,
                  fontSize: 10,
                  fontFamily: MONO,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                title={k}
              >
                {k}
              </span>
              <button
                onClick={() => save(keys.filter((x) => x !== k))}
                disabled={busy}
                title="Remove this key (future enrollments only)"
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, flexShrink: 0 }}
              >
                <X size={12} color={DIM} />
              </button>
            </div>
          ))}

          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <Input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="ssh-ed25519 AAAA… you@laptop"
              spellCheck={false}
              style={{ flex: 1 }}
            />
            <Btn variant="primary" small onClick={() => save([...(keys ?? []), draftCheck.key])} disabled={busy || !canAdd}>
              {busy ? 'SAVING…' : 'ADD KEY'}
            </Btn>
          </div>
          {draft.trim() !== '' && draftCheck.error ? (
            <Hint warn style={{ marginTop: 6 }}>{draftCheck.error}</Hint>
          ) : (
            <Hint style={{ marginTop: 6 }}>
              Paste a public key line, e.g. from <Tok>~/.ssh/id_ed25519.pub</Tok>.
            </Hint>
          )}
        </div>
      )}
    </>
  );
}

// --- Deployment mode ------------------------------------------------------

// consequenceOf returns the confirm-dialog copy for switching TO `target`.
// The sharp edge is LAN-peer: it idles a live firewall (DHCP + threat detection
// off), which can drop devices offline if Rasputin is the one running the
// network. Copy stays plain-language / vendor-neutral (no "DHCP"/OpenWrt).
function consequenceOf(target: Exclude<DeploymentMode, ''>, firewallCapable: boolean): {
  message: string;
  danger: boolean;
} {
  if (target === 'lan_peer') {
    if (firewallCapable) {
      return {
        danger: true,
        message:
          'Switching to “Join my existing network” turns your firewall node off — it stops handing out addresses and stops watching for threats. If Rasputin is currently running your network, connected devices — including the one you’re using right now — may drop offline when their address lease renews. Only switch if another router on the network hands out addresses.',
      };
    }
    return {
      danger: false,
      message:
        'Rasputin will run as a device on your existing network. Your current router keeps doing the firewalling — nothing else changes.',
    };
  }
  if (target === 'router') {
    return {
      danger: false,
      message:
        'Rasputin becomes your router — it starts handing out addresses, running the firewall, and watching for threats on its network port.',
    };
  }
  return {
    danger: false,
    message:
      'Rasputin runs its own protected network — it starts handing out addresses, running the firewall, and watching for threats on that network.',
  };
}

function DeploymentModeSection() {
  const [state, setState] = useState<SetupState | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<Exclude<DeploymentMode, ''> | null>(null);

  useEffect(() => {
    getSetupState()
      .then(setState)
      .catch((e) => setErr(String(e)));
  }, []);

  async function apply(mode: Exclude<DeploymentMode, ''>) {
    setBusy(true);
    setErr(null);
    try {
      setState(await setDeploymentMode(mode));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
      setPending(null);
    }
  }

  const currentLabel = state ? MODES.find((m) => m.id === state.mode)?.label : null;
  const consequence = pending ? consequenceOf(pending, state?.firewallCapable ?? false) : null;

  return (
    <>
      <SectionLabel>DEPLOYMENT MODE</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        How Rasputin sits on your network. Changing this reconfigures the firewall node — it takes
        effect within a minute or two.{' '}
        {currentLabel && (
          <>
            Currently: <span style={{ color: FG }}>{currentLabel}</span>.
          </>
        )}
      </Hint>

      {state === null && !err && <Hint>Loading…</Hint>}
      {err && <Hint warn>{err}</Hint>}

      {state && (
        <div style={{ maxWidth: 560 }}>
          <DeploymentModePicker
            mode={state.mode}
            firewallCapable={state.firewallCapable}
            busy={busy}
            onSelect={(m) => setPending(m)}
          />
        </div>
      )}

      {pending && consequence && (
        <ConfirmModal
          title="Change deployment mode?"
          message={consequence.message}
          confirmLabel={busy ? 'SWITCHING…' : 'SWITCH MODE'}
          danger={consequence.danger}
          onConfirm={() => apply(pending)}
          onCancel={() => setPending(null)}
        />
      )}
    </>
  );
}

function ThemeCard({
  meta,
  selected,
  onSelect,
}: {
  meta: ThemeMeta;
  selected: boolean;
  onSelect: () => void;
}) {
  const [hover, setHover] = useState(false);
  const { bg, panel, fg, accent } = meta.swatch;

  return (
    <button
      type="button"
      onClick={onSelect}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      aria-pressed={selected}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        padding: 12,
        textAlign: 'left',
        cursor: 'pointer',
        fontFamily: MONO,
        background: selected ? accentA(0.08) : hover ? 'rgba(var(--rasp-fg-rgb),0.04)' : 'transparent',
        border: `1px solid ${selected ? ACCENT : HAIR}`,
        transition: 'background 0.15s, border-color 0.15s',
      }}
    >
      {/* Live mini-preview rendered from the theme's own swatch colors so it
          reads correctly regardless of which theme is currently active. */}
      <div
        style={{
          position: 'relative',
          height: 92,
          background: bg,
          border: `1px solid ${HAIR}`,
          overflow: 'hidden',
          padding: 10,
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: accent, flexShrink: 0 }} />
          <span style={{ width: 54, height: 6, background: fg, opacity: 0.85 }} />
          <span style={{ marginLeft: 'auto', width: 26, height: 6, background: accent }} />
        </div>
        <div style={{ flex: 1, background: panel, border: `1px solid ${accent}`, padding: 6 }}>
          <span style={{ display: 'block', width: '40%', height: 5, background: accent, marginBottom: 5 }} />
          <span style={{ display: 'block', width: '70%', height: 4, background: fg, opacity: 0.4 }} />
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: selected ? ACCENT : FG, fontSize: 12, letterSpacing: '0.08em' }}>
          {meta.label.toUpperCase()}
        </span>
        {selected && (
          <span
            style={{
              marginLeft: 'auto',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              color: ACCENT,
              fontSize: 9,
              letterSpacing: '0.1em',
            }}
          >
            <Check size={11} /> ACTIVE
          </span>
        )}
      </div>
      <span style={{ color: DIM, fontSize: 10, lineHeight: 1.55 }}>{meta.description}</span>
    </button>
  );
}
