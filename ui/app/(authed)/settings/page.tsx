'use client';

// /settings — operator preferences for this control plane. Sections:
//   • Appearance (theme picker)
//   • Deployment mode (post-setup change of setup.mode — the only surface for
//     this once the first-run wizard has completed; the wizard redirects away
//     when setup is done, so without this an operator who picked the wrong mode
//     was stuck. Backend: POST /api/setup/mode, same endpoint the wizard uses.)
//   • Metrics & logs — the on/off switch for observability. Same species of gap
//     as deployment mode: the stack shipped complete but could only be turned on
//     by restarting the api with an env var, which an appliance operator cannot
//     do. Backend: POST /api/obs/{enable,disable} (async — returns a job).
//   • Operator SSH key(s) — the cluster-remembered key(s) the Add-node wizard
//     prefills from. Rotation here is forward-only (future seeds only); it
//     never re-keys already-enrolled nodes.
// The Settings icon in the sidebar routes here.

import { Check, Settings as SettingsIcon, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Btn, PageShell, PageHeader, PageBody, SectionLabel, Hint, Input, Select, Tok, EnabledToggle, DIM, FG, HAIR } from '../../../components/kit';
import { accentA, ACCENT, MONO } from '../../../components/ui-theme';
import { THEMES, useTheme, type ThemeMeta } from '../../../lib/theme';
import { DeploymentModePicker, MODES } from '../../../components/DeploymentModePicker';
import { ConfirmModal } from '../../../components/ConfirmModal';
import {
  disableObs,
  enableObs,
  getBMCBackends,
  getBMCConfig,
  getJob,
  getObsStatus,
  getOperatorKeys,
  getSetupState,
  listNodes,
  setBMCConfig,
  setDeploymentMode,
  setOperatorKeys,
} from '../../../lib/api';
import { validateSSHKey } from '../../../lib/enroll';
import type { BMCBackendInfo, BMCConfigView, DeploymentMode, Node, ObsStatus, SetupState } from '../../../lib/types';

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
        <BMCSection />

        <div style={{ height: 32 }} />
        <ObservabilitySection />

        <div style={{ height: 32 }} />
        <OperatorSSHKeySection />
      </PageBody>
    </PageShell>
  );
}

// --- Metrics & logs ---------------------------------------------------------

// The canonical on/off surface for observability. Before this existed the only
// way to turn the stack on was to restart the api with RASPUTIN_OBS_ENABLED=1
// — impossible on an appliance (read-only rootfs, no shell, no SSH server),
// which meant a complete Tier 2 stack shipped unreachable. See wiki
// design/control-plane/observability-stack.md §3.8.
//
// Copy here is deliberately vendor-neutral per architecture.md's UI-strings
// rule: the operator turns on "metrics & logs", not VictoriaMetrics + Loki +
// Grafana. It's also NOT an upsell — observability is OSS we ship and the
// entitlements doc explicitly kills gating it, so the cost we state is disk
// and time, not money.
// BMC — settings-driven backend selection (wiki design/control-plane/
// bmc-settings.md §7). Hard on/off: the cluster has no BMC until an
// operator explicitly selects one here; the mock is an ordinary explicit
// selection for dev. The picker renders the api-served supported list.
function BMCSection() {
  const [backends, setBackends] = useState<BMCBackendInfo[]>([]);
  const [current, setCurrent] = useState<BMCConfigView | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [err, setErr] = useState<string | null>(null);

  // Form state (staged until APPLY).
  const [kind, setKind] = useState('');
  const [hostNode, setHostNode] = useState('');
  const [mockTargets, setMockTargets] = useState<Set<string>>(new Set());
  const [bsDev, setBsDev] = useState('');
  const [bsUnlock, setBsUnlock] = useState('');
  const [bsUnlockSet, setBsUnlockSet] = useState(false);
  const [bsMapJSON, setBsMapJSON] = useState('');

  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [jobNote, setJobNote] = useState<string | null>(null);

  const reload = () =>
    Promise.all([getBMCBackends(), getBMCConfig(), listNodes()])
      .then(([b, c, n]) => {
        setBackends(b);
        setCurrent(c);
        setNodes(n);
        seedForm(c);
        setErr(null);
      })
      .catch((e) => setErr(String(e)));

  function seedForm(c: BMCConfigView) {
    setKind(c.backend ?? '');
    setHostNode(c.hostNodeId ?? '');
    const cfg = (c.config ?? {}) as Record<string, unknown>;
    if (c.backend === 'mock' && Array.isArray(cfg.targets)) {
      setMockTargets(new Set(cfg.targets.filter((t): t is string => typeof t === 'string')));
    } else {
      setMockTargets(new Set());
    }
    if (c.backend === 'bitscope') {
      setBsDev(typeof cfg.dev === 'string' ? cfg.dev : '');
      setBsUnlockSet(cfg.unlockSet === true);
      setBsMapJSON(Array.isArray(cfg.targets) ? JSON.stringify(cfg.targets, null, 2) : '');
    } else {
      setBsDev('');
      setBsUnlockSet(false);
      setBsMapJSON('');
    }
    setBsUnlock('');
  }

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function buildConfig(): unknown {
    if (kind === 'mock') return { targets: [...mockTargets] };
    if (kind === 'bitscope') {
      let targets: unknown = [];
      try {
        targets = bsMapJSON.trim() ? JSON.parse(bsMapJSON) : [];
      } catch {
        throw new Error('address map is not valid JSON');
      }
      const cfg: Record<string, unknown> = { targets };
      if (bsDev.trim()) cfg.dev = bsDev.trim();
      if (bsUnlock) cfg.unlock = bsUnlock; // empty = keep stored (write-only)
      return cfg;
    }
    return undefined;
  }

  async function apply() {
    setBusy(true);
    setErr(null);
    setJobNote(null);
    try {
      const job = await setBMCConfig({
        kind: kind || 'none',
        hostNodeId: hostNode || undefined,
        config: kind ? buildConfig() : undefined,
      });
      // Poll the job briefly so the section shows the outcome (the push
      // is a single RPC — seconds, not minutes).
      let final = job;
      for (let i = 0; i < 20 && (final.status === 'queued' || final.status === 'running'); i++) {
        await new Promise((r) => setTimeout(r, 1000));
        final = await getJob(job.id);
      }
      if (final.status === 'succeeded') {
        setJobNote(kind ? 'Applied — BMC controls now follow the advertised targets.' : 'BMC is off.');
      } else {
        setErr(final.error || `configure job ${final.status}`);
      }
      await reload();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }

  const pinned = current?.pinnedNode;
  const activeLabel =
    current?.backend
      ? `${current.backend.toUpperCase()} via ${current.hostNodeId ?? '?'}`
      : 'OFF';

  return (
    <>
      <SectionLabel>BMC / POWER &amp; CONSOLE</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        Out-of-band power control and serial console for nodes reached by a BMC. Off until a
        backend is selected here — controls appear only for nodes the BMC host advertises.
        Currently: <Tok>{activeLabel}</Tok>
      </Hint>

      {pinned && (
        <Hint warn style={{ marginBottom: 12 }}>
          BMC is pinned by RASPUTIN_BMC_BACKEND on node {pinned} — remove the env var and restart
          that agent to manage it here.
        </Hint>
      )}

      {!pinned && current !== null && (
        <div style={{ maxWidth: 560, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <label style={{ color: DIM, fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em' }}>
            BACKEND
            <Select value={kind} onChange={(e) => setKind(e.target.value)} style={{ display: 'block', marginTop: 4, width: '100%' }}>
              <option value="">None (BMC off)</option>
              {backends.map((b) => (
                <option key={b.kind} value={b.kind} disabled={b.status !== 'available'}>
                  {b.label}
                  {b.status !== 'available' ? ' — coming later' : ''}
                </option>
              ))}
            </Select>
          </label>

          {kind && (
            <label style={{ color: DIM, fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em' }}>
              BMC HOST NODE (owns the bus)
              <Select value={hostNode} onChange={(e) => setHostNode(e.target.value)} style={{ display: 'block', marginTop: 4, width: '100%' }}>
                <option value="">— select a node —</option>
                {nodes.map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.id} ({n.role})
                  </option>
                ))}
              </Select>
            </label>
          )}

          {kind === 'mock' && (
            <div>
              <div style={{ color: DIM, fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em', marginBottom: 4 }}>
                TARGETS (nodes the mock pretends to reach)
              </div>
              {nodes.map((n) => (
                <label key={n.id} style={{ display: 'flex', alignItems: 'center', gap: 8, color: FG, fontFamily: MONO, fontSize: 11, padding: '2px 0' }}>
                  <input
                    type="checkbox"
                    checked={mockTargets.has(n.id)}
                    onChange={(e) => {
                      const next = new Set(mockTargets);
                      if (e.target.checked) next.add(n.id);
                      else next.delete(n.id);
                      setMockTargets(next);
                    }}
                  />
                  {n.id}
                </label>
              ))}
            </div>
          )}

          {kind === 'bitscope' && (
            <>
              <label style={{ color: DIM, fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em' }}>
                SERIAL DEVICE
                <Input value={bsDev} onChange={(e) => setBsDev(e.target.value)} placeholder="/dev/serial0" style={{ display: 'block', marginTop: 4, width: '100%' }} />
              </label>
              <label style={{ color: DIM, fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em' }}>
                UNLOCK SEQUENCE {bsUnlockSet ? '(set — leave blank to keep)' : '(blank = factory default)'}
                <Input type="password" value={bsUnlock} onChange={(e) => setBsUnlock(e.target.value)} placeholder={bsUnlockSet ? '••••••••' : 'UnLockMe'} style={{ display: 'block', marginTop: 4, width: '100%' }} />
              </label>
              <label style={{ color: DIM, fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em' }}>
                ADDRESS MAP (JSON rows: {'{"pos":"A-0","node_id":"…"}'})
                <textarea
                  value={bsMapJSON}
                  onChange={(e) => setBsMapJSON(e.target.value)}
                  rows={6}
                  spellCheck={false}
                  style={{
                    display: 'block', marginTop: 4, width: '100%', background: 'transparent',
                    border: `1px solid ${HAIR}`, color: FG, fontFamily: MONO, fontSize: 11, padding: 8,
                  }}
                />
              </label>
            </>
          )}

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Btn variant="primary" disabled={busy || (kind !== '' && !hostNode)} onClick={() => setConfirming(true)}>
              {busy ? 'APPLYING…' : 'APPLY'}
            </Btn>
            {jobNote && <span style={{ color: DIM, fontFamily: MONO, fontSize: 10 }}>{jobNote}</span>}
          </div>
        </div>
      )}

      {err && <Hint warn style={{ marginTop: 10 }}>{err}</Hint>}

      {confirming && (
        <ConfirmModal
          title={kind ? `Configure ${kind.toUpperCase()} BMC?` : 'Turn BMC off?'}
          message={
            kind
              ? `The selection is pushed to ${hostNode || 'the host node'}, which takes over the BMC bus and re-registers. Any open serial console closes. Power and CONSOLE controls appear only for the advertised targets.`
              : 'The host clears its BMC configuration and stops advertising targets. Every power and console control disappears and the api refuses BMC operations — hard off.'
          }
          confirmLabel={busy ? 'APPLYING…' : 'APPLY'}
          onConfirm={() => void apply()}
          onCancel={() => setConfirming(false)}
        />
      )}
    </>
  );
}

function ObservabilitySection() {
  const [status, setStatus] = useState<ObsStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<'on' | 'off' | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  const state = status?.state ?? 'off';

  useEffect(() => {
    let alive = true;
    const load = () =>
      getObsStatus()
        .then((s) => alive && setStatus(s))
        .catch((e) => alive && setErr(String(e)));
    load();
    // Poll while the stack is warming up so the section converges on its own
    // — a cold enable can take minutes and there's no push channel for status.
    // Idle at a slow tick otherwise; this page isn't a dashboard.
    const every = state === 'starting' ? 3000 : 15000;
    const t = setInterval(load, every);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [state]);

  async function apply(next: 'on' | 'off') {
    setBusy(true);
    setErr(null);
    try {
      const job = next === 'on' ? await enableObs() : await disableObs();
      setJobId(job.id);
      setStatus(await getObsStatus());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
      setPending(null);
    }
  }

  return (
    <>
      <SectionLabel>METRICS &amp; LOGS</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        Records each node&apos;s CPU, memory and disk over time, plus container activity, searchable
        logs, and threshold alerts. Node status, tasks and basic alerts work without this — turning it
        on adds the history and the charts.
      </Hint>

      {status === null && !err && <Hint>Loading…</Hint>}

      {status && (
        <div style={{ maxWidth: 560 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
            <EnabledToggle
              enabled={state !== 'off'}
              onToggle={() => !busy && state !== 'starting' && setPending(state === 'off' ? 'on' : 'off')}
              title={state === 'starting' ? 'Starting — please wait' : undefined}
            />
            <span style={{ color: DIM, fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em' }}>
              {state === 'on' && 'RECORDING'}
              {state === 'starting' && 'STARTING…'}
              {state === 'off' && 'NOT RECORDING'}
            </span>
          </div>

          {state === 'starting' && (
            <Hint style={{ marginBottom: 10 }}>
              Downloading and starting. The first run fetches roughly 500 MB and can take several
              minutes — you can leave this page.{' '}
              {jobId && <a href="/tasks" style={{ color: ACCENT }}>Follow it in Tasks →</a>}
            </Hint>
          )}

          {state === 'off' && (
            <Hint style={{ marginBottom: 10 }}>
              Uses roughly 500 MB of downloads on first start, then grows as it records. Best on a
              control plane with an SSD or NVMe drive.
            </Hint>
          )}

          {/* A stuck "starting" is almost always a pull or health failure —
              surface it here rather than making the operator find Tasks. */}
          {state === 'starting' && status.lastError && <Hint warn>{status.lastError}</Hint>}
          {err && <Hint warn>{err}</Hint>}
        </div>
      )}

      {pending === 'on' && (
        <ConfirmModal
          title="Turn on metrics & logs?"
          message={
            'Rasputin will download about 500 MB the first time, then start recording history to this control plane. Expect a few minutes before charts fill in.\n\n' +
            'Recorded data keeps growing over time and is not size-capped yet, so this is best on a control plane with an SSD or NVMe drive rather than a memory card.'
          }
          confirmLabel={busy ? 'TURNING ON…' : 'TURN ON'}
          onConfirm={() => apply('on')}
          onCancel={() => setPending(null)}
        />
      )}

      {pending === 'off' && (
        <ConfirmModal
          title="Turn off metrics & logs?"
          message={
            'Charts, container activity, log search and threshold alerts stop working, and node history stops being recorded.\n\n' +
            'Everything already recorded is kept — turning this back on later picks up where it left off. Node status and basic alerts are unaffected.'
          }
          confirmLabel={busy ? 'TURNING OFF…' : 'TURN OFF'}
          onConfirm={() => apply('off')}
          onCancel={() => setPending(null)}
        />
      )}
    </>
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
