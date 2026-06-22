'use client';

import { ChevronDown, ChevronRight, Cpu, Database, Download, Plus, X } from 'lucide-react';
import { useState } from 'react';
import { mintBusToken } from '../lib/api';
import type { MintedBusToken } from '../lib/types';
import {
  type AddableRole,
  downloadSeed,
  flashCommand,
  nodeImageFor,
  renderNodeSeed,
  suggestNodeId,
} from '../lib/enroll';
import { Btn, CopyButton, DIM, FG, HAIR, Hint, Input, SectionLabel, Tok } from './kit';
import { ACCENT, accentA, MONO } from './ui-theme';

const ROLES: { value: AddableRole; label: string; icon: typeof Cpu; blurb: string }[] = [
  { value: 'compute', label: 'COMPUTE', icon: Cpu, blurb: 'runs apps & workloads' },
  { value: 'storage', label: 'STORAGE', icon: Database, blurb: 'storage-focused node' },
];

export function AddNodeWizard({
  clusterPrefix,
  clusterOsVersion,
  taken,
  onClose,
  onMinted,
}: {
  clusterPrefix: string;
  // The cluster's OS version (the controlplane's), so the wizard can tell the
  // operator which image to flash + link the matching download. Undefined when
  // unknown → generic guidance.
  clusterOsVersion?: string;
  taken: Set<string>;
  // Reports the freshly-minted pending enrollment so the grid can show it and
  // start watching for the node to come online.
  onMinted: (p: { id: string; tokenId: string; role: AddableRole }) => void;
  onClose: () => void;
}) {
  const [role, setRole] = useState<AddableRole>('compute');
  const [nodeId, setNodeId] = useState(() => suggestNodeId(clusterPrefix, 'compute', taken));
  const [edited, setEdited] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [minted, setMinted] = useState<MintedBusToken | null>(null);

  // Re-suggest the id when the role changes, unless the user has hand-edited it.
  function pickRole(r: AddableRole) {
    setRole(r);
    if (!edited) setNodeId(suggestNodeId(clusterPrefix, r, taken));
  }

  const collision = taken.has(nodeId.trim());
  const valid = nodeId.trim().length > 0 && !collision;

  async function generate() {
    if (!valid) return;
    setBusy(true);
    setErr(null);
    try {
      const id = nodeId.trim();
      const m = await mintBusToken(role, id);
      setMinted(m);
      onMinted({ id: m.nodeId || id, tokenId: m.id, role });
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Plus size={14} color={ACCENT} />
          <span style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.1em' }}>ADD NODE</span>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }} title="Close">
          <X size={14} color={DIM} />
        </button>
      </div>
      <div style={{ height: 1, background: HAIR, marginBottom: 16 }} />

      {minted ? (
        <SuccessView
          role={role}
          nodeId={minted.nodeId}
          token={minted.token}
          clusterOsVersion={clusterOsVersion}
          onClose={onClose}
        />
      ) : (
        <>
          <SectionLabel>ROLE</SectionLabel>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            {ROLES.map((r) => {
              const Icon = r.icon;
              const sel = role === r.value;
              return (
                <button
                  key={r.value}
                  onClick={() => pickRole(r.value)}
                  style={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'flex-start',
                    gap: 4,
                    padding: '10px 12px',
                    background: sel ? accentA(0.08) : 'rgba(var(--rasp-fg-rgb),0.03)',
                    border: `1px solid ${sel ? accentA(0.5) : HAIR}`,
                    cursor: 'pointer',
                    transition: 'background 0.15s, border-color 0.15s',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <Icon size={13} color={sel ? ACCENT : DIM} />
                    <span style={{ color: sel ? ACCENT : FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>{r.label}</span>
                  </div>
                  <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>{r.blurb}</span>
                </button>
              );
            })}
          </div>

          <SectionLabel>NODE NAME</SectionLabel>
          <Input
            value={nodeId}
            onChange={(e) => {
              setNodeId(e.target.value);
              setEdited(true);
            }}
            spellCheck={false}
            style={{ width: '100%', marginBottom: 6 }}
          />
          {collision ? (
            <Hint warn style={{ marginBottom: 16 }}>
              <Tok>{nodeId.trim()}</Tok> is already taken — pick another name.
            </Hint>
          ) : (
            <Hint style={{ marginBottom: 16 }}>
              A unique name for this node. The suggestion follows your cluster&apos;s naming; edit if you like.
            </Hint>
          )}

          {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <Btn onClick={onClose} disabled={busy}>CANCEL</Btn>
            <Btn variant="primary" onClick={generate} disabled={busy || !valid}>
              {busy ? 'GENERATING…' : 'GENERATE ENROLLMENT FILE'}
            </Btn>
          </div>
        </>
      )}
    </Overlay>
  );
}

function SuccessView({
  role,
  nodeId,
  token,
  clusterOsVersion,
  onClose,
}: {
  role: AddableRole;
  nodeId: string;
  token: string;
  clusterOsVersion?: string;
  onClose: () => void;
}) {
  const seed = renderNodeSeed(role, nodeId, token);
  const image = nodeImageFor(clusterOsVersion);
  const command = flashCommand(seed);
  const [showManual, setShowManual] = useState(false);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Primary path: one command flashes + enrolls the node end to end. */}
      <div
        style={{
          background: accentA(0.06),
          border: `1px solid ${accentA(0.4)}`,
          padding: '12px 14px',
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
        }}
      >
        <span style={{ color: ACCENT, fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>
          FLASH THIS NODE IN ONE COMMAND
        </span>
        <span style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.5 }}>
          Plug the new node&apos;s drive into your computer, then run this. It downloads the matching
          image, verifies it, flashes the drive, writes <Tok>{nodeId}</Tok>&apos;s enrollment (and
          checks it landed), then ejects.
        </span>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
          <pre style={{ ...seedBox, flex: 1, minWidth: 0 }}>{command}</pre>
          <CopyButton value={command} />
        </div>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
          macOS &amp; Linux. Only offers external/removable drives, and asks you to confirm before it writes anything.
        </span>
      </div>

      {/* Fallback: hand-flash with the seed file. */}
      <button
        onClick={() => setShowManual((v) => !v)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          padding: 0,
          color: DIM,
          fontSize: 10,
          fontFamily: MONO,
        }}
      >
        {showManual ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        Prefer to flash manually?
      </button>

      {showManual && (
        <>
          <div
            style={{
              background: accentA(0.06),
              border: `1px solid ${accentA(0.4)}`,
              padding: '12px 14px',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
            }}
          >
            <span style={{ color: ACCENT, fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>
              ENROLLMENT FILE — SAVE IT NOW, NOT SHOWN AGAIN
            </span>
            <span style={{ color: FG, fontSize: 10, fontFamily: MONO }}>
              for <Tok>{nodeId}</Tok>
            </span>
            <div style={{ position: 'relative' }}>
              <pre style={seedBox}>{seed}</pre>
              <div style={{ position: 'absolute', top: 4, right: 4 }}>
                <CopyButton value={seed} />
              </div>
            </div>
            <div>
              <Btn variant="primary" small onClick={() => downloadSeed(seed)}>
                <Download size={11} /> DOWNLOAD rasputin-seed.env
              </Btn>
            </div>
          </div>

          <SectionLabel>MANUAL STEPS</SectionLabel>
          <ol style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              image ? (
                <>
                  Flash <Tok>Rasputin OS {image.version}</Tok> (your cluster&apos;s version) to the node&apos;s storage —{' '}
                  <a href={image.downloadUrl} target="_blank" rel="noreferrer" style={linkStyle}>
                    download the image
                  </a>{' '}
                  (
                  <a href={image.releaseUrl} target="_blank" rel="noreferrer" style={linkStyle}>
                    verify against the checksum in the release&apos;s manifest
                  </a>
                  ).
                </>
              ) : (
                <>Flash a Rasputin OS node image — the same build your cluster runs — to the new node&apos;s storage.</>
              ),
              <>Copy this <Tok>rasputin-seed.env</Tok> to the root of the disk&apos;s boot partition (labeled <Tok>RASPUTIN-FW</Tok>).</>,
              <>Seat the node in the backplane and power it on.</>,
            ].map((step, i) => (
              <li key={i} style={{ color: DIM, fontSize: 11, fontFamily: MONO, lineHeight: 1.5 }}>
                {step}
              </li>
            ))}
          </ol>
        </>
      )}

      <Hint>
        It&apos;ll appear below as <Tok>PENDING</Tok> until it powers on and joins — usually under a minute — then
        flip to a live node automatically.
      </Hint>

      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Btn variant="primary" onClick={onClose}>DONE</Btn>
      </div>
    </div>
  );
}

function Overlay({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  return (
    <div
      onClick={onClose}
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
          background: 'var(--rasp-panel)',
          border: `1px solid ${HAIR}`,
          padding: 24,
          width: 440,
          maxHeight: '88vh',
          overflowY: 'auto',
        }}
      >
        {children}
      </div>
    </div>
  );
}

const linkStyle: React.CSSProperties = { color: ACCENT, textDecoration: 'underline' };

const seedBox: React.CSSProperties = {
  margin: 0,
  padding: '8px 10px',
  background: '#060c16',
  border: `1px solid ${HAIR}`,
  color: '#cdd6e4',
  fontSize: 10,
  fontFamily: MONO,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
};
