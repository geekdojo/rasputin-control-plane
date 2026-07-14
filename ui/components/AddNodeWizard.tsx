'use client';

import { ChevronDown, ChevronRight, Cpu, Database, Download, Plus, Shield, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getFirewallImage, getOperatorKeys, mintBusToken, setOperatorKeys } from '../lib/api';
import type { FlashableImage, MintedBusToken } from '../lib/types';
import {
  type AddableRole,
  type NodeArch,
  downloadSeed,
  FIREWALL_HOST_PLACEHOLDER,
  firewallApplyCommand,
  flashCommand,
  NODE_ARCHES,
  nodeImageFor,
  renderFirewallSeed,
  renderNodeSeed,
  suggestNodeId,
  validateSSHKey,
} from '../lib/enroll';
import { Btn, CopyButton, DIM, FG, HAIR, Hint, Input, SectionLabel, Tok } from './kit';
import { ACCENT, accentA, MONO } from './ui-theme';

const ROLES: { value: AddableRole; label: string; icon: typeof Cpu; blurb: string }[] = [
  { value: 'compute', label: 'COMPUTE', icon: Cpu, blurb: 'runs apps & workloads' },
  { value: 'storage', label: 'STORAGE', icon: Database, blurb: 'storage-focused node' },
  { value: 'firewall', label: 'FIREWALL', icon: Shield, blurb: 'network edge & security' },
];

// The firewall is x86-only (a single PCIe lane + 5 W ceiling rule out ARM
// boards), so its enrollment always targets the amd64 image.
const FIREWALL_ARCH: NodeArch = 'amd64';

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
  const [arch, setArch] = useState<NodeArch>('amd64');
  const [nodeId, setNodeId] = useState(() => suggestNodeId(clusterPrefix, 'compute', taken));
  const [edited, setEdited] = useState(false);
  const [sshKeyInput, setSshKeyInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [minted, setMinted] = useState<MintedBusToken | null>(null);
  // The cluster-remembered operator key(s): prefill source + the list we
  // append to on mint. null until fetched (or if the fetch failed — then we
  // skip the persist rather than risk clobbering the stored list).
  const [rememberedKeys, setRememberedKeys] = useState<string[] | null>(null);
  const [prefilled, setPrefilled] = useState(false);

  // Prefill the SSH key from the cluster setting — the cluster has seen the
  // operator's key on every seed it ever minted, so don't re-ask. Best-effort:
  // a failed fetch just leaves the field manual, and an operator who already
  // started typing wins over the prefill.
  useEffect(() => {
    let alive = true;
    getOperatorKeys()
      .then((ok) => {
        if (!alive) return;
        setRememberedKeys(ok.keys);
        if (ok.captured && ok.keys.length > 0) {
          setSshKeyInput((cur) => {
            if (cur !== '') return cur; // operator got there first
            setPrefilled(true);
            return ok.keys[0];
          });
        }
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const isFirewall = role === 'firewall';
  // Images bake no SSH key (pre-GA vendor-key removal) — the seed line minted
  // here is the node's only network-SSH path. Optional: blank = console/UI-only.
  const sshCheck = validateSSHKey(sshKeyInput);

  // Re-suggest the id when the role changes, unless the user has hand-edited it.
  // The firewall is x86-only, so selecting it pins the arch to amd64 (the arch
  // picker is hidden for that role).
  function pickRole(r: AddableRole) {
    setRole(r);
    if (r === 'firewall') setArch(FIREWALL_ARCH);
    if (!edited) setNodeId(suggestNodeId(clusterPrefix, r, taken));
  }

  const collision = taken.has(nodeId.trim());
  const valid = nodeId.trim().length > 0 && !collision && !sshCheck.error;

  async function generate() {
    if (!valid) return;
    setBusy(true);
    setErr(null);
    try {
      const id = nodeId.trim();
      const m = await mintBusToken(role, id);
      setMinted(m);
      onMinted({ id: m.nodeId || id, tokenId: m.id, role });
      // Remember a newly-seen key for the next enrollment (persist-on-mint).
      // Best-effort and non-blocking — the mint already succeeded; skipped
      // when the stored list never loaded (a blind PUT could clobber it).
      if (sshCheck.key && rememberedKeys && !rememberedKeys.includes(sshCheck.key)) {
        setOperatorKeys([...rememberedKeys, sshCheck.key]).catch(() => {});
      }
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
        isFirewall ? (
          <FirewallSuccessView nodeId={minted.nodeId} token={minted.token} sshKey={sshCheck.key} onClose={onClose} />
        ) : (
          <SuccessView
            role={role}
            arch={arch}
            nodeId={minted.nodeId}
            token={minted.token}
            sshKey={sshCheck.key}
            clusterOsVersion={clusterOsVersion}
            onClose={onClose}
          />
        )
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

          {isFirewall ? (
            <Hint style={{ marginBottom: 16 }}>
              The firewall runs on an Intel/AMD (<Tok>x86-64</Tok>) board — a Raspberry Pi can&apos;t drive
              dual high-speed network ports, so this role is x86-only.
            </Hint>
          ) : (
            <>
          <SectionLabel>ARCHITECTURE</SectionLabel>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            {NODE_ARCHES.map((a) => {
              const sel = arch === a.value;
              return (
                <button
                  key={a.value}
                  onClick={() => setArch(a.value)}
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
                  <span style={{ color: sel ? ACCENT : FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>{a.label}</span>
                  <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>{a.blurb}</span>
                </button>
              );
            })}
          </div>
          <Hint style={{ marginBottom: 16 }}>
            The CPU of the board you&apos;re flashing. Pick <Tok>ARM64</Tok> for a Raspberry Pi, <Tok>AMD64</Tok> for an Intel/AMD board.
          </Hint>
            </>
          )}

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

          <SectionLabel>SSH KEY (OPTIONAL)</SectionLabel>
          <Input
            value={sshKeyInput}
            onChange={(e) => setSshKeyInput(e.target.value)}
            placeholder="ssh-ed25519 AAAA… you@laptop"
            spellCheck={false}
            style={{ width: '100%', marginBottom: 6 }}
          />
          {sshCheck.error ? (
            <Hint warn style={{ marginBottom: 16 }}>{sshCheck.error}</Hint>
          ) : prefilled && rememberedKeys?.includes(sshCheck.key) ? (
            <Hint style={{ marginBottom: 16 }}>
              Remembered from your earlier enrollments — edit to use a different key for this node,
              or manage the stored key under <Tok>Settings</Tok>.
            </Hint>
          ) : (
            <Hint style={{ marginBottom: 16 }}>
              Paste your SSH <em>public</em> key (from e.g. <Tok>~/.ssh/id_ed25519.pub</Tok>) to enable
              key-only SSH to this node. Images ship with no key at all — leave blank and the node is
              reachable via this UI and its local console only.
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
  arch,
  nodeId,
  token,
  sshKey,
  clusterOsVersion,
  onClose,
}: {
  role: AddableRole;
  arch: NodeArch;
  nodeId: string;
  token: string;
  sshKey: string;
  clusterOsVersion?: string;
  onClose: () => void;
}) {
  const seed = renderNodeSeed(role, nodeId, token, sshKey);
  const image = nodeImageFor(clusterOsVersion, arch);
  const command = flashCommand(seed, arch);
  const archLabel = NODE_ARCHES.find((a) => a.value === arch)?.label ?? arch.toUpperCase();
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
          <Tok>{archLabel}</Tok> image, verifies it, flashes the drive, writes <Tok>{nodeId}</Tok>&apos;s
          enrollment (and checks it landed), then ejects.
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
                  Flash <Tok>Rasputin OS {image.version}</Tok> <Tok>{archLabel}</Tok> (your cluster&apos;s version) to the node&apos;s storage —{' '}
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

// The firewall is a different beast from an OS node: it ships its own x86-only
// image and is typically ALREADY running it (bundled units arrive pre-imaged),
// so enrollment is an over-the-network push of the seed — not a blank-drive
// flash. No flash.sh one-liner here; instead the operator saves the seed and
// delivers it over SSH. A collapsible covers imaging a brand-new board.
function FirewallSuccessView({
  nodeId,
  token,
  sshKey,
  onClose,
}: {
  nodeId: string;
  token: string;
  sshKey: string;
  onClose: () => void;
}) {
  const seed = renderFirewallSeed(nodeId, token, sshKey);
  const command = firewallApplyCommand();
  const [showImage, setShowImage] = useState(false);
  const [image, setImage] = useState<FlashableImage | null>(null);
  const [imageResolved, setImageResolved] = useState(false);

  // Resolve the latest firewall image so we can offer a verified download for a
  // fresh board. Best-effort: on failure we fall back to the release channel.
  useEffect(() => {
    let live = true;
    getFirewallImage()
      .then((img) => live && setImage(img))
      .finally(() => live && setImageResolved(true));
    return () => {
      live = false;
    };
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* The seed — the only secret. Save it now; it's unrecoverable. */}
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
          <Btn variant="primary" small onClick={() => downloadSeed(seed, 'seed.env')}>
            <Download size={11} /> DOWNLOAD seed.env
          </Btn>
        </div>
      </div>

      {/* Delivery: push the seed to the already-running firewall over SSH.
          This path needs SSH access — i.e. a firewall that was previously
          seeded with your key. A brand-new board has no credentials at all
          (images ship key-less, password auth off) and takes the seed via
          its FAT partition instead — see the collapsible below. */}
      <SectionLabel>DELIVER IT TO THE FIREWALL</SectionLabel>
      <span style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.5 }}>
        Your firewall is already running and enrolled with your SSH key. From the folder where you
        saved <Tok>seed.env</Tok>, run this — swap <Tok>{FIREWALL_HOST_PLACEHOLDER}</Tok> for the
        firewall&apos;s address on your network:
      </span>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
        <pre style={{ ...seedBox, flex: 1, minWidth: 0 }}>{command}</pre>
        <CopyButton value={command} />
      </div>
      <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
        It copies the file into place and applies it — the firewall joins immediately, no reboot.
        No SSH access yet? Use the brand-new-board steps below instead.
      </span>

      {/* Fallback: image a brand-new board first. */}
      <button
        onClick={() => setShowImage((v) => !v)}
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
        {showImage ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        Setting up a brand-new firewall board?
      </button>

      {showImage && (
        <>
          <SectionLabel>IMAGE THE BOARD FIRST</SectionLabel>
          <ol style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              image ? (
                <>
                  Write the <Tok>firewall image {image.version}</Tok> (<Tok>x86-64</Tok>) to the whole disk of
                  the firewall board —{' '}
                  <a href={image.url} target="_blank" rel="noreferrer" style={linkStyle}>
                    download the image
                  </a>{' '}
                  (verify its sha256 <Tok>{image.sha256.slice(0, 12)}…</Tok> against the release&apos;s{' '}
                  <Tok>manifest.json</Tok>).
                </>
              ) : imageResolved ? (
                <>
                  Write the latest <Tok>x86-64</Tok> firewall image to the whole disk of the board —{' '}
                  <a href={FIREWALL_RELEASES_URL} target="_blank" rel="noreferrer" style={linkStyle}>
                    grab the newest release&apos;s <Tok>-ab.img.gz</Tok>
                  </a>
                  .
                </>
              ) : (
                <>Resolving the latest firewall image…</>
              ),
              <>
                Before booting, put the seed on the disk: the image&apos;s first partition is a small FAT
                volume labeled <Tok>RASPUTIN-FW</Tok> — mount it on your computer and copy{' '}
                <Tok>seed.env</Tok> to its root. (A fresh image has no SSH credentials at all, so this —
                not the command above — is how the first seed gets on.)
              </>,
              <>Connect the board to your network and boot — it seeds itself and joins.</>,
            ].map((step, i) => (
              <li key={i} style={{ color: DIM, fontSize: 11, fontFamily: MONO, lineHeight: 1.5 }}>
                {step}
              </li>
            ))}
          </ol>
        </>
      )}

      <Hint>
        It&apos;ll appear below as <Tok>PENDING</Tok> until it applies the file and joins — usually seconds —
        then flip to a live node automatically.
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

// Fallback link when the control plane can't resolve a specific firewall image
// (no release on the channel yet, or the update channel isn't configured): the
// public release channel, where the operator can grab the newest firewall build.
const FIREWALL_RELEASES_URL = 'https://github.com/geekdojo/rasputin-openwrt-firewall/releases';

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
