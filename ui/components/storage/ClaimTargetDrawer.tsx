'use client';

// The claim flow — design/storage.md §4.8's destructive confirmation and §4.6's
// key ceremony, in one drawer.
//
// Three things this file is shaped around, in descending order of consequence:
//
//  1. **Wipe is harder to reach than adopt, deliberately.** Adopting is one
//     button. Wiping is behind a closed disclosure, then an exactly-typed
//     string that is SPECIFIC TO THIS DISK (its serial), then a checkbox naming
//     how many generations die. §4.8 calls this "the one interaction in §4
//     capable of losing the data §4 was built to keep", and the interaction
//     cost should say so.
//  2. **No plaintext key material leaves the browser.** The passphrase lives in
//     an uncontrolled input — it is never in React state, never in a request,
//     never in an error string. The data key is minted, wrapped twice and
//     zeroed inside lib/archive-key.ts and is never seen here at all.
//  3. **The recovery code is displayed exactly once, behind a forced
//     acknowledgement**, BEFORE the claim is submitted. See the comment on the
//     recovery step for why that order and not the other one.

import { AlertTriangle, Database, HardDrive, KeyRound, ShieldCheck } from 'lucide-react';
import { useRef, useState } from 'react';
import { claimBackupTarget } from '../../lib/api';
import { mintArchiveKey, type MintedArchiveKey } from '../../lib/archive-key';
import type { BackupCandidate, BackupTarget, ClaimBackupTargetRequest, Job } from '../../lib/types';
import {
  Btn,
  CopyButton,
  DIM,
  Drawer,
  FG,
  HAIR,
  HAIR_SOFT,
  Hint,
  Input,
  SectionLabel,
  Tok,
} from '../kit';
import { ACCENT, accentA, MONO } from '../ui-theme';
import {
  type CandidateDisposition,
  diskName,
  disposition,
  formatDiskSize,
  partitionLine,
  partitionSummary,
  transportLabel,
  wipePhrase,
} from './format';

const DANGER = '#f87171';
const WARN = '#facc15';
const OK_GREEN = '#4ade80';

/** Minimum passphrase length. Argon2id raises the cost of each guess; it cannot
 * make a four-character passphrase take more than a moment to exhaust. */
const MIN_PASSPHRASE = 12;

type Step = 'confirm' | 'passphrase' | 'recovery' | 'done';

export function ClaimTargetDrawer({
  candidate,
  nodeId,
  existingTarget,
  onClose,
  onSubmitted,
}: {
  candidate: BackupCandidate;
  nodeId: string;
  /** The cluster's currently-claimed target, if it has one. Drives `replace`. */
  existingTarget?: BackupTarget;
  onClose: () => void;
  onSubmitted: (job: Job) => void;
}) {
  const disp = disposition(candidate);
  const [step, setStep] = useState<Step>('confirm');
  const [wipeArmed, setWipeArmed] = useState(false);
  const [label, setLabel] = useState(candidate.backupSet?.label ?? '');
  const [replace, setReplace] = useState(false);
  const [minted, setMinted] = useState<MintedArchiveKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [job, setJob] = useState<Job | null>(null);

  const action: 'format' | 'adopt' | 'wipe' = disp === 'format' ? 'format' : wipeArmed ? 'wipe' : 'adopt';

  // A fresh backup set means a fresh §4.6 data key. Adoption is the opposite:
  // the disk's generations are ALREADY encrypted under the key its marker
  // names, and minting a new one here would record a key that unlocks nothing
  // on that disk. So the ceremony runs for format and wipe, and never for
  // adopt.
  const mintsFreshKey = action === 'format' || action === 'wipe';

  const needsReplace = Boolean(existingTarget) && existingTarget?.status === 'claimed';

  async function submit(archiveKey?: MintedArchiveKey) {
    setBusy(true);
    setErr(null);
    try {
      const req: ClaimBackupTargetRequest = {
        nodeId,
        devicePath: candidate.devicePath,
        fingerprint: candidate.fingerprint,
        ...(label.trim() ? { label: label.trim() } : {}),
        ...(needsReplace && replace ? { replace: true } : {}),
        ...(action === 'adopt' ? { adopt: true } : {}),
        // The token is echoed back verbatim from the picker. Its absence is a
        // refusal, never a default — and a candidate with no token has no wipe
        // control to reach this branch from.
        ...(action === 'wipe' && candidate.wipeToken ? { wipe: { token: candidate.wipeToken } } : {}),
        ...(archiveKey ? { archiveKey: archiveKey.archiveKey } : {}),
      };
      const j = await claimBackupTarget(req);
      setJob(j);
      setStep('done');
      onSubmitted(j);
    } catch (e) {
      // The passphrase and the data key are not in scope here and cannot reach
      // this string: `req` above has no field for either.
      setErr(String(e));
      if (archiveKey) {
        // The wrapped key was built for a claim that did not happen. Drop it and
        // send the operator back to mint a new one rather than re-submitting
        // material whose recovery code they have already been shown and told is
        // final — a second claim under the same code would make "shown once"
        // a lie about which target it belongs to.
        setMinted(null);
        setStep('passphrase');
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer title={titleFor(step, action, disp)} onClose={onClose}>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <DiskFacts candidate={candidate} />

        {step === 'confirm' && (
          <ConfirmStep
            candidate={candidate}
            label={label}
            onLabel={setLabel}
            needsReplace={needsReplace}
            existingTarget={existingTarget}
            replace={replace}
            onReplace={setReplace}
            wipeArmed={wipeArmed}
            onArmWipe={setWipeArmed}
            busy={busy}
            onContinue={() => (mintsFreshKey ? setStep('passphrase') : submit())}
          />
        )}

        {step === 'passphrase' && (
          <PassphraseStep
            busy={busy}
            onBack={() => setStep('confirm')}
            onMinted={(m) => {
              setMinted(m);
              setStep('recovery');
            }}
            onError={setErr}
            setBusy={setBusy}
          />
        )}

        {step === 'recovery' && minted && (
          <RecoveryStep
            minted={minted}
            busy={busy}
            action={action}
            onConfirm={() => submit(minted)}
          />
        )}

        {step === 'done' && job && <DoneStep job={job} action={action} encrypted={Boolean(minted)} />}

        {err && (
          <div
            role="alert"
            style={{ color: DANGER, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, border: `1px solid ${DANGER}`, padding: '8px 10px' }}
          >
            {err}
          </div>
        )}
      </div>
    </Drawer>
  );
}

function titleFor(step: Step, action: 'format' | 'adopt' | 'wipe', disp: CandidateDisposition): string {
  if (step === 'passphrase') return 'ARCHIVE ENCRYPTION';
  if (step === 'recovery') return 'RECOVERY CODE — SHOWN ONCE';
  if (step === 'done') return 'CLAIM SUBMITTED';
  if (action === 'wipe') return 'DESTROY BACKUP SET';
  // An unreadable marker cannot be adopted, so the drawer must not announce
  // itself as the adopt flow — the title would be offering the one thing this
  // disk is the exception to.
  if (disp === 'unreadable') return 'REVIEW DISK — MARKER UNREADABLE';
  if (action === 'adopt') return 'ADOPT BACKUP TARGET';
  return 'CLAIM BACKUP TARGET';
}

// ---------------------------------------------------------------------------
// The disk, stated the same way on every step. §4.8: model, size and current
// contents, in front of the operator at the moment they confirm.
// ---------------------------------------------------------------------------

function DiskFacts({ candidate }: { candidate: BackupCandidate }) {
  const parts = candidate.partitions ?? [];
  return (
    <div style={{ border: `1px solid ${HAIR}`, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <HardDrive size={13} color={ACCENT} />
        <span style={{ color: FG, fontSize: 12, fontFamily: MONO }}>{diskName(candidate)}</span>
      </div>
      <Row k="SIZE" v={formatDiskSize(candidate.sizeBytes)} />
      <Row k="BUS" v={`${transportLabel(candidate.transport)}${candidate.removable ? ' · removable' : ''}`} />
      <Row k="PATH" v={candidate.devicePath} />
      {candidate.serial && <Row k="SERIAL" v={candidate.serial} />}
      {candidate.wwn && <Row k="WWN" v={candidate.wwn} />}
      <Row k="CONTENTS" v={partitionSummary(parts)} />
      {parts.length > 0 && (
        <ul style={{ margin: 0, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 3 }}>
          {parts.map((p) => (
            <li key={p.devicePath} style={{ color: DIM, fontSize: 9, fontFamily: MONO, lineHeight: 1.6 }}>
              {partitionLine(p)}
            </li>
          ))}
        </ul>
      )}
      {candidate.identityWeak && (
        <Hint warn>
          This disk reported neither a WWN nor a serial, so it is identified by model, size and
          partition table alone. Two identical blank sticks from one batch can look the same to
          that test — check the bus and the contents above before you continue.
        </Hint>
      )}
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
      <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.1em', minWidth: 74 }}>{k}</span>
      <span style={{ color: FG, fontSize: 10, fontFamily: MONO, wordBreak: 'break-all' }}>{v}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 1 — confirm what this does.
// ---------------------------------------------------------------------------

function ConfirmStep({
  candidate,
  label,
  onLabel,
  needsReplace,
  existingTarget,
  replace,
  onReplace,
  wipeArmed,
  onArmWipe,
  busy,
  onContinue,
}: {
  candidate: BackupCandidate;
  label: string;
  onLabel: (v: string) => void;
  needsReplace: boolean;
  existingTarget?: BackupTarget;
  replace: boolean;
  onReplace: (v: boolean) => void;
  wipeArmed: boolean;
  onArmWipe: (v: boolean) => void;
  busy: boolean;
  onContinue: () => void;
}) {
  const disp = disposition(candidate);
  const set = candidate.backupSet;
  const generations = set?.generations ?? 0;

  return (
    <>
      {disp === 'format' && (
        <Callout color={WARN} icon={AlertTriangle} title="THIS DISK WILL BE FORMATTED">
          Rasputin will repartition and format the whole disk, then claim it as the cluster&apos;s
          backup target. Everything on it is destroyed. This happens once, now — never on a
          later backup run.
        </Callout>
      )}

      {disp === 'adopt' && !wipeArmed && (
        <Callout color={OK_GREEN} icon={ShieldCheck} title="ADOPT — NOTHING IS DESTROYED">
          This disk already carries a Rasputin backup set. Adopting takes it over exactly as it
          stands: no format, no data lost. If you plugged this disk in to restore from it, this
          is the choice you want.
        </Callout>
      )}

      {disp === 'unreadable' && !wipeArmed && (
        <Callout color={WARN} icon={AlertTriangle} title="MARKER UNREADABLE">
          This disk announces a Rasputin backup set, but its marker file could not be read. It
          cannot be adopted — there is no partition UUID to adopt it by — and it cannot be
          claimed as a blank disk, because the backup-set refusal stands in the way. Destroying
          the set and claiming it fresh is the only way forward for this disk.
        </Callout>
      )}

      {set && !wipeArmed && (
        <div style={{ border: `1px solid ${HAIR}`, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <SectionLabel style={{ marginBottom: 2 }}>EXISTING BACKUP SET</SectionLabel>
          {set.label && <Row k="LABEL" v={set.label} />}
          {set.clusterId && <Row k="CLUSTER" v={set.clusterId} />}
          <Row k="GENERATIONS" v={generations > 0 ? String(generations) : 'none reported'} />
          {set.createdAt && <Row k="CREATED" v={new Date(set.createdAt).toLocaleString()} />}
          {set.keyId && <Row k="KEY ID" v={set.keyId} />}
          {set.keyId && (
            <Hint>
              These generations are encrypted under key <Tok>{set.keyId}</Tok>. Adopting records the
              target; reading those archives still needs the passphrase or recovery code from when
              that key was minted. Adoption does not — and cannot — mint a new one.
            </Hint>
          )}
        </div>
      )}

      {!wipeArmed && (
        <label htmlFor="target-label" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.1em' }}>
            LABEL (OPTIONAL)
          </span>
          <Input
            id="target-label"
            value={label}
            onChange={(e) => onLabel(e.target.value)}
            placeholder="e.g. Backup disk — desk drawer"
            maxLength={64}
          />
          <Hint>
            A name for you, not an identifier. The target is keyed by partition UUID, minted when
            the disk is formatted.
          </Hint>
        </label>
      )}

      {needsReplace && !wipeArmed && (
        <div style={{ border: `1px solid ${WARN}`, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: WARN, fontSize: 10, fontFamily: MONO, letterSpacing: '0.08em' }}>
            THIS CLUSTER ALREADY HAS A TARGET
          </span>
          <Hint>
            <Tok>{existingTarget?.label || existingTarget?.partUuid || 'the current target'}</Tok> is
            claimed. Claiming this disk supersedes it. The old target is not touched or erased —
            it may still hold the only copy of an archive — but backups stop going to it.
          </Hint>
          <Check
            id="replace-ack"
            checked={replace}
            onChange={onReplace}
            label="Supersede the current backup target"
          />
        </div>
      )}

      {!wipeArmed && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Btn
            variant="primary"
            disabled={busy || (needsReplace && !replace) || disp === 'unreadable'}
            onClick={onContinue}
            title={disp === 'unreadable' ? 'This disk cannot be adopted — its marker is unreadable' : undefined}
          >
            {busy ? 'SUBMITTING…' : disp === 'format' ? 'CONTINUE — SET UP ENCRYPTION' : 'ADOPT THIS DISK'}
          </Btn>
        </div>
      )}

      {/* The wipe path. Closed by default, and reached only by choosing to open
          it — §4.8's "second, separate choice", rendered as one. */}
      {candidate.wipeToken && (
        <WipeDisclosure
          candidate={candidate}
          generations={generations}
          armed={wipeArmed}
          onArm={onArmWipe}
          busy={busy}
          onContinue={onContinue}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// The wipe disclosure — the most dangerous control in the product.
// ---------------------------------------------------------------------------

function WipeDisclosure({
  candidate,
  generations,
  armed,
  onArm,
  busy,
  onContinue,
}: {
  candidate: BackupCandidate;
  generations: number;
  armed: boolean;
  onArm: (v: boolean) => void;
  busy: boolean;
  onContinue: () => void;
}) {
  const [typed, setTyped] = useState('');
  const [ack, setAck] = useState(false);
  const phrase = wipePhrase(candidate);
  const matches = typed.trim() === phrase;

  if (!armed) {
    return (
      <div style={{ borderTop: `1px solid ${HAIR_SOFT}`, paddingTop: 12 }}>
        <Btn
          variant="ghost"
          small
          onClick={() => onArm(true)}
          style={{ color: DANGER }}
          aria-label={`Destroy the backup set on ${diskName(candidate)} instead of adopting it`}
        >
          Destroy this backup set instead…
        </Btn>
      </div>
    );
  }

  return (
    <div style={{ border: `1px solid ${DANGER}`, background: 'rgba(248,113,113,0.05)', padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <AlertTriangle size={14} color={DANGER} />
        <span style={{ color: DANGER, fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>
          DESTROY THE BACKUP SET ON THIS DISK
        </span>
      </div>
      <Hint style={{ color: DANGER }}>
        {generations > 0
          ? `This destroys ${generations} retained archive generation${generations === 1 ? '' : 's'} and every secret they hold. `
          : 'This destroys the Rasputin backup set this disk carries. '}
        There is no undo, and no other copy unless you made one. If this disk was plugged in to
        restore from, close this and adopt it instead.
      </Hint>

      <label htmlFor="wipe-phrase" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.1em' }}>
          TYPE <span style={{ color: FG }}>{phrase}</span> TO CONFIRM
        </span>
        <Input
          id="wipe-phrase"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={phrase}
          autoComplete="off"
          spellCheck={false}
        />
      </label>

      <Check
        id="wipe-ack"
        checked={ack}
        onChange={setAck}
        label={
          generations > 0
            ? `I understand ${generations} archive generation${generations === 1 ? '' : 's'} will be destroyed`
            : 'I understand this backup set will be destroyed'
        }
      />

      <div style={{ display: 'flex', gap: 8 }}>
        <Btn variant="danger" disabled={busy || !matches || !ack} onClick={onContinue}>
          {busy ? 'SUBMITTING…' : 'DESTROY AND CLAIM'}
        </Btn>
        <Btn
          onClick={() => {
            setTyped('');
            setAck(false);
            onArm(false);
          }}
          disabled={busy}
        >
          CANCEL WIPE
        </Btn>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 2 — the passphrase. §4.6 custody path one.
// ---------------------------------------------------------------------------

function PassphraseStep({
  busy,
  onBack,
  onMinted,
  onError,
  setBusy,
}: {
  busy: boolean;
  onBack: () => void;
  onMinted: (m: MintedArchiveKey) => void;
  onError: (e: string | null) => void;
  setBusy: (v: boolean) => void;
}) {
  // Uncontrolled on purpose. A controlled field puts every keystroke of the
  // passphrase into React state, which is the thing that ends up in a devtools
  // snapshot, an error boundary's props dump, or a future "persist form state"
  // change nobody thinks about. Only two booleans derived from it live in
  // state; the characters live in the DOM node and are cleared on submit.
  const pass1 = useRef<HTMLInputElement>(null);
  const pass2 = useRef<HTMLInputElement>(null);
  const [longEnough, setLongEnough] = useState(false);
  const [matches, setMatches] = useState(false);

  function recheck() {
    const a = pass1.current?.value ?? '';
    const b = pass2.current?.value ?? '';
    setLongEnough(a.length >= MIN_PASSPHRASE);
    setMatches(a.length > 0 && a === b);
  }

  async function mint() {
    const value = pass1.current?.value ?? '';
    if (value.length < MIN_PASSPHRASE || value !== (pass2.current?.value ?? '')) return;
    setBusy(true);
    onError(null);
    try {
      // Encoded to bytes here and consumed (zeroed) by mintArchiveKey. The
      // string itself is immutable and cannot be wiped — what we can do, and
      // do, is keep its lifetime to this function and clear the inputs it came
      // from the moment the wrapping is done.
      const bytes = new TextEncoder().encode(value);
      const m = await mintArchiveKey(bytes);
      if (pass1.current) pass1.current.value = '';
      if (pass2.current) pass2.current.value = '';
      setLongEnough(false);
      setMatches(false);
      onMinted(m);
    } catch (e) {
      // mintArchiveKey never puts its inputs in an error; neither does this.
      onError(`could not mint the archive key: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Callout color={ACCENT} icon={KeyRound} title="THE ARCHIVE IS ENCRYPTED — THE KEY IS NOT OURS TO KEEP">
        A backup exists to survive this controlplane&apos;s death, so its key cannot live on it: a
        key stored under <Tok>/var/lib/rasputin</Tok> is inside the archive it encrypts. Rasputin
        generates the key in your browser and keeps only two sealed copies — one openable with the
        passphrase you choose now, one with a recovery code shown on the next screen.
      </Callout>

      <Hint warn>
        Losing either custody path is survivable; losing both is not. Nobody — not Rasputin, not
        Geekdojo — can open this archive without one of them.
      </Hint>

      <label htmlFor="archive-pass" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.1em' }}>PASSPHRASE</span>
        <Input
          id="archive-pass"
          ref={pass1}
          type="password"
          onChange={recheck}
          autoComplete="new-password"
          spellCheck={false}
          placeholder={`at least ${MIN_PASSPHRASE} characters`}
        />
      </label>

      <label htmlFor="archive-pass2" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.1em' }}>
          PASSPHRASE AGAIN
        </span>
        <Input
          id="archive-pass2"
          ref={pass2}
          type="password"
          onChange={recheck}
          autoComplete="new-password"
          spellCheck={false}
        />
      </label>

      <Hint>
        Length beats cleverness. A few unrelated words you will still recognise in two years
        outperforms a short string with substitutions in it — this passphrase is stretched with
        Argon2id, which prices each guess, but it cannot make a short one expensive to exhaust.
      </Hint>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <Btn variant="primary" disabled={busy || !longEnough || !matches} onClick={mint}>
          {busy ? 'DERIVING KEY…' : 'GENERATE KEY'}
        </Btn>
        <Btn onClick={onBack} disabled={busy}>
          BACK
        </Btn>
        {!longEnough && (
          <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
            at least {MIN_PASSPHRASE} characters
          </span>
        )}
        {longEnough && !matches && (
          <span style={{ color: WARN, fontSize: 9, fontFamily: MONO }}>the two entries differ</span>
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Step 3 — the recovery code, shown once, behind a forced acknowledgement.
// ---------------------------------------------------------------------------

// Shown BEFORE the claim is submitted, not after, and the order is a decision.
//
// Show-after risks the page dying between a successful claim and the display,
// which loses the recovery path on a target that now exists — one forgotten
// passphrase from an unreadable archive. Show-before risks the operator saving
// a code for a claim that then fails, which costs them a scrap of paper. The
// second failure is annoying; the first is the exact outcome §4.6 exists to
// prevent.
function RecoveryStep({
  minted,
  busy,
  action,
  onConfirm,
}: {
  minted: MintedArchiveKey;
  busy: boolean;
  action: 'format' | 'adopt' | 'wipe';
  onConfirm: () => void;
}) {
  const [ack, setAck] = useState(false);
  return (
    <>
      <Callout color={WARN} icon={AlertTriangle} title="WRITE THIS DOWN NOW — IT IS NOT SHOWN AGAIN">
        This is the second of the two ways into your archive. It is not stored anywhere you can
        read it back: Rasputin holds only a sealed copy of the key it opens.
      </Callout>

      <div style={{ position: 'relative' }}>
        <pre
          style={{
            margin: 0,
            padding: '14px 12px',
            background: '#060c16',
            border: `1px solid ${accentA(0.4)}`,
            color: ACCENT,
            fontSize: 13,
            fontFamily: MONO,
            letterSpacing: '0.08em',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            textAlign: 'center',
          }}
        >
          {minted.recoveryCode}
        </pre>
        <div style={{ position: 'absolute', top: 4, right: 4 }}>
          <CopyButton value={minted.recoveryCode} ariaLabel="Copy the archive recovery code" />
        </div>
      </div>

      <Hint>
        Dashes and letter case do not matter when you type it back. The alphabet has no I, L, O or
        U in it, so there is no 1/I or 0/O to get wrong.
      </Hint>

      <div style={{ border: `1px solid ${DANGER}`, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <span style={{ color: DANGER, fontSize: 10, fontFamily: MONO, letterSpacing: '0.08em' }}>
          DO NOT STORE THIS ONLY IN VAULTWARDEN
        </span>
        <Hint style={{ color: DANGER }}>
          Vaultwarden runs on this cluster, so its data is inside the archive this code unlocks.
          Storing the code only there means that on the day you need it — the day the cluster is
          gone — the code is gone with it. Print it, write it on paper, or put it in a password
          manager that lives somewhere else.
        </Hint>
      </div>

      <Hint warn>
        Losing either custody path is survivable; losing both is not.
      </Hint>

      <Check
        id="recovery-ack"
        checked={ack}
        onChange={setAck}
        label="I have saved this recovery code somewhere outside this cluster"
      />

      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <Btn variant={action === 'wipe' ? 'danger' : 'primary'} disabled={busy || !ack} onClick={onConfirm}>
          {busy ? 'SUBMITTING…' : action === 'wipe' ? 'DESTROY AND CLAIM' : action === 'format' ? 'FORMAT AND CLAIM' : 'CLAIM'}
        </Btn>
      </div>
    </>
  );
}

function DoneStep({ job, action, encrypted }: { job: Job; action: 'format' | 'adopt' | 'wipe'; encrypted: boolean }) {
  return (
    <>
      <Callout color={OK_GREEN} icon={Database} title="CLAIM SUBMITTED">
        Job <Tok>{job.id}</Tok> is running.{' '}
        {action === 'adopt'
          ? 'The disk is being taken over as it stands.'
          : 'The disk is being formatted and claimed.'}{' '}
        Every refusal §4.8 defines is checked inside that job, in order, before anything is
        written — including a re-check that this is still the same disk you confirmed.
      </Callout>
      {encrypted && (
        <Hint>
          The wrapped key was submitted with the claim. If the job fails, the target is not
          created and the recovery code you saved belongs to nothing — start again and you will be
          given a new one.
        </Hint>
      )}
      <Hint>Watch it in Tasks.</Hint>
    </>
  );
}

// ---------------------------------------------------------------------------

function Callout({
  color,
  icon: Icon,
  title,
  children,
}: {
  color: string;
  icon: React.ElementType;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ border: `1px solid ${color}`, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon size={13} color={color} />
        <span style={{ color, fontSize: 10, fontFamily: MONO, letterSpacing: '0.08em' }}>{title}</span>
      </div>
      <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.7, margin: 0 }}>{children}</p>
    </div>
  );
}

function Check({
  id,
  checked,
  onChange,
  label,
}: {
  id: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <label
      htmlFor={id}
      style={{
        display: 'inline-flex',
        alignItems: 'flex-start',
        gap: 8,
        color: DIM,
        fontSize: 10,
        fontFamily: MONO,
        lineHeight: 1.6,
        cursor: 'pointer',
      }}
    >
      {/* aria-label as well as the visible text: the label's content is a
          `label` PROP, so a static analyser (and any tool walking the tree
          before render) sees a checkbox with no name. */}
      <input
        id={id}
        type="checkbox"
        aria-label={label}
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        style={{ accentColor: ACCENT, marginTop: 2 }}
      />
      {label}
    </label>
  );
}
