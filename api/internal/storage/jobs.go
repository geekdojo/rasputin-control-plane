package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ClaimJobKind is the workflow kind operators submit to claim a backup target.
const ClaimJobKind = "backup.target.claim"

// Step timeouts. Each is the AGENT's work budget from proto plus enough slack
// for the round trip and the marshal — the api must outwait the agent, or it
// gives up on a handler that is about to answer correctly. The claim budget is
// fifteen minutes because the step is wipefs + sfdisk + mkfs + a udev settle on
// a disk that may be a spinning 8 TB archive drive.
const (
	validateStepTimeout  = 10 * time.Second
	enumerateStepTimeout = proto.StorageEnumerateWork + rpcSlack
	claimStepTimeout     = proto.StorageClaimWork + 90*time.Second
	persistStepTimeout   = 15 * time.Second
)

// Config is the environment the saga runs in.
type Config struct {
	// ClusterID is stamped into the on-disk marker so a disk can say which
	// cluster wrote it — the difference, on a replacement controlplane, between
	// a blank disk and the only copy of the archive being restored. Empty off a
	// provisioned appliance; the marker then simply carries no cluster.
	ClusterID string
}

// ClaimWorkflow returns the five-step backup.target.claim saga.
//
//	1 validate       api    spec sanity; an existing claimed target and no
//	                        `replace`
//	2 enumerate      agent  the disk is present, unprotected, and the one the
//	                        operator confirmed
//	3 check_existing api    adopt-or-wipe-or-refuse for a disk already carrying
//	                        a Rasputin backup set (§4.8's restore guard)
//	4 claim          agent  THE DESTRUCTIVE STEP — Irreversible, never retried,
//	                        the last agent step
//	5 persist_target api    record partUUID, node, mount path, wrapped keys
//
// The order is the safety property. jobs.Runner has no compensation: a step's
// failure leaves every prior step exactly as it ran, so every refusal has to
// come BEFORE the irreversible act rather than after it. By step 4 there is
// nothing left to ask that the api could answer — only what the agent can
// refuse against live hardware, which it re-checks itself.
func ClaimWorkflow(store *Store, inv *inventory.Store, cfg Config) jobs.Workflow {
	return jobs.Workflow{
		Kind: ClaimJobKind,
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: validateStepTimeout, Do: claimValidate(store, inv)},
			{Name: "enumerate", Timeout: enumerateStepTimeout, Retries: 1, Do: claimEnumerate()},
			{Name: "check_existing", Timeout: enumerateStepTimeout, Retries: 1, Do: claimCheckExisting()},
			// Irreversible: a mkfs cannot be undone by a saga that has no
			// compensation, so the runner refuses to retry it and refuses to
			// re-run it for a job whose ledger already records an attempt.
			// Declared unconditionally even though the ADOPT branch only reads:
			// the declaration describes what the step MAY do, and a flag cannot
			// make a static declaration conditional.
			{Name: "claim", Timeout: claimStepTimeout, Retries: 0, Irreversible: true, Do: claimClaim(cfg)},
			{Name: "persist_target", Timeout: persistStepTimeout, Retries: 1, Do: claimPersist(store)},
		},
		OnTerminal: finalizeTargetRow(store),
	}
}

// ----- Step results -------------------------------------------------------
//
// Each step's result is a typed struct rather than a raw ack, so the next step
// reads a shape this package defined instead of re-deriving one. None of these
// carries key material: KeyID is an identifier, and the wrapped blobs live in
// the spec and go straight to the store without passing through a step result.

// enumerateResult is what step 2 proved. The device path here is the one the
// disk has NOW, resolved from the fingerprint — not the one the operator saw.
type enumerateResult struct {
	NodeID      string `json:"nodeId"`
	DevicePath  string `json:"devicePath"`
	Fingerprint string `json:"fingerprint"`
	Model       string `json:"model,omitempty"`
	Serial      string `json:"serial,omitempty"`
	// WWN is carried so step 3 can re-derive the wipe confirmation token from
	// the SAME stable identity the picker minted it over. Without it the token
	// would have to be computed once and passed along, and a token that travels
	// with the plan is no longer a re-check against live hardware.
	WWN       string `json:"wwn,omitempty"`
	SizeBytes uint64 `json:"sizeBytes,omitempty"`
	Moved     bool   `json:"moved,omitempty"`
	// HasBackupSet and BackupSet are carried forward so step 3 decides from the
	// evidence step 2 already gathered rather than paying a second enumeration.
	HasBackupSet bool                    `json:"hasBackupSet"`
	BackupSet    *proto.StorageBackupSet `json:"backupSet,omitempty"`
	Backend      string                  `json:"backend,omitempty"`
}

// claimPlan is step 3's verdict and the ONLY input step 4 acts on.
type claimPlan struct {
	NodeID      string `json:"nodeId"`
	DevicePath  string `json:"devicePath"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
	// Adopt selects the non-destructive branch: the disk already carries a
	// Rasputin backup set and the operator chose to take it over as it stands.
	Adopt bool `json:"adopt"`
	// Wipe records that the disk carried a Rasputin backup set and the operator
	// made §4.8's second, separate choice to destroy it.
	//
	// It selects NO different behaviour at step 4 — a wipe formats through the
	// same command, the same subject and the same Irreversible step as any other
	// format, which is exactly why no agent-side safety check can be bypassed by
	// it. It exists so the log line, the ledger and the Tasks view can say what
	// was destroyed.
	Wipe bool `json:"wipe"`
	// WipedSet is the human description of what the wipe destroys, captured at
	// the moment it was still readable.
	WipedSet string `json:"wipedSet,omitempty"`
	// ExistingPartUUID is the marker's own partition UUID, on the adopt branch.
	// It is how the disk gets re-adopted by its own account after a claim that
	// formatted it but never got as far as recording it.
	ExistingPartUUID string `json:"existingPartUuid,omitempty"`
	// ExistingKeyID is the §4.6 key the disk's generations are already under.
	// An identifier, never key material.
	ExistingKeyID string `json:"existingKeyId,omitempty"`
}

// claimOutcome is step 4's result, in one shape for both branches so step 5
// does not have to know which one ran.
type claimOutcome struct {
	Adopted bool `json:"adopted"`
	// Wiped is true when the format destroyed an existing Rasputin backup set.
	Wiped       bool   `json:"wiped"`
	PartUUID    string `json:"partUuid"`
	DevicePath  string `json:"devicePath,omitempty"`
	MountPath   string `json:"mountPath,omitempty"`
	FSType      string `json:"fsType,omitempty"`
	SizeBytes   uint64 `json:"sizeBytes,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyID       string `json:"keyId,omitempty"`
}

// ----- Step 1: validate ---------------------------------------------------

func claimValidate(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := ParseClaimSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		node, err := inv.Get(sc.Ctx, spec.NodeID)
		if err != nil {
			return nil, fmt.Errorf("inventory: %w", err)
		}
		if node == nil {
			return nil, fmt.Errorf("node %s is not registered", spec.NodeID)
		}
		claimed, err := store.ListClaimed(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("existing targets: %w", err)
		}
		if len(claimed) > 0 && !spec.Replace {
			cur := claimed[0]
			return nil, fmt.Errorf("this cluster already has a claimed backup target (%s on %s, partUuid %s) — confirm `replace` to supersede it. The existing disk is not touched either way",
				displayLabel(cur.Label), cur.NodeID, cur.PartUUID)
		}
		now := time.Now().UTC()
		if err := store.CreatePending(sc.Ctx, sc.JobID, spec.NodeID, spec.DevicePath, spec.Label, now); err != nil {
			return nil, fmt.Errorf("record claim attempt: %w", err)
		}
		// Deliberately says what will happen, in the operator's words, on the
		// live event stream. Nothing here is key material: a node, a path the
		// disk had a moment ago, a truncated fingerprint and a label.
		sc.Log("info", fmt.Sprintf("claiming backup target %s on %s (fingerprint %s)%s",
			spec.DevicePath, spec.NodeID, short(spec.Fingerprint), choiceSuffix(spec)))
		return json.Marshal(map[string]any{
			"nodeId":     spec.NodeID,
			"devicePath": spec.DevicePath,
			"replace":    spec.Replace,
			"adopt":      spec.Adopt,
			// WHETHER a wipe was chosen, never the confirmation token itself.
			// The token is evidence the caller looked at the disk; echoing it
			// into a step result that the Tasks view renders would turn a
			// refused claim into a how-to for the next one.
			"wipe": spec.Wipe != nil,
			// Reports only WHETHER key material was supplied. The blobs
			// themselves never enter a step result.
			"archiveKeySupplied": spec.ArchiveKey.present(),
		})
	}
}

// ----- Step 2: enumerate --------------------------------------------------

func claimEnumerate() jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := ParseClaimSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		ack, err := Enumerate(sc.Ctx, sc.NATS, spec.NodeID)
		if err != nil {
			return nil, err
		}
		cand, err := findCandidate(ack, spec)
		if err != nil {
			return nil, err
		}
		if cand.Protected {
			reason := cand.ProtectedReason
			if reason == "" {
				reason = "it holds the currently-mounted boot or persistent partitions"
			}
			return nil, fmt.Errorf("refusing to claim %s [%s]: %s",
				cand.DevicePath, proto.StorageRefusalProtected, reason)
		}
		res := enumerateResult{
			NodeID:       spec.NodeID,
			DevicePath:   cand.DevicePath,
			Fingerprint:  cand.Fingerprint,
			Model:        cand.Model,
			Serial:       cand.Serial,
			WWN:          cand.WWN,
			SizeBytes:    cand.SizeBytes,
			Moved:        cand.DevicePath != spec.DevicePath,
			HasBackupSet: cand.HasBackupSet,
			BackupSet:    cand.BackupSet,
			Backend:      ack.Backend,
		}
		if res.Moved {
			// Worth saying out loud: this is the case a device-path-keyed
			// design gets wrong, and an operator watching the log should see
			// that the fingerprint did its job rather than wonder why the path
			// changed.
			sc.Log("info", fmt.Sprintf("the confirmed disk is now at %s (it was %s at confirmation) — matched by fingerprint",
				cand.DevicePath, spec.DevicePath))
		}
		sc.Log("info", fmt.Sprintf("verified %s: %s %s, %d bytes, backend=%s",
			cand.DevicePath, displayLabel(cand.Model), cand.Transport, cand.SizeBytes, ack.Backend))
		return json.Marshal(res)
	}
}

// ----- Step 3: check_existing ---------------------------------------------

// claimCheckExisting is §4.8's restore guard, and it is the api's decision, not
// the agent's. The agent reports HasBackupSet / BackupSet and obeys;
// proto.StorageRefusalBackupSetPresent is defined for THIS step and the agent
// never emits it.
//
// The refusal exists because restore-before-first-boot (#291) has the operator
// plug their archive disk into a REPLACEMENT controlplane. A flow that formats
// whatever it is handed destroys the only copy of the thing being restored, and
// it does so on the one day the archive was ever going to matter.
//
// A disk carrying a set therefore has exactly three outcomes here, and by
// default it has the first:
//
//	neither choice  refuse   — the disk is untouched and the operator is told why
//	adopt           keep     — take the set over as it stands, format nothing
//	wipe + token    destroy  — §4.8's "or wiped only on a second, separate choice"
//
// The wipe branch is a REFUSAL like the other two until its token matches the
// disk as it is NOW. Nothing about it reaches the agent: it selects the same
// format the ordinary blank-disk path already runs, so the agent's boot-device
// exclusion and fingerprint re-check apply to it unchanged.
func claimCheckExisting() jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := ParseClaimSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		res, err := priorEnumerate(sc, spec)
		if err != nil {
			return nil, err
		}
		plan := claimPlan{
			NodeID:      res.NodeID,
			DevicePath:  res.DevicePath,
			Fingerprint: res.Fingerprint,
			Label:       spec.Label,
		}

		if !res.HasBackupSet {
			// Both choices exist only to answer "what about the set already on
			// this disk?". A disk that carries none answers neither, and the
			// operator was therefore looking at something other than this disk.
			// Refusing costs a re-run; proceeding formats a disk on the strength
			// of a stale prompt.
			switch {
			case spec.Adopt:
				return nil, fmt.Errorf("refusing to adopt %s: it carries no Rasputin backup set. `adopt` takes over an EXISTING set — re-run the picker and choose again",
					res.DevicePath)
			case spec.Wipe != nil:
				return nil, fmt.Errorf("refusing to wipe %s: it carries no Rasputin backup set. `wipe` destroys an EXISTING set, and an ordinary claim already formats a blank disk — re-run the picker and choose again",
					res.DevicePath)
			}
			sc.Log("info", fmt.Sprintf("%s carries no Rasputin backup set — it will be formatted", res.DevicePath))
			return json.Marshal(plan)
		}

		set := res.BackupSet

		// §4.8's second, separate choice. Checked before the blanket refusal
		// below because a wipe is not an adopt, and it is deliberately checked
		// against a token re-derived from THIS enumeration — the disk as it is
		// now, not as the picker saw it.
		if spec.Wipe != nil {
			expected := WipeToken(res.Fingerprint, res.WWN, res.Serial, res.SizeBytes, set)
			if !wipeTokenMatches(spec.Wipe.Token, expected) {
				// Deliberately does NOT print the expected token. A refusal is
				// not a how-to: the fix is to look at the disk again, which is
				// the whole point of requiring the confirmation.
				return nil, fmt.Errorf("refusing to wipe %s [%s]: the wipe confirmation does not match this disk as it is NOW — %s. Either the token was not the one the picker published for this disk, or what the disk holds changed since. Nothing was written. Re-run the picker, look at what is on it, and confirm again",
					res.DevicePath, proto.StorageRefusalBackupSetPresent, describeBackupSet(set))
			}
			plan.Wipe = true
			plan.WipedSet = describeBackupSet(set)
			// The loudest line the saga writes, and it is written BEFORE the
			// destructive step rather than after it, so an operator watching the
			// live stream sees what is about to be destroyed while the format is
			// still a step away.
			sc.Log("warn", fmt.Sprintf("WIPING the existing backup set on %s — %s. Confirmed; it will be destroyed and cannot be recovered",
				res.DevicePath, plan.WipedSet))
			return json.Marshal(plan)
		}

		if !spec.Adopt {
			return nil, fmt.Errorf("refusing to claim %s [%s]: %s. Nothing was written. Choose `adopt` to take this set over as it stands, `wipe` with the confirmation token the picker publishes for this disk to destroy it and claim the disk fresh, or pick a different disk",
				res.DevicePath, proto.StorageRefusalBackupSetPresent, describeBackupSet(set))
		}
		// Adopting requires something to adopt BY. A disk that announces a
		// backup set whose marker could not be read has no partition UUID to be
		// taken over by, so it cannot be adopted — but it is no longer a dead
		// end, because it is exactly the disk `wipe` exists to reclaim, and the
		// picker mints a token for it like any other.
		if set == nil || set.PartUUID == "" {
			return nil, fmt.Errorf("refusing to adopt %s [%s]: it announces a Rasputin backup set but its marker (%s) is unreadable or carries no partition UUID, so there is nothing to adopt it BY. To reclaim this disk, choose `wipe` with the confirmation token the picker publishes for it — that destroys what is on it and claims it fresh",
				res.DevicePath, proto.StorageRefusalBackupSetPresent, proto.StorageMarkerFile)
		}
		// §4.6: the generations already on this disk are encrypted under the
		// key the marker names. Recording a DIFFERENT key against them would
		// leave an archive that reads as decryptable and is not — discovered,
		// as always, on the day it was needed.
		if k := spec.ArchiveKey; k.present() && set.KeyID != "" && k.KeyID != set.KeyID {
			return nil, fmt.Errorf("refusing to adopt %s: its generations are encrypted under key %s, and the claim supplies key %s. Supply the wrapped blobs for the disk's own key, or pick a different disk",
				res.DevicePath, set.KeyID, k.KeyID)
		}
		plan.Adopt = true
		plan.ExistingPartUUID = set.PartUUID
		plan.ExistingKeyID = set.KeyID
		sc.Log("info", fmt.Sprintf("adopting the existing backup set on %s (partUuid %s) — nothing on it will be formatted; %s",
			res.DevicePath, set.PartUUID, describeBackupSet(set)))
		return json.Marshal(plan)
	}
}

// priorEnumerate reads step 2's verdict, falling back to a fresh enumeration
// when it is absent (a renamed step, or a check run out of band).
//
// The fallback is safe HERE and would not be at step 4: this step only reads.
func priorEnumerate(sc *jobs.StepCtx, spec *ClaimSpec) (*enumerateResult, error) {
	if raw, ok := sc.PriorResults["enumerate"]; ok && len(raw) > 0 {
		var res enumerateResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("decode cached enumerate result: %w", err)
		}
		if res.DevicePath != "" {
			return &res, nil
		}
	}
	sc.Log("warn", "enumerate result not cached; re-issuing the read-only RPC")
	ack, err := Enumerate(sc.Ctx, sc.NATS, spec.NodeID)
	if err != nil {
		return nil, err
	}
	cand, err := findCandidate(ack, spec)
	if err != nil {
		return nil, err
	}
	if cand.Protected {
		return nil, fmt.Errorf("refusing to claim %s [%s]: %s",
			cand.DevicePath, proto.StorageRefusalProtected, cand.ProtectedReason)
	}
	return &enumerateResult{
		NodeID: spec.NodeID, DevicePath: cand.DevicePath, Fingerprint: cand.Fingerprint,
		Model: cand.Model, Serial: cand.Serial, WWN: cand.WWN, SizeBytes: cand.SizeBytes,
		HasBackupSet: cand.HasBackupSet, BackupSet: cand.BackupSet, Backend: ack.Backend,
	}, nil
}

// ----- Step 4: claim ------------------------------------------------------

// claimClaim is the destructive step, and the last agent step in the saga.
//
// It acts ONLY on step 3's plan. There is deliberately no fallback that
// re-derives the plan from the spec the way step 3 re-derives an enumeration:
// re-deriving is how a step ends up formatting a disk on the strength of
// evidence nothing checked. A missing plan fails the job with nothing written.
func claimClaim(cfg Config) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := ParseClaimSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		raw, ok := sc.PriorResults["check_existing"]
		if !ok || len(raw) == 0 {
			return nil, errors.New("refusing to claim: step check_existing left no plan, so nothing has verified this disk. A destructive step does not reconstruct its own authorization")
		}
		var plan claimPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			return nil, fmt.Errorf("refusing to claim: unreadable plan from check_existing: %w", err)
		}
		if plan.DevicePath == "" || plan.Fingerprint == "" {
			return nil, errors.New("refusing to claim: the plan from check_existing names no disk or no fingerprint")
		}

		if plan.Adopt {
			return adoptExisting(sc, &plan)
		}

		keyID := ""
		if spec.ArchiveKey.present() {
			keyID = spec.ArchiveKey.KeyID
		}
		cmd, err := json.Marshal(proto.StorageClaimCmd{
			DevicePath:  plan.DevicePath,
			Fingerprint: plan.Fingerprint,
			Label:       plan.Label,
			ClusterID:   cfg.ClusterID,
			// An identifier. The §4.6 data key itself never crosses this wire,
			// and there is no field on StorageClaimCmd that could carry it.
			KeyID: keyID,
		})
		if err != nil {
			return nil, err
		}
		// One command, one subject, one Irreversible step, whether the disk was
		// blank or carried a set the operator chose to destroy. The wipe changes
		// only what this line SAYS: there is no wipe flag on StorageClaimCmd, so
		// there is no agent-side branch a wipe could take around the boot-device
		// exclusion or the fingerprint re-check the agent runs before it writes.
		if plan.Wipe {
			sc.Log("warn", fmt.Sprintf("WIPING %s on %s — this destroys the Rasputin backup set it carries (%s) and everything else on that disk",
				plan.DevicePath, plan.NodeID, plan.WipedSet))
		} else {
			sc.Log("warn", fmt.Sprintf("FORMATTING %s on %s — this destroys everything on that disk",
				plan.DevicePath, plan.NodeID))
		}
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.StorageClaimSubject(plan.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("claim rpc to %s: %w", plan.NodeID, err)
		}
		var ack proto.StorageClaimAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("claim: unreadable reply from %s: %w", plan.NodeID, err)
		}
		if !ack.OK {
			return nil, refusalError("claim of "+plan.DevicePath, ack.Refusal, ack.Detail)
		}
		if ack.PartUUID == "" {
			// The partition UUID is the target's identity. An ack without one
			// describes a disk nothing can find again, and recording it would
			// produce a target that silently fails at the first mount.
			return nil, fmt.Errorf("claim of %s reported success with no partition UUID — that is the only identifier a target has, so there is nothing to record",
				plan.DevicePath)
		}
		// The returned fingerprint DIFFERS from the one sent, by construction:
		// the partition table it hashes is what was just replaced. That is what
		// makes a replayed claim fail closed. It is recorded as the target's new
		// fingerprint and is never read as drift.
		out := claimOutcome{
			Wiped:       plan.Wipe,
			PartUUID:    ack.PartUUID,
			DevicePath:  firstNonEmpty(ack.DevicePath, plan.DevicePath),
			MountPath:   ack.MountPath,
			FSType:      ack.FSType,
			SizeBytes:   ack.SizeBytes,
			Fingerprint: ack.Fingerprint,
			KeyID:       keyID,
		}
		verb := "claimed"
		if plan.Wipe {
			verb = "wiped and claimed"
		}
		sc.Log("info", fmt.Sprintf("%s %s: partUuid=%s fs=%s mount=%s",
			verb, out.DevicePath, out.PartUUID, out.FSType, out.MountPath))
		return json.Marshal(out)
	}
}

// adoptExisting is the non-destructive branch: the disk already carries a
// Rasputin backup set and the operator chose to take it over as it stands.
//
// It uses inspect rather than claim, and that is the entire difference between
// "recover the target that a failed persist orphaned" and "wipe the archive
// somebody plugged in to restore from". Inspect mounts if needed and reads; it
// writes nothing.
func adoptExisting(sc *jobs.StepCtx, plan *claimPlan) (json.RawMessage, error) {
	cmd, err := json.Marshal(proto.StorageInspectCmd{PartUUID: plan.ExistingPartUUID})
	if err != nil {
		return nil, err
	}
	msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.StorageInspectSubject(plan.NodeID), cmd)
	if err != nil {
		return nil, fmt.Errorf("inspect rpc to %s: %w", plan.NodeID, err)
	}
	var ack proto.StorageInspectAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return nil, fmt.Errorf("inspect: unreadable reply from %s: %w", plan.NodeID, err)
	}
	if !ack.OK {
		return nil, refusalError("adopt of "+plan.DevicePath, ack.Refusal, ack.Detail)
	}
	if !ack.Present {
		return nil, fmt.Errorf("refusing to adopt %s [%s]: nothing with partition UUID %s is attached any more",
			plan.DevicePath, proto.StorageRefusalNotFound, plan.ExistingPartUUID)
	}
	keyID := plan.ExistingKeyID
	if ack.BackupSet != nil && ack.BackupSet.KeyID != "" {
		keyID = ack.BackupSet.KeyID
	}
	out := claimOutcome{
		Adopted:    true,
		PartUUID:   plan.ExistingPartUUID,
		DevicePath: firstNonEmpty(ack.DevicePath, plan.DevicePath),
		MountPath:  ack.MountPath,
		FSType:     ack.FSType,
		SizeBytes:  ack.TotalBytes,
		KeyID:      keyID,
	}
	sc.Log("info", fmt.Sprintf("adopted %s: partUuid=%s fs=%s mount=%s (nothing was formatted)",
		out.DevicePath, out.PartUUID, out.FSType, out.MountPath))
	return json.Marshal(out)
}

// ----- Step 5: persist_target ---------------------------------------------

func claimPersist(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := ParseClaimSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		raw, ok := sc.PriorResults["claim"]
		if !ok || len(raw) == 0 {
			return nil, errors.New("no claim result to persist")
		}
		var out claimOutcome
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("decode claim result: %w", err)
		}
		if out.PartUUID == "" {
			return nil, errors.New("claim result carries no partition UUID")
		}

		// This step's one retry has to be safe, and the disk is already
		// formatted by the time it runs — so a second attempt must recognise
		// its own first attempt rather than fail forever on the status guard.
		if row, err := store.GetByJob(sc.Ctx, sc.JobID); err == nil && row != nil &&
			row.Status == TargetClaimed && row.PartUUID == out.PartUUID {
			return json.Marshal(row)
		}

		res := ClaimResult{
			PartUUID:    out.PartUUID,
			DevicePath:  out.DevicePath,
			MountPath:   out.MountPath,
			FSType:      out.FSType,
			SizeBytes:   out.SizeBytes,
			Fingerprint: out.Fingerprint,
			Adopted:     out.Adopted,
			Wiped:       out.Wiped,
			// The wrapped blobs come from the SPEC and go straight to the
			// store. They are the only §4.6 material this package touches, they
			// are ciphertext, and they never pass through a step result, a log
			// line or an event payload on the way.
			Key: spec.ArchiveKey,
			At:  time.Now().UTC(),
		}
		if out.Adopted && out.KeyID != "" {
			// The disk's own marker is the authority on which key its existing
			// generations are under.
			res.KeyIDOverride = out.KeyID
		}
		if err := store.MarkClaimed(sc.Ctx, sc.JobID, res); err != nil {
			return nil, fmt.Errorf("persist target: %w", err)
		}

		if spec.Replace {
			supersedePriorTargets(sc, store)
		}
		row, err := store.GetByJob(sc.Ctx, sc.JobID)
		if err != nil || row == nil {
			return nil, fmt.Errorf("target recorded but could not be read back: %v", err)
		}
		sc.Log("info", fmt.Sprintf("backup target recorded: partUuid=%s node=%s mount=%s",
			row.PartUUID, row.NodeID, row.MountPath))
		return json.Marshal(row)
	}
}

// supersedePriorTargets marks every OTHER claimed target replaced, after the
// new one is safely recorded. Ordering matters: a failure here leaves two
// claimed rows, which an operator can see and fix; the reverse order would
// leave a window with none.
//
// Never deletes. The superseded disk may be sitting on a shelf holding the only
// copy of an archive, and this row is where an operator finds out it exists.
func supersedePriorTargets(sc *jobs.StepCtx, store *Store) {
	claimed, err := store.ListClaimed(sc.Ctx)
	if err != nil {
		log.Printf("storage: list claimed targets for supersede: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, c := range claimed {
		if c.JobID == sc.JobID {
			continue
		}
		if err := store.MarkReplaced(sc.Ctx, c.JobID, now); err != nil {
			log.Printf("storage: supersede target %s: %v", c.JobID, err)
			continue
		}
		sc.Log("info", fmt.Sprintf("superseded the previous backup target %s on %s — the disk itself is untouched and still holds its archive",
			c.PartUUID, c.NodeID))
	}
}

// ----- OnTerminal ---------------------------------------------------------

// finalizeTargetRow gives the backup_targets row a terminal status on EVERY
// path the job can end on (ADR-0005 Decision 5, and the #53 lesson).
//
// Without it, a saga that failed at enumerate or check_existing propagates its
// error to the runner, which fails the JOB and never touches the row — so the
// Backup view renders a refused claim as one still running, indefinitely. That
// is exactly the shape #53 recorded for node_updates, reproduced on the bench
// on 2026-08-12, and there is no reason this table would have been luckier.
//
// Only ever writes to a row still pending. That guard is what makes the hook
// safe to fire on success too: a `claimed` row is a verdict step 5 recorded,
// and this hook has no business overwriting it.
func finalizeTargetRow(store *Store) func(context.Context, string, bool, string) {
	return func(ctx context.Context, jobID string, success bool, errMsg string) {
		row, err := store.GetByJob(ctx, jobID)
		if err != nil || row == nil {
			return // not a claim job, or the row was never created
		}
		if row.Status != TargetPending {
			return // already has a verdict
		}
		if errMsg == "" {
			// A job that succeeded with its row still pending means a step
			// ended the saga without recording an outcome. Say so rather than
			// inventing a target that does not exist.
			errMsg = "job ended without recording a backup target"
		}
		if err := store.MarkFailed(ctx, jobID, errMsg, time.Now().UTC()); err != nil {
			log.Printf("storage: finalize backup target %s: %v", jobID, err)
			return
		}
		log.Printf("storage: backup target row %s finalized as failed (%s)", jobID, errMsg)
	}
}

// ReconcileStrandedRows finalizes pending rows whose job is already terminal.
// Called once at api start.
//
// The hook above closes the path going forward but cannot reach back: a row
// stranded by a process that died between failing the job and firing the hook
// has no later event to catch it. Decides only from a job that has ALREADY
// reached a terminal state, never from a clock — a claim legitimately takes
// fifteen minutes, and a timeout reaper would fail live ones.
func ReconcileStrandedRows(ctx context.Context, store *Store, jobStore *jobs.Store) error {
	rows, err := store.ListPending(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		j, err := jobStore.GetJob(ctx, row.JobID)
		if err != nil || j == nil {
			continue
		}
		if j.Status != jobs.StatusFailed && j.Status != jobs.StatusSucceeded {
			continue // still genuinely running
		}
		msg := j.Error
		if msg == "" {
			msg = "job reached a terminal state without recording a backup target"
		}
		if err := store.MarkFailed(ctx, row.JobID, msg, time.Now().UTC()); err != nil {
			log.Printf("storage: reconcile stranded %s: %v", row.JobID, err)
			continue
		}
		log.Printf("storage: reconciled stranded backup target %s (job already %s)", row.JobID, j.Status)
	}
	return nil
}

// ----- helpers ------------------------------------------------------------

func describeBackupSet(set *proto.StorageBackupSet) string {
	if set == nil {
		return "its marker could not be read"
	}
	who := "this cluster"
	if set.ClusterID != "" {
		who = "cluster " + set.ClusterID
	}
	gens := "an unknown number of"
	if set.Generations > 0 {
		gens = fmt.Sprintf("%d", set.Generations)
	}
	label := ""
	if set.Label != "" {
		label = fmt.Sprintf(" labelled %q,", set.Label)
	}
	return fmt.Sprintf("it carries a Rasputin backup set written by %s,%s holding %s retained generation(s)", who, label, gens)
}

// choiceSuffix says, on the live event stream and in the operator's words, which
// of §4.8's two answers about an existing backup set this claim carries.
func choiceSuffix(spec *ClaimSpec) string {
	switch {
	case spec.Adopt:
		return " — adopting an existing backup set, nothing will be formatted"
	case spec.Wipe != nil:
		return " — WIPING an existing backup set, which is destroyed"
	}
	return ""
}

func displayLabel(s string) string {
	if s == "" {
		return "(unnamed)"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// short truncates a fingerprint for a log line. Fingerprints are not secrets —
// they are a hash of hardware identity — but a full one is 64 characters of
// noise in a line an operator is trying to read.
func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
