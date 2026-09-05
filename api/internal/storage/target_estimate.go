package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The target-side pre-flight estimate — what a generation is going to put on
// the backup disk, worked out BEFORE the agent is asked whether there is room
// (design/storage.md §4.4, geekdojo-brain#297).
//
// # Why the identity set alone was not an estimate
//
// The archive the api seals is the identity set, and for a while that was the
// whole generation, so its measured size plus a margin was the whole estimate.
// It is not the whole generation any more: every classified app volume lands
// on the SAME disk through the ingest endpoint as its own sealed member beside
// the archive (assemble.go's file comment). On a real cluster the volumes are
// most of the bytes — a Vaultwarden vault is small, an Immich upload tree is
// not — so a check that counted the identity set alone could pass, and the run
// could then fill the target part-way through the fan-out with an app stopped.
// That is the failure §4.4's check exists to refuse.
//
// # Where the volume sizes come from, and what they are when there are none
//
// The one place a volume's size on the target is RECORDED is the manifest of a
// generation that holds it: VolumeRecord.SealedSizeBytes, over the member as
// it sits on the disk. Each run's assemble step keeps the manifest it wrote in
// the job ledger (runAssembleResult.ManifestJSON), so the api can read the
// most recent capture of every volume it is about to take without touching
// the removable disk, mounted or not, before the agent has confirmed it. The
// lookup walks the ledger newest-first and takes the first captured record per
// member — "the most recent generation's manifest that holds it".
//
// A volume no generation has ever held — the first run, or an app installed
// since the last one — has no recorded size, and the estimate does not pretend
// otherwise. It counts a per-class placeholder (proto's
// BackupUnknownVolumeBytes*), and it NAMES the volume it guessed for, in the
// step result, the run row and the log, so a refusal reads "3 volumes counted
// at their class default" rather than as a measurement.
//
// # What this is not
//
// It is a pre-flight, not a reservation: the agent compares the estimate
// against the free space at that moment, and a volume that has grown since its
// last capture, or a first capture larger than the placeholder, can still fill
// the disk. The ingest endpoint's own per-member bound and the agent's staging
// reserve are the guards that catch that; this one stops the predictable case
// — the same-night-every-week refusal §4.4 names — before anything is stopped
// or staged.

// TargetEstimate is the pre-flight arithmetic, kept as a value so the numbers
// go into the step result, the run row and the refusal rather than only into
// one comparison. Sizes and names only; nothing key-shaped can be here.
type TargetEstimate struct {
	// IdentityBytes is the measured §4.5 identity set — the live database plus
	// the trust directory plus Headscale state — as MeasureIdentitySet found it.
	IdentityBytes uint64 `json:"identityBytes"`
	// VolumeBytes is the sum over every volume this run intends to stage:
	// the recorded size where one exists, the class placeholder where none
	// does. Volumes lists each term.
	VolumeBytes uint64 `json:"volumeBytes"`
	// MarginBytes is proto.BackupTargetReserveBytes, echoed so the total
	// explains itself without the reader knowing the constant. The agent adds
	// the same reserve to what it is sent; RequiredBytes in its ack should
	// equal EstimateBytes here.
	MarginBytes uint64 `json:"marginBytes"`
	// EstimateBytes is IdentityBytes + VolumeBytes + MarginBytes, saturating.
	EstimateBytes uint64 `json:"estimateBytes"`
	// Volumes is the per-volume breakdown, in staging order.
	Volumes []VolumeEstimate `json:"volumes,omitempty"`
	// UnknownVolumes names the volumes counted at their class placeholder —
	// "app/volume" — so a refusal can say which of its terms were guesses.
	UnknownVolumes []string `json:"unknownVolumes,omitempty"`
}

// VolumeEstimate is one volume's term in the estimate.
type VolumeEstimate struct {
	App    string `json:"app"`
	Volume string `json:"volume"`
	Class  string `json:"class"`
	Bytes  uint64 `json:"bytes"`
	// Known is true when Bytes is a recorded size from Generation's manifest;
	// false when it is the class placeholder.
	Known      bool   `json:"known"`
	Generation string `json:"generation,omitempty"`
}

// PayloadBytes is what goes on the wire as BackupPreflightCmd.EstimateBytes:
// the identity set plus the volumes, WITHOUT the margin, because the agent adds
// proto.BackupTargetReserveBytes itself and sending it twice would double it.
func (e TargetEstimate) PayloadBytes() uint64 { return satAdd(e.IdentityBytes, e.VolumeBytes) }

// Explain renders the breakdown for a log line or a refusal. Every term, with
// the guessed ones named: "there is not room" is not actionable, and "1.2 GiB
// of app volumes, two of them counted at a default because nothing has ever
// captured them" is.
func (e TargetEstimate) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "The estimate is %s of identity set plus %s of app volumes (%d) plus a %s margin, %s in all",
		humanBytes(e.IdentityBytes), humanBytes(e.VolumeBytes), len(e.Volumes), humanBytes(e.MarginBytes), humanBytes(e.EstimateBytes))
	if len(e.UnknownVolumes) > 0 {
		fmt.Fprintf(&b, "; %d volume(s) have never been captured and were counted at their class default (%s)",
			len(e.UnknownVolumes), strings.Join(e.UnknownVolumes, ", "))
	}
	return b.String()
}

// PriorVolumeSize is a volume's most recently recorded size on the target and
// the generation whose manifest recorded it.
type PriorVolumeSize struct {
	Bytes      uint64
	Generation string
}

// StepLister is the slice of the job ledger the estimate reads: a run's step
// results, so the manifest its assemble step kept can be opened. An interface
// so the estimate is testable without a runner.
type StepLister interface {
	ListSteps(ctx context.Context, jobID string) ([]*jobs.JobStep, error)
}

// priorVolumeScanLimit bounds how many earlier runs the size lookup reads.
// Newest first, and it stops early once every planned volume has a size, so
// on a steady cluster it opens one manifest. The bound matters only for a
// volume that has NOT been captured lately: after this many runs without it,
// its last recorded size is old enough that the class default is the more
// honest term anyway.
const priorVolumeScanLimit = 25

// PriorVolumeSizes reads, for each member in `want`, the size recorded by the
// most recent run that captured it. Members with no recorded size are absent
// from the result. A ledger that cannot be read contributes nothing and says
// so in the log — an estimate does not fail a run over its own inputs; it
// falls back to the placeholders and names them.
func PriorVolumeSizes(ctx context.Context, store *Store, steps StepLister, want map[string]bool) map[string]PriorVolumeSize {
	out := map[string]PriorVolumeSize{}
	if store == nil || steps == nil || len(want) == 0 {
		return out
	}
	runs, err := store.ListRuns(ctx, priorVolumeScanLimit)
	if err != nil {
		log.Printf("storage: prior volume sizes: list runs: %v", err)
		return out
	}
	for _, r := range runs {
		if len(out) == len(want) {
			break
		}
		m, ok := manifestFromLedger(ctx, steps, r.JobID)
		if !ok {
			continue
		}
		for _, v := range m.AppVolumes.Volumes {
			if !v.Captured || v.Member == "" || !want[v.Member] {
				continue
			}
			if _, seen := out[v.Member]; seen {
				continue
			}
			// The sealed size is what sits on the disk. Records from before it
			// was kept have only the plaintext tar's length, which the seal
			// adds a header to — near enough for an estimate, and better
			// than a placeholder.
			size := v.SealedSizeBytes
			if size == 0 {
				size = v.SizeBytes
			}
			if size == 0 {
				continue
			}
			out[v.Member] = PriorVolumeSize{Bytes: size, Generation: m.GenerationID}
		}
	}
	return out
}

// manifestFromLedger opens the manifest a run's assemble step kept, if the run
// got that far.
func manifestFromLedger(ctx context.Context, steps StepLister, jobID string) (Manifest, bool) {
	sts, err := steps.ListSteps(ctx, jobID)
	if err != nil {
		log.Printf("storage: prior volume sizes: steps for %s: %v", jobID, err)
		return Manifest{}, false
	}
	for _, st := range sts {
		if st.Name != "assemble" || st.Status != jobs.StepSucceeded || len(st.Result) == 0 {
			continue
		}
		var asm runAssembleResult
		if err := json.Unmarshal(st.Result, &asm); err != nil || asm.ManifestJSON == "" {
			return Manifest{}, false
		}
		var m Manifest
		if err := json.Unmarshal([]byte(asm.ManifestJSON), &m); err != nil {
			return Manifest{}, false
		}
		return m, true
	}
	return Manifest{}, false
}

// EstimateTargetPayload composes the estimate for one run: the measured
// identity set, each planned volume at its recorded size or its class
// placeholder, and the margin.
func EstimateTargetPayload(identityBytes uint64, plan []PlannedVolume, prior map[string]PriorVolumeSize) TargetEstimate {
	est := TargetEstimate{IdentityBytes: identityBytes, MarginBytes: proto.BackupTargetReserveBytes}
	for _, p := range plan {
		term := VolumeEstimate{App: p.AppName, Volume: p.Volume, Class: p.Class}
		if ps, ok := prior[p.Member()]; ok && ps.Bytes > 0 {
			term.Bytes, term.Known, term.Generation = ps.Bytes, true, ps.Generation
		} else {
			term.Bytes = unknownVolumeBytes(p.Class)
			est.UnknownVolumes = append(est.UnknownVolumes, p.String())
		}
		est.Volumes = append(est.Volumes, term)
		est.VolumeBytes = satAdd(est.VolumeBytes, term.Bytes)
	}
	sort.Strings(est.UnknownVolumes)
	est.EstimateBytes = satAdd(satAdd(est.IdentityBytes, est.VolumeBytes), est.MarginBytes)
	return est
}

// unknownVolumeBytes is the placeholder for a volume of the given class that no
// generation has sized. Only `critical` and `state` are ever planned
// (PlanAppVolumes); anything else that reaches here is counted as `state`,
// the larger of the two, because a class this does not recognise is not a
// reason to count less.
func unknownVolumeBytes(class string) uint64 {
	if class == tileschema.BackupCritical {
		return proto.BackupUnknownVolumeBytesCritical
	}
	return proto.BackupUnknownVolumeBytesState
}

// satAdd adds two sizes, saturating rather than wrapping. A sum that wrapped
// to a small number would be an estimate SMALLER than its parts — a pre-flight
// that passes on a disk with no room, arrived at by arithmetic.
func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return ^uint64(0)
}
