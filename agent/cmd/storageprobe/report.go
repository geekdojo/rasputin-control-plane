package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The reports. Every verb's output is built as DATA here and rendered
// somewhere else, for two reasons that both bit the throwaway this replaces.
//
// The first is that the interesting decisions — which candidates are the
// protected set, whether a claim ack carries enough to be called a success —
// are then table-testable without capturing stdout and matching prose. The
// second is that one report feeds both renderers, so the human text and the
// --json a script parses cannot disagree about what happened.

// fixtureBanner is what a mock run says, on every verb, at the top. Wording
// chosen to be unmissable in an SSH scrollback: an operator on the bench who
// skims past it and reads the disk list as hardware is the whole failure mode.
const fixtureBanner = "MOCK BACKEND — every disk, size, fingerprint and mount below is a FIXTURE, not this machine"

// ---------------------------------------------------------------------------
// enumerate
// ---------------------------------------------------------------------------

// enumerateReport is the read-only disk listing, split by the only distinction
// that matters when you are about to format something.
//
// The protected set is its OWN FIELD rather than a flag on a flat list. That is
// the headline this command exists to print: on a controlplane with two
// identical NVMes there is no model, size, transport or bus difference between
// the boot medium and the spare, so which of them is protected — and the prose
// reason naming the mount that protects it — is the only thing in the entire
// output that tells them apart. A `protected: true` field two levels down a
// JSON array is not that, and neither is a footnote.
type enumerateReport struct {
	Backend  string    `json:"backend"`
	Fixture  bool      `json:"fixture"`
	Observed time.Time `json:"observed"`
	// Protected are the disks Claim will refuse. Reported first and reported
	// whole — proto.Enumerate returns them rather than filtering them, and so
	// does this.
	Protected []proto.StorageCandidate `json:"protected"`
	// Claimable is everything else. "Claimable" means "not in the protected
	// set", never "safe": a disk here may hold the operator's photo archive,
	// which is why the partition table is printed with it.
	Claimable []proto.StorageCandidate `json:"claimable"`
	// Warnings are conditions an operator must read before typing `claim`.
	// Prose, never parsed.
	Warnings []string `json:"warnings,omitempty"`
}

// newEnumerateReport partitions an ack and works out what needs saying about
// it.
func newEnumerateReport(ack *proto.StorageEnumerateAck, sel backendChoice) enumerateReport {
	rep := enumerateReport{Backend: sel.Name, Fixture: sel.Fixture}
	if sel.Fixture {
		rep.Warnings = append(rep.Warnings, fixtureBanner)
	}
	if ack == nil {
		rep.Warnings = append(rep.Warnings, "the backend returned no enumerate ack at all")
		return rep
	}
	rep.Backend, rep.Observed = ack.Backend, ack.Ts
	for _, c := range ack.Candidates {
		if c.Protected {
			rep.Protected = append(rep.Protected, c)
			if strings.TrimSpace(c.ProtectedReason) == "" {
				// The reason is the readout, not decoration. A protected disk
				// with no reason means the derivation ran and produced
				// nothing to say, which is a bug in the thing whose answer an
				// operator is about to trust with a format.
				rep.Warnings = append(rep.Warnings, fmt.Sprintf(
					"%s is protected but names no reason — the reason is the safety readout, and a blank one is a bug, not a clean bill of health", c.DevicePath))
			}
			continue
		}
		rep.Claimable = append(rep.Claimable, c)
	}
	if len(ack.Candidates) > 0 && len(rep.Protected) == 0 {
		// protect.go refuses to resolve an empty protected set — "/" always
		// resolves on a real Linux system — so a real enumerate cannot reach
		// here with nothing protected unless the boot medium is not among the
		// candidates at all (an mmcblk or a virtual device lsblk did not offer
		// as a whole disk). That is worth a stare before formatting anything,
		// because the operator's mental model of "the other one is the spare"
		// no longer has an anchor.
		rep.Warnings = append(rep.Warnings, "NO DISK IN THIS LIST IS PROTECTED — the boot medium is not among the candidates, so nothing here distinguishes it. Do not claim anything until you know why")
	}
	for _, c := range ack.Candidates {
		if c.IdentityWeak {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"%s reports neither WWN nor serial, so its fingerprint rests on model + size + partition table — two identical blank disks from one batch can fingerprint the same", c.DevicePath))
		}
	}
	if !ack.OK {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("the backend answered ok=false (refusal %q): %s", ack.Refusal, ack.Detail))
	}
	return rep
}

// ---------------------------------------------------------------------------
// claim
// ---------------------------------------------------------------------------

// claimReport is a successful claim, expanded into the fields an operator has
// to check on the platter afterwards.
//
// StorageClaimAck does not carry all of them. The GPT partition name, the
// mount options and the marker filename live in proto's per-purpose spec table
// and nowhere else, so they are resolved here from the purpose the agent
// ECHOED BACK on the ack — the purpose it actually claimed the disk for, not
// the one the command asked for. That distinction is the reason Purpose is a
// required field below rather than a defaulted one: this command will not
// resolve a spec from a guess and print the result as ground truth.
type claimReport struct {
	Backend    string `json:"backend"`
	Fixture    bool   `json:"fixture"`
	DevicePath string `json:"devicePath"`
	// PartUUID is the identifier for this target everywhere downstream. The
	// device path is not, and the api persists this one.
	PartUUID string               `json:"partUuid"`
	Purpose  proto.StoragePurpose `json:"purpose"`
	// Label is the operator's human name for the disk, written into the
	// marker. Distinct from FSLabel, which is the purpose's and not theirs.
	Label string `json:"label,omitempty"`
	// GPTName, FSLabel, MountOptions and MarkerPath are the four an operator
	// verifies by hand afterwards — `lsblk -o NAME,PARTLABEL,LABEL`, `mount`,
	// and a `cat` of the marker.
	GPTName      string `json:"gptName"`
	FSLabel      string `json:"fsLabel"`
	FSType       string `json:"fsType,omitempty"`
	MountPath    string `json:"mountPath"`
	MountOptions string `json:"mountOptions"`
	MarkerPath   string `json:"markerPath"`
	SizeBytes    uint64 `json:"sizeBytes,omitempty"`
	// Fingerprint is the POST-format fingerprint, which differs from the one
	// the claim carried because the format rewrote the partition table it
	// hashes. Printed so the difference is visible rather than surprising, and
	// so a later verify has something to compare against.
	Fingerprint string `json:"fingerprint,omitempty"`
	// BackupSet / DataSet are the marker as written. Exactly one is set — a
	// claim formats one filesystem and drops one marker on it.
	BackupSet *proto.StorageBackupSet `json:"backupSet,omitempty"`
	DataSet   *proto.StorageDataSet   `json:"dataSet,omitempty"`
	// MarkerVerified says whether the marker was read back OFF THE MOUNTED
	// FILESYSTEM after the claim, which is §6.3's check applied to this
	// command's own work. Empty for a backup claim, which has no exported
	// verifier — see verifyClaimedMarker.
	MarkerVerified string   `json:"markerVerified,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

// newClaimReport expands a claim ack, and REFUSES to describe it as a success
// when any of the ground truth is missing.
//
// This is the whole reason the claim path goes through a report rather than a
// Printf. "claim OK" with a partUUID the operator cannot see, or a mount path
// the ack did not carry, is a line that reads as proof and is not one — and a
// bench tool's only product is the belief an operator forms from reading it.
// So every missing field is collected and returned together: a run that is
// wrong in three ways should say so once, not three times across three fixes.
func newClaimReport(ack *proto.StorageClaimAck, sel backendChoice) (claimReport, error) {
	if ack == nil {
		return claimReport{}, fmt.Errorf("the backend returned no claim ack")
	}
	if !ack.OK {
		// A refusal that got this far is a backend that answered ok=false
		// without an error. It is not a claim and must not be rendered as one.
		return claimReport{}, fmt.Errorf("the backend answered ok=false (refusal %q): %s", ack.Refusal, ack.Detail)
	}

	rep := claimReport{
		Backend:     sel.Name,
		Fixture:     sel.Fixture,
		DevicePath:  ack.DevicePath,
		PartUUID:    strings.TrimSpace(ack.PartUUID),
		Purpose:     ack.Purpose,
		Label:       ack.Label,
		FSLabel:     strings.TrimSpace(ack.FSLabel),
		FSType:      ack.FSType,
		MountPath:   strings.TrimSpace(ack.MountPath),
		SizeBytes:   ack.SizeBytes,
		Fingerprint: strings.TrimSpace(ack.Fingerprint),
		BackupSet:   ack.BackupSet,
		DataSet:     ack.DataSet,
	}
	if sel.Fixture {
		rep.Warnings = append(rep.Warnings, fixtureBanner)
	}

	var missing []string
	if rep.PartUUID == "" {
		missing = append(missing, "partUuid (the identifier for this target everywhere downstream)")
	}
	if rep.MountPath == "" {
		missing = append(missing, "mountPath")
	}
	if rep.FSLabel == "" {
		missing = append(missing, "fsLabel")
	}

	// The purpose is required BEFORE the spec lookup, because the spec is what
	// supplies the other three fields. StorageClaimAck.Purpose is documented
	// as resolved — a claim that sent none comes back saying "backup" — so an
	// empty one here is an agent that did not answer the question, and
	// applying the wire default ourselves would be this command inventing the
	// answer it was sent to report.
	if strings.TrimSpace(string(rep.Purpose)) == "" {
		missing = append(missing, "purpose (the ack echoes the purpose the agent RESOLVED; empty means it did not, and the GPT name, mount options and marker file all follow from it)")
	} else if spec, err := proto.StoragePurposeSpecFor(rep.Purpose); err != nil {
		missing = append(missing, fmt.Sprintf("a resolvable purpose (%v)", err))
	} else {
		rep.GPTName = spec.PartName
		rep.MountOptions = spec.MountOptions
		rep.MarkerPath = filepath.Join(rep.MountPath, spec.MarkerFile)
		if rep.FSLabel != "" && rep.FSLabel != spec.FSLabel {
			// Both values are known, so both are printed rather than one
			// being picked. A disagreement means the backend labelled the
			// filesystem with something the spec table does not name for this
			// purpose, which is a drift between the two backends or between a
			// backend and proto — exactly the thing this table exists to stop.
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"the filesystem is labelled %q but proto's spec table says a %q claim is labelled %q — the backend and the table disagree",
				rep.FSLabel, rep.Purpose, spec.FSLabel))
		}
	}
	if len(missing) > 0 {
		return claimReport{}, fmt.Errorf(
			"the claim ack is missing ground truth an operator must be able to check, so this run will NOT be reported as a success: %s",
			strings.Join(missing, "; "))
	}

	if rep.Fingerprint == "" {
		// Not fatal: nothing downstream needs it to use the disk. Worth
		// saying, because it is what a later verify compares against and its
		// absence is only noticed when that verify has nothing to do.
		rep.Warnings = append(rep.Warnings, "no post-format fingerprint on the ack — a later verify has nothing to compare against")
	}
	if rep.FSType == "" {
		rep.Warnings = append(rep.Warnings, "no fsType on the ack")
	}
	if rep.BackupSet == nil && rep.DataSet == nil {
		rep.Warnings = append(rep.Warnings, "the ack carries neither a backup set nor a data set — the marker was written to the platter but not reported back")
	}
	return rep, nil
}

// verifyClaimedMarker reads the marker back off the mounted filesystem and
// says what it found, which is §6.3's check turned on this command's own
// output: a claim that reported a mount path is not proof that the thing at
// that path is the disk.
//
// It runs for the DATA purpose only, and that is a limit of what the package
// exports rather than a judgement about backup targets — VerifyDataMarker is
// the §6.3 check and there is no exported counterpart for
// .rasputin-backup-set.json. Rather than reimplement one here (a second reader
// of a file format whose only other reader is the backend, which is how two
// answers to one question start), a backup claim reports the marker path and
// leaves the reading to the operator's `cat`.
func verifyClaimedMarker(rep *claimReport) {
	if rep.Purpose != proto.StoragePurposeData {
		return
	}
	set, err := storage.VerifyDataMarker(rep.MountPath, rep.PartUUID)
	if err != nil {
		rep.MarkerVerified = "NO"
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"the claim reported success but §6.3's marker check FAILS at %s: %v", rep.MountPath, err))
		return
	}
	rep.MarkerVerified = fmt.Sprintf("yes — %s names partition %s, marker version %d",
		rep.MarkerPath, set.PartUUID, set.MarkerVersion)
}

// ---------------------------------------------------------------------------
// mount-data
// ---------------------------------------------------------------------------

// dataMountReport is the §6.5 startup sweep's result, split the way the
// operator reads it: what mounted, and what did not and why.
//
// Both halves are reported, and a skip is not an error here for the same
// reason it is not one in the agent — §6.3's first bullet is that a missing
// data disk must never make a node unbootable, so the sweep logs and carries
// on. What this command adds over the agent's log is an exit code, because a
// bench script asking "did the disk come up" needs an answer it can branch on.
type dataMountReport struct {
	Backend string `json:"backend"`
	Fixture bool   `json:"fixture"`
	// Mounted are the disks that came up, with where they landed.
	Mounted []dataMountLine `json:"mounted"`
	// Skipped are the disks the sweep looked at and did not mount, each with
	// the reason. A skipped disk means the apps placed on it will not find
	// their data — §6.3's loud condition.
	Skipped  []dataMountLine `json:"skipped"`
	Warnings []string        `json:"warnings,omitempty"`
}

// dataMountLine is one disk the sweep looked at. storage.DataMount carries an
// error value, which does not survive JSON; this carries its text.
type dataMountLine struct {
	PartUUID       string `json:"partUuid,omitempty"`
	DevicePath     string `json:"devicePath,omitempty"`
	MountPath      string `json:"mountPath,omitempty"`
	AlreadyMounted bool   `json:"alreadyMounted,omitempty"`
	// MarkerPath is where §6.3's marker sits on a mounted disk, derived from
	// the data purpose's spec rather than spelled here.
	MarkerPath string `json:"markerPath,omitempty"`
	Error      string `json:"error,omitempty"`
}

func newDataMountReport(mounts []storage.DataMount, sel backendChoice) dataMountReport {
	rep := dataMountReport{Backend: sel.Name, Fixture: sel.Fixture}
	if sel.Fixture {
		rep.Warnings = append(rep.Warnings, fixtureBanner)
	}
	spec, specErr := proto.StoragePurposeSpecFor(proto.StoragePurposeData)
	for _, m := range mounts {
		line := dataMountLine{
			PartUUID:       m.PartUUID,
			DevicePath:     m.DevicePath,
			MountPath:      m.MountPath,
			AlreadyMounted: m.AlreadyMounted,
		}
		if m.Err != nil {
			line.Error = m.Err.Error()
			rep.Skipped = append(rep.Skipped, line)
			continue
		}
		if specErr == nil && line.MountPath != "" {
			line.MarkerPath = filepath.Join(line.MountPath, spec.MarkerFile)
		}
		rep.Mounted = append(rep.Mounted, line)
	}
	if len(mounts) == 0 {
		rep.Warnings = append(rep.Warnings, "the sweep found no claimed data disk on this node — enumeration succeeded and matched nothing, which is not the same as a failure to look")
	}
	return rep
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

// inspectReport is a claimed target as it exists on the disk right now.
//
// The two booleans on StorageInspectAck mean different things and the report
// keeps them apart: Present false is "nothing with that partition UUID is
// attached" — an answer, the operator unplugged it — while OK false is "the
// agent could not answer". The pair OK=false with Present=true is a third
// thing again: a disk that IS attached and would not mount.
type inspectReport struct {
	Backend    string                  `json:"backend"`
	Fixture    bool                    `json:"fixture"`
	Present    bool                    `json:"present"`
	OK         bool                    `json:"ok"`
	PartUUID   string                  `json:"partUuid,omitempty"`
	DevicePath string                  `json:"devicePath,omitempty"`
	MountPath  string                  `json:"mountPath,omitempty"`
	FSType     string                  `json:"fsType,omitempty"`
	FSLabel    string                  `json:"fsLabel,omitempty"`
	Purpose    proto.StoragePurpose    `json:"purpose,omitempty"`
	MarkerPath string                  `json:"markerPath,omitempty"`
	TotalBytes uint64                  `json:"totalBytes,omitempty"`
	FreeBytes  uint64                  `json:"freeBytes,omitempty"`
	BackupSet  *proto.StorageBackupSet `json:"backupSet,omitempty"`
	DataSet    *proto.StorageDataSet   `json:"dataSet,omitempty"`
	Refusal    proto.StorageRefusal    `json:"refusal,omitempty"`
	Detail     string                  `json:"detail,omitempty"`
	Warnings   []string                `json:"warnings,omitempty"`
}

func newInspectReport(ack *proto.StorageInspectAck, sel backendChoice) inspectReport {
	rep := inspectReport{Backend: sel.Name, Fixture: sel.Fixture}
	if sel.Fixture {
		rep.Warnings = append(rep.Warnings, fixtureBanner)
	}
	if ack == nil {
		rep.Warnings = append(rep.Warnings, "the backend returned no inspect ack at all")
		return rep
	}
	rep.OK, rep.Present = ack.OK, ack.Present
	rep.PartUUID, rep.DevicePath, rep.MountPath = ack.PartUUID, ack.DevicePath, ack.MountPath
	rep.FSType, rep.FSLabel = ack.FSType, ack.FSLabel
	rep.TotalBytes, rep.FreeBytes = ack.TotalBytes, ack.FreeBytes
	rep.BackupSet, rep.DataSet = ack.BackupSet, ack.DataSet
	rep.Refusal, rep.Detail = ack.Refusal, ack.Detail

	// The purpose is derived from the filesystem label, which proto is explicit
	// is a HINT and never identity. It is used here for exactly what a hint is
	// good for — naming the marker file to go and read — and for nothing that
	// touches the disk.
	if purpose, ok := proto.StoragePurposeForFSLabel(strings.TrimSpace(ack.FSLabel)); ok {
		rep.Purpose = purpose
		if spec, err := proto.StoragePurposeSpecFor(purpose); err == nil && ack.MountPath != "" {
			rep.MarkerPath = filepath.Join(ack.MountPath, spec.MarkerFile)
		}
	}
	switch {
	case !ack.Present:
		rep.Warnings = append(rep.Warnings, "NOT PRESENT — no attached disk carries that partition UUID. That is an answer, not a failure: the target is unplugged, or was never claimed on this node")
	case !ack.OK:
		rep.Warnings = append(rep.Warnings, "the disk IS attached and the agent could not answer for it — an attached target that will not mount, not a missing one")
	}
	if ack.Present && ack.OK && ack.BackupSet == nil && ack.DataSet == nil {
		rep.Warnings = append(rep.Warnings, "the target is mounted and carries NO marker — under §6.3 that is either an unmounted mount point on the boot medium or not the disk it claims to be")
	}
	return rep
}

// ---------------------------------------------------------------------------

// humanBytes renders a size the way an operator checks it against the label on
// the drive. Binary units, because that is what lsblk prints and the whole
// point of printing a size here is that the two can be compared.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
