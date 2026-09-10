package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Rendering. Two modes over one report — human text by default, --json for a
// script — and neither computes anything: every decision was made in report.go
// so the two cannot come to different conclusions about the same run.
//
// Text is the DEFAULT rather than JSON. The headline use of this command is an
// operator on an SSH session reading which of two identical NVMes is the boot
// medium, immediately before typing a command that formats the other one, and
// `jq` is not on a Rasputin node.

// renderJSON writes any report as indented JSON. Indented, not compact: the
// consumer is usually a human piping to `less` on a machine with no jq, and a
// script does not care either way.
func renderJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// renderEnumerateText writes the disk listing, protected set first.
func renderEnumerateText(w io.Writer, rep enumerateReport) error {
	var b strings.Builder
	writeWarnings(&b, rep.Warnings)
	fmt.Fprintf(&b, "backend=%s  observed=%s  candidates=%d\n\n",
		rep.Backend, rep.Observed.UTC().Format("2006-01-02T15:04:05Z"), len(rep.Protected)+len(rep.Claimable))

	// The protected block is first, is always printed — including its count
	// when it is zero, which is the alarming case — and carries the reason
	// verbatim on its own line under each disk.
	fmt.Fprintf(&b, "PROTECTED (%d) — `claim` refuses these; the reason is re-derived from live mounts before any format\n", len(rep.Protected))
	if len(rep.Protected) == 0 {
		b.WriteString("  (none — see the warning above)\n")
	}
	for _, c := range rep.Protected {
		writeCandidate(&b, c)
	}

	fmt.Fprintf(&b, "\nCLAIMABLE (%d) — not in the protected set. That is not the same as empty: read the partition table\n", len(rep.Claimable))
	if len(rep.Claimable) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, c := range rep.Claimable {
		writeCandidate(&b, c)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// writeCandidate renders one disk. The fingerprint is on it because `claim`
// requires it and this listing is where an operator copies it from.
//
// The protection reason comes IMMEDIATELY under the device line, above the
// partition table, and not at the end of the block. It is the one line in this
// output an operator must not skim past, and a reason printed after eight
// lines of partitions is a reason printed off the bottom of a terminal.
func writeCandidate(b *strings.Builder, c proto.StorageCandidate) {
	fmt.Fprintf(b, "  %s  %s  %s  %s%s\n", c.DevicePath, humanBytes(c.SizeBytes),
		firstNonBlank(c.Model, "(no model)"), c.Transport, removableSuffix(c.Removable))
	if c.Protected {
		fmt.Fprintf(b, "      PROTECTED:   %s\n", firstNonBlank(c.ProtectedReason, "(the backend gave no reason — that is a bug, not a clean bill of health)"))
	}
	fmt.Fprintf(b, "      fingerprint: %s\n", c.Fingerprint)
	fmt.Fprintf(b, "      identity:    wwn=%s serial=%s%s\n",
		firstNonBlank(c.WWN, "-"), firstNonBlank(c.Serial, "-"), weakSuffix(c.IdentityWeak))
	if purpose, ok := c.ClaimedPurpose(); ok {
		fmt.Fprintf(b, "      claimed as:  %s\n", purpose)
	} else {
		b.WriteString("      claimed as:  (nothing Rasputin wrote)\n")
	}
	if len(c.Partitions) == 0 {
		b.WriteString("      partitions:  (none)\n")
		return
	}
	b.WriteString("      partitions:\n")
	for _, p := range c.Partitions {
		fmt.Fprintf(b, "        %s  %s  fs=%s label=%s partuuid=%s%s\n",
			p.DevicePath, humanBytes(p.SizeBytes),
			firstNonBlank(p.FSType, "-"), firstNonBlank(p.Label, "-"), firstNonBlank(p.PartUUID, "-"),
			mountedSuffix(p.Mountpoint))
	}
}

// renderClaimText writes a completed claim. Every field here is one an
// operator can go and check by hand afterwards, which is the point of printing
// them rather than "claim OK".
func renderClaimText(w io.Writer, rep claimReport) error {
	var b strings.Builder
	writeWarnings(&b, rep.Warnings)
	fmt.Fprintf(&b, "CLAIMED %s as %q (backend=%s)\n\n", rep.DevicePath, rep.Purpose, rep.Backend)
	fmt.Fprintf(&b, "  partUuid:      %s      <- the identifier. Persist this, never the device path\n", rep.PartUUID)
	fmt.Fprintf(&b, "  gpt name:      %s\n", rep.GPTName)
	fmt.Fprintf(&b, "  fs label:      %s\n", rep.FSLabel)
	fmt.Fprintf(&b, "  fs type:       %s\n", rep.FSType)
	fmt.Fprintf(&b, "  mount path:    %s\n", rep.MountPath)
	fmt.Fprintf(&b, "  mount options: %s\n", rep.MountOptions)
	fmt.Fprintf(&b, "  marker:        %s\n", rep.MarkerPath)
	if rep.MarkerVerified != "" {
		fmt.Fprintf(&b, "  marker read back: %s\n", rep.MarkerVerified)
	}
	fmt.Fprintf(&b, "  size:          %s\n", humanBytes(rep.SizeBytes))
	if rep.Label != "" {
		fmt.Fprintf(&b, "  operator label: %s\n", rep.Label)
	}
	fmt.Fprintf(&b, "  fingerprint:   %s\n", firstNonBlank(rep.Fingerprint, "(none reported)"))
	b.WriteString("      ^ this is the POST-format fingerprint and DIFFERS from the one you passed in.\n")
	b.WriteString("        The format rewrote the partition table the hash covers, which is what makes a\n")
	b.WriteString("        replayed claim fail closed. Re-run `enumerate` before claiming anything else.\n")
	b.WriteString("\nCheck it on the box:\n")
	fmt.Fprintf(&b, "  lsblk -o NAME,PARTLABEL,LABEL,PARTUUID,MOUNTPOINT %s\n", rep.DevicePath)
	fmt.Fprintf(&b, "  findmnt %s\n", rep.MountPath)
	fmt.Fprintf(&b, "  cat %s\n", rep.MarkerPath)
	_, err := io.WriteString(w, b.String())
	return err
}

// renderDataMountText writes the startup sweep's result. Skips come FIRST and
// are labelled SKIPPED rather than folded in among the successes: a disk that
// did not mount is the condition §6.3 wants loud, and it is invisible in a
// list that leads with three that did.
func renderDataMountText(w io.Writer, rep dataMountReport) error {
	var b strings.Builder
	writeWarnings(&b, rep.Warnings)
	fmt.Fprintf(&b, "MountClaimedData (backend=%s): %d mounted, %d skipped\n\n", rep.Backend, len(rep.Mounted), len(rep.Skipped))
	if len(rep.Skipped) > 0 {
		b.WriteString("SKIPPED — apps placed on these will not find their data:\n")
		for _, m := range rep.Skipped {
			fmt.Fprintf(&b, "  %s (%s)\n      %s\n",
				firstNonBlank(m.PartUUID, "(no partUuid)"), firstNonBlank(m.DevicePath, "(no device)"), m.Error)
		}
		b.WriteString("\n")
	}
	b.WriteString("MOUNTED:\n")
	if len(rep.Mounted) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, m := range rep.Mounted {
		state := "mounted now"
		if m.AlreadyMounted {
			state = "already mounted (an agent restart, not a boot)"
		}
		fmt.Fprintf(&b, "  %s (%s)\n      at:     %s — %s\n", m.PartUUID, firstNonBlank(m.DevicePath, "(no device)"), m.MountPath, state)
		if m.MarkerPath != "" {
			fmt.Fprintf(&b, "      marker: %s\n", m.MarkerPath)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// renderInspectText writes one claimed target's state.
func renderInspectText(w io.Writer, rep inspectReport) error {
	var b strings.Builder
	writeWarnings(&b, rep.Warnings)
	fmt.Fprintf(&b, "inspect %s (backend=%s): present=%t ok=%t\n", firstNonBlank(rep.PartUUID, "(no partUuid)"), rep.Backend, rep.Present, rep.OK)
	if rep.Refusal != "" {
		fmt.Fprintf(&b, "  refusal:     %s — %s\n", rep.Refusal, rep.Detail)
	}
	if !rep.Present {
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(&b, "  device:      %s\n", firstNonBlank(rep.DevicePath, "-"))
	fmt.Fprintf(&b, "  mount path:  %s\n", firstNonBlank(rep.MountPath, "-"))
	fmt.Fprintf(&b, "  fs:          type=%s label=%s\n", firstNonBlank(rep.FSType, "-"), firstNonBlank(rep.FSLabel, "-"))
	fmt.Fprintf(&b, "  purpose:     %s   (from the fs label, which is a HINT — nothing destructive keys off it)\n",
		firstNonBlank(string(rep.Purpose), "(label is none of ours)"))
	if rep.MarkerPath != "" {
		fmt.Fprintf(&b, "  marker:      %s\n", rep.MarkerPath)
	}
	fmt.Fprintf(&b, "  space:       %s free of %s\n", humanBytes(rep.FreeBytes), humanBytes(rep.TotalBytes))
	switch {
	case rep.DataSet != nil:
		fmt.Fprintf(&b, "  data set:    cluster=%s partuuid=%s label=%q created=%s markerVersion=%d\n",
			firstNonBlank(rep.DataSet.ClusterID, "-"), firstNonBlank(rep.DataSet.PartUUID, "-"),
			rep.DataSet.Label, rep.DataSet.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), rep.DataSet.MarkerVersion)
	case rep.BackupSet != nil:
		fmt.Fprintf(&b, "  backup set:  cluster=%s partuuid=%s label=%q keyId=%s created=%s markerVersion=%d\n",
			firstNonBlank(rep.BackupSet.ClusterID, "-"), firstNonBlank(rep.BackupSet.PartUUID, "-"),
			rep.BackupSet.Label, firstNonBlank(rep.BackupSet.KeyID, "-"),
			rep.BackupSet.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), rep.BackupSet.MarkerVersion)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// writeWarnings puts every warning at the TOP of the output and prefixes each
// with a marker that survives being skimmed. Bottom-of-output warnings are
// warnings nobody read.
func writeWarnings(b *strings.Builder, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	for _, w := range warnings {
		fmt.Fprintf(b, "!! %s\n", w)
	}
	b.WriteString("\n")
}

func firstNonBlank(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func removableSuffix(removable bool) string {
	if removable {
		return "  removable"
	}
	return ""
}

func weakSuffix(weak bool) string {
	if weak {
		return "  (IDENTITY WEAK — no wwn and no serial)"
	}
	return ""
}

func mountedSuffix(mountpoint string) string {
	if strings.TrimSpace(mountpoint) == "" {
		return ""
	}
	return "  MOUNTED AT " + mountpoint
}
