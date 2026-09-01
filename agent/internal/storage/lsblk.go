package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// lsblk JSON decoding, kept in its own file so the parsing can be unit-tested
// against captured real output without a runner, a disk, or root.
//
// The flexible scalar types below are not defensiveness for its own sake.
// lsblk's JSON has changed shape across util-linux releases — `size` is a
// decimal string in some versions and a number under --bytes in others, `rm`
// and `rota` are "0"/"1" strings in older builds and booleans in newer ones —
// and the agent runs on Buildroot, OpenWrt and whatever a developer has. A
// decoder that hard-fails on the wrong scalar kind would turn a cosmetic
// upstream change into "no candidate disks", which reads to an operator as
// broken hardware.

// lsblkOutput is the top level of `lsblk --json`.
type lsblkOutput struct {
	BlockDevices []lsblkDevice `json:"blockdevices"`
}

// lsblkDevice is one node of the lsblk tree. The requested column set is
// explicit at the call site rather than `-O`, so this struct and that list are
// the contract; adding a field here means adding the column there.
type lsblkDevice struct {
	Name       string        `json:"name"`
	KName      string        `json:"kname"`
	Path       string        `json:"path"`
	Type       string        `json:"type"`
	Size       flexUint64    `json:"size"`
	Model      string        `json:"model"`
	Serial     string        `json:"serial"`
	WWN        string        `json:"wwn"`
	Tran       string        `json:"tran"`
	RM         flexBool      `json:"rm"`
	FSType     string        `json:"fstype"`
	Label      string        `json:"label"`
	PartUUID   string        `json:"partuuid"`
	MountPoint string        `json:"mountpoint"`
	Children   []lsblkDevice `json:"children"`
}

// lsblkColumns is the column list passed to lsblk. Order is irrelevant to JSON
// output but the set is not — a column left out decodes as the zero value with
// no error, which for WWN or SERIAL would silently weaken every fingerprint.
const lsblkColumns = "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,RM,FSTYPE,LABEL,PARTUUID,MOUNTPOINT"

// flexUint64 decodes a JSON number, a decimal string, or null.
type flexUint64 uint64

func (f *flexUint64) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = 0
		return nil
	}
	s := strings.Trim(string(b), `"`)
	if s == "" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("lsblk: unparseable size %q: %w", s, err)
	}
	*f = flexUint64(v)
	return nil
}

// flexBool decodes a JSON bool, "0"/"1", "true"/"false", or null.
type flexBool bool

func (f *flexBool) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	switch s {
	case "", "null", "0", "false":
		*f = false
	case "1", "true":
		*f = true
	default:
		return fmt.Errorf("lsblk: unparseable boolean %q", s)
	}
	return nil
}

// parseLsblk decodes `lsblk --json` output.
func parseLsblk(b []byte) (*lsblkOutput, error) {
	var out lsblkOutput
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse lsblk json: %w", err)
	}
	return &out, nil
}

// nonCandidatePrefixes are kernel names that are never a backup target. Note
// this is the ONLY place in the package where a device name influences a
// decision, and it is deliberately one-directional: it can only remove a device
// from the candidate list, never mark one safe to format. Protection is decided
// by the mount walk in protect.go and by nothing else.
var nonCandidatePrefixes = []string{
	"loop", // squashfs / snap loopbacks
	"ram",  // ramdisks
	"zram",
	"sr",  // optical
	"fd",  // floppy, and the odd USB card reader that presents as one
	"dm-", // stacked devices are protected via slaves/, never claimed directly
	"md",  // ditto
}

// isCandidateDisk reports whether an lsblk node is a whole disk an operator
// could plausibly claim.
func isCandidateDisk(d lsblkDevice) bool {
	if d.Type != "disk" {
		return false
	}
	if d.Size == 0 {
		// A card reader with no card, or a device that failed to enumerate.
		// Offering it would produce a format that fails halfway.
		return false
	}
	for _, p := range nonCandidatePrefixes {
		if strings.HasPrefix(d.KName, p) || strings.HasPrefix(d.Name, p) {
			return false
		}
	}
	return true
}

// transportOf maps lsblk's TRAN column onto the proto enum.
func transportOf(tran string) string {
	switch strings.ToLower(strings.TrimSpace(tran)) {
	case "usb":
		return "usb"
	case "nvme":
		return "nvme"
	case "sata", "ata":
		return "sata"
	case "mmc":
		return "mmc"
	case "virtio", "vmbus", "xen":
		return "virtual"
	default:
		return "unknown"
	}
}
