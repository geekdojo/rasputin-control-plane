package updater

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
)

// grubenv.go — a minimal reader/writer for the GRUB environment block, the
// on-disk file GRUB's grub.cfg uses to carry the A/B boot-counter
// (ORDER + <slot>_OK / <slot>_TRY). On the compute (n100) image RAUC owns this
// file via its grub bootloader backend + grub-editenv; the firewall has no
// RAUC, so OpenWrtABBackend edits it directly with this codec.
//
// Format (grub-core/lib/envblk.c): a fixed-size (default 1024-byte) block that
// begins with the literal signature line, followed by `name=value\n` entries,
// with the remainder padded with '#' bytes. GRUB reads AND writes this file at
// boot (grub.cfg calls save_env to consume tries), which imposes the single
// most important constraint on our writer:
//
//	⚠ The file must be overwritten IN PLACE (same inode / same FAT cluster
//	  chain), never recreated via temp-file + rename. GRUB's save_env writes
//	  through a precomputed block list; if we relocate the file's data blocks
//	  (which truncate-and-recreate does on FAT), GRUB's next save_env scribbles
//	  over whatever now occupies the old blocks. So writeGrubenv opens the
//	  existing file O_WRONLY and overwrites its bytes at offset 0, keeping the
//	  size identical. First-time creation happens exactly once at image build /
//	  provisioning, never on the update path.
const (
	grubenvSignature = "# GRUB Environment Block\n"
	grubenvSize      = 1024
	grubenvPadByte   = '#'
)

// parseGrubenv decodes a GRUB environment block into a key→value map. It
// tolerates a missing signature (returns an empty map rather than erroring) so
// a corrupt/blank file degrades to "defaults" — the grub.cfg already hard-codes
// safe defaults before load_env, so an empty map here can never brick a boot.
func parseGrubenv(b []byte) map[string]string {
	kv := map[string]string{}
	body := b
	if bytes.HasPrefix(body, []byte(grubenvSignature)) {
		body = body[len(grubenvSignature):]
	}
	// The '#' padding is a contiguous trailing run with no newlines, so it
	// surfaces as one final field; entries never start with '#', so skipping
	// '#'-leading fields drops the padding cleanly.
	for _, line := range strings.Split(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			kv[line[:i]] = line[i+1:]
		}
	}
	return kv
}

// encodeGrubenv serialises kv into a size-byte GRUB environment block. Keys are
// emitted in sorted order for deterministic output (stable across writes so a
// no-op mark-good doesn't churn the file / diff). Returns an error if the
// entries don't fit in size bytes — grub-editenv fails the same way rather than
// silently dropping state.
func encodeGrubenv(kv map[string]string, size int) ([]byte, error) {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString(grubenvSignature)
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(kv[k])
		buf.WriteByte('\n')
	}
	if buf.Len() > size {
		return nil, fmt.Errorf("grubenv: %d bytes of entries exceed %d-byte block", buf.Len(), size)
	}
	out := make([]byte, size)
	copy(out, buf.Bytes())
	for i := buf.Len(); i < size; i++ {
		out[i] = grubenvPadByte
	}
	return out, nil
}

// readGrubenv loads and parses the grubenv at path.
func readGrubenv(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseGrubenv(b), nil
}

// writeGrubenv overwrites the grubenv at path IN PLACE with kv, preserving the
// existing block size (so GRUB's save_env block list stays valid — see the file
// header). The file MUST already exist (created once at provisioning); writing
// to a missing grubenv is an error rather than a silent create, because a
// freshly-created file would land on different FAT clusters and defeat the
// in-place guarantee GRUB relies on.
func writeGrubenv(path string, kv map[string]string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("grubenv: %w (must be pre-created at provisioning)", err)
	}
	size := int(fi.Size())
	if size < len(grubenvSignature) {
		// A too-small file can't be a real grubenv; fall back to the GRUB
		// default so we don't write a truncated block GRUB would reject.
		size = grubenvSize
	}
	block, err := encodeGrubenv(kv, size)
	if err != nil {
		return err
	}
	// O_WRONLY (NOT O_CREATE|O_TRUNC): overwrite bytes in the existing file so
	// the FAT cluster chain is untouched. block is exactly `size` bytes, i.e.
	// the current file length, so there's nothing to truncate.
	f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(block, 0); err != nil {
		return err
	}
	return f.Sync()
}

// abState is the decoded A/B boot-counter carried in grubenv. Mirrors the
// variables the firewall grub.cfg reads: ORDER (slot-name preference list) plus
// per-slot OK (bootable) and TRY (attempt-consumed) flags.
type abState struct {
	order []string        // e.g. ["A","B"]
	ok    map[string]bool // "A"/"B" → bootable
	try   map[string]bool // "A"/"B" → a boot attempt has been consumed
}

// decodeAB extracts the A/B counter from a parsed grubenv map. Absent keys
// default to the same safe values grub.cfg hard-codes (ORDER "A B", A good, B
// not) so a partial file still yields a coherent state.
func decodeAB(kv map[string]string) abState {
	order := strings.Fields(kv["ORDER"])
	if len(order) == 0 {
		order = []string{"A", "B"}
	}
	st := abState{
		order: order,
		ok:    map[string]bool{"A": kv["A_OK"] == "1", "B": kv["B_OK"] == "1"},
		try:   map[string]bool{"A": kv["A_TRY"] == "1", "B": kv["B_TRY"] == "1"},
	}
	// If neither slot recorded an OK flag at all, assume the flash-time default
	// (A good) rather than a state with no bootable slot.
	if _, hasA := kv["A_OK"]; !hasA {
		if _, hasB := kv["B_OK"]; !hasB {
			st.ok["A"] = true
		}
	}
	return st
}

// encodeAB folds the A/B counter back into a grubenv map, preserving any other
// keys already present in kv (there are none today, but this keeps the codec
// non-destructive).
func encodeAB(kv map[string]string, st abState) map[string]string {
	out := map[string]string{}
	for k, v := range kv {
		switch k {
		case "ORDER", "A_OK", "A_TRY", "B_OK", "B_TRY":
			// replaced below
		default:
			out[k] = v
		}
	}
	out["ORDER"] = strings.Join(st.order, " ")
	out["A_OK"] = b2s(st.ok["A"])
	out["B_OK"] = b2s(st.ok["B"])
	out["A_TRY"] = b2s(st.try["A"])
	out["B_TRY"] = b2s(st.try["B"])
	return out
}

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
