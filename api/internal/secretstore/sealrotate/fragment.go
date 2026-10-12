package sealrotate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"regexp"
)

// Shape is which of the three seal fragments is on disk.
type Shape int

// The shapes. The fragment is the rotation's single commit point: each shape
// names only key files whose bytes match their ids (plan, "Seal layout").
const (
	// Clean: current is seal-key; rotation/ holds nothing the fragment names.
	Clean Shape = iota + 1
	// Staged: current is the new key in rotation/, previous is seal-key.
	Staged
	// Verify: current is the new key in rotation/, with no previous.
	Verify
)

// String names the shape in logs and step results.
func (s Shape) String() string {
	switch s {
	case Clean:
		return "clean"
	case Staged:
		return "staged"
	case Verify:
		return "verify"
	}
	return "unknown"
}

// Fragment is one seal fragment: its shape and the key ids it names. Previous
// is set only for Staged.
type Fragment struct {
	Shape    Shape
	Current  KeyID
	Previous KeyID
}

// render is the fragment's bytes, with each key's path from p. Clean is
// byte for byte what rasputin-seal-key.sh's printf writes; Verify is the same
// two lines naming the rotation credential.
func (f Fragment) render(p Paths) ([]byte, error) {
	switch f.Shape {
	case Clean:
		return fmt.Appendf(nil, "seal \"static\" {\n  current_key_id = %q\n  current_key    = %q\n}\n",
			f.Current, "file://"+p.sealKeyCred()), nil
	case Verify:
		return fmt.Appendf(nil, "seal \"static\" {\n  current_key_id = %q\n  current_key    = %q\n}\n",
			f.Current, "file://"+p.RotationCred(f.Current)), nil
	case Staged:
		if f.Previous == "" {
			return nil, errors.New("sealrotate: a staged fragment needs a previous key id")
		}
		return fmt.Appendf(nil, "seal \"static\" {\n  current_key_id  = %q\n  current_key     = %q\n  previous_key_id = %q\n  previous_key    = %q\n}\n",
			f.Current, "file://"+p.RotationCred(f.Current), f.Previous, "file://"+p.sealKeyCred()), nil
	}
	return nil, fmt.Errorf("sealrotate: no fragment of shape %d", f.Shape)
}

// The fragment's grammar is the three shapes above and nothing else: an
// opening line, one `key = "value"` per line, a closing brace. This is not an
// HCL parser and accepts no other HCL; anything it does not recognise is
// refused, never guessed at.
var (
	openRE  = regexp.MustCompile(`^seal "static" \{$`)
	fieldRE = regexp.MustCompile(`^[ \t]*([a-z_]+)[ \t]*=[ \t]*"([^"\\]*)"[ \t]*$`)
)

// parseFragment reads b as one of the three shapes, with key paths from p.
// Each error names the defect.
func parseFragment(p Paths, b []byte) (Fragment, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return Fragment{}, errors.New("sealrotate: the seal fragment is empty")
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	fields := map[string]string{}
	state := 0 // 0 before the block, 1 inside it, 2 after it
	for sc.Scan() {
		line := sc.Text()
		switch {
		case state == 0 && openRE.MatchString(line):
			state = 1
		case state == 0:
			return Fragment{}, errors.New("sealrotate: the seal fragment does not open with a static seal block")
		case state == 1 && line == "}":
			state = 2
		case state == 1:
			m := fieldRE.FindStringSubmatch(line)
			if m == nil {
				return Fragment{}, errors.New("sealrotate: the seal fragment has a line that is not key = \"value\"")
			}
			switch m[1] {
			case "current_key_id", "current_key", "previous_key_id", "previous_key":
			default:
				return Fragment{}, fmt.Errorf("sealrotate: the seal fragment sets %s, which a rotation never writes", m[1])
			}
			if _, dup := fields[m[1]]; dup {
				return Fragment{}, fmt.Errorf("sealrotate: the seal fragment sets %s twice", m[1])
			}
			fields[m[1]] = m[2]
		case line != "":
			return Fragment{}, errors.New("sealrotate: the seal fragment has more than one seal block, or text after it")
		}
	}
	if err := sc.Err(); err != nil {
		return Fragment{}, fmt.Errorf("sealrotate: read the seal fragment: %w", err)
	}
	if state != 2 {
		return Fragment{}, errors.New("sealrotate: the seal fragment's block is not closed")
	}
	return classify(p, fields)
}

// classify maps a fragment's fields to its shape, refusing any combination a
// rotation never writes.
func classify(p Paths, fields map[string]string) (Fragment, error) {
	curID, ok := fields["current_key_id"]
	if !ok {
		return Fragment{}, errors.New("sealrotate: the seal fragment has no current_key_id")
	}
	cur, err := ParseKeyID(curID)
	if err != nil {
		return Fragment{}, err
	}
	curPath, ok := fields["current_key"]
	if !ok {
		return Fragment{}, errors.New("sealrotate: the seal fragment has no current_key")
	}
	prevID, hasPrevID := fields["previous_key_id"]
	prevPath, hasPrevPath := fields["previous_key"]
	if hasPrevID != hasPrevPath {
		return Fragment{}, errors.New("sealrotate: the seal fragment has a previous key id without a previous key, or the reverse")
	}
	switch {
	case !hasPrevID && curPath == "file://"+p.sealKeyCred():
		return Fragment{Shape: Clean, Current: cur}, nil
	case !hasPrevID && curPath == "file://"+p.RotationCred(cur):
		return Fragment{Shape: Verify, Current: cur}, nil
	case hasPrevID && curPath == "file://"+p.RotationCred(cur):
		prev, err := ParseKeyID(prevID)
		if err != nil {
			return Fragment{}, err
		}
		if prev == cur {
			return Fragment{}, errors.New("sealrotate: the seal fragment's previous key id is its current one")
		}
		if prevPath != "file://"+p.sealKeyCred() {
			return Fragment{}, errors.New("sealrotate: the seal fragment's previous key is not the seal key credential")
		}
		return Fragment{Shape: Staged, Current: cur, Previous: prev}, nil
	}
	return Fragment{}, errors.New("sealrotate: the seal fragment's current key is not a credential this rotation writes")
}
