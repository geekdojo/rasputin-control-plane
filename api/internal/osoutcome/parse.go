package osoutcome

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
)

// maxRecord is the largest record Parse accepts. The real records are four
// short lines; anything larger is not one.
const maxRecord = 4096

// maxReason bounds the reason sentence.
const maxReason = 1024

var (
	bootIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	runIDRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Record is one parsed outcome record. A field the source does not declare
// is empty.
type Record struct {
	Outcome string
	BootID  string
	RunID   string
	KeyID   string
	Reason  string
}

// Parse reads b as src's record. It is strict: the bytes are valid UTF-8 of
// at most maxRecord bytes ending in a newline, every line is key=value split
// at the first '=', and each declared key, outcome included, appears exactly
// once with no other key and no blank line. The outcome is in src's
// vocabulary and every field passes its type's check. Anything else is an
// error, never a Record.
func Parse(src Source, b []byte) (Record, error) {
	if len(b) > maxRecord {
		return Record{}, fmt.Errorf("the record is over %d bytes", maxRecord)
	}
	if !utf8.Valid(b) {
		return Record{}, errors.New("the record is not valid UTF-8")
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return Record{}, errors.New("the record does not end in a newline")
	}
	values := make(map[string]string, len(src.Fields)+1)
	for i, line := range strings.Split(string(b[:len(b)-1]), "\n") {
		k, v, ok := strings.Cut(line, "=")
		switch {
		case line == "":
			return Record{}, fmt.Errorf("line %d is blank", i+1)
		case !ok:
			return Record{}, fmt.Errorf("line %d has no '='", i+1)
		case k != fieldOutcome && !src.has(k):
			return Record{}, fmt.Errorf("line %d has the unknown key %q", i+1, k)
		}
		if _, dup := values[k]; dup {
			return Record{}, fmt.Errorf("the key %q appears twice", k)
		}
		values[k] = v
	}
	if _, ok := values[fieldOutcome]; !ok {
		return Record{}, errors.New("the record has no outcome line")
	}
	for _, f := range src.Fields {
		if _, ok := values[f]; !ok {
			return Record{}, fmt.Errorf("the record has no %s line", f)
		}
	}
	rec := Record{
		Outcome: values[fieldOutcome],
		BootID:  values[FieldBootID],
		RunID:   values[FieldRunID],
		KeyID:   values[FieldKeyID],
		Reason:  values[FieldReason],
	}
	if _, ok := src.Outcomes[rec.Outcome]; !ok {
		return Record{}, fmt.Errorf("the outcome %q is not one %s records", rec.Outcome, src.Kind)
	}
	if src.has(FieldBootID) && !bootIDRE.MatchString(rec.BootID) {
		return Record{}, errors.New("boot_id is not a lowercase uuid")
	}
	if src.has(FieldRunID) && !runIDRE.MatchString(rec.RunID) {
		return Record{}, errors.New("run_id is not 32 lowercase hex characters")
	}
	if src.has(FieldKeyID) && rec.KeyID != "-" {
		if _, err := sealrotate.ParseKeyID(rec.KeyID); err != nil {
			return Record{}, errors.New("key_id is neither - nor rasputin-<uuid>")
		}
	}
	if src.has(FieldReason) {
		if err := checkReason(rec.Reason); err != nil {
			return Record{}, err
		}
	}
	return rec, nil
}

// checkReason admits 1 to maxReason bytes with no C0 control character other
// than tab.
func checkReason(r string) error {
	if r == "" || len(r) > maxReason {
		return fmt.Errorf("reason is not 1 to %d bytes", maxReason)
	}
	for i := 0; i < len(r); i++ {
		if c := r[i]; c < 0x20 && c != '\t' {
			return errors.New("reason holds a control character")
		}
	}
	return nil
}
