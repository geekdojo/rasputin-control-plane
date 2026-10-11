package secretstore

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Health is the store's sys/health answer.
type Health struct {
	Initialized bool
	Sealed      bool
	Standby     bool
	Version     string
}

// KV is one version of a kv-v2 secret. Each value is the caller's own
// secret.Value: the caller destroys it (Destroy does all of them).
type KV struct {
	Data        map[string]secret.Value
	Version     int
	CreatedTime time.Time
}

// Destroy zeroes every value in kv.
func (kv KV) Destroy() {
	for _, v := range kv.Data {
		v.Destroy()
	}
}

// Metadata is a kv-v2 secret's version history.
type Metadata struct {
	CurrentVersion int
	OldestVersion  int
	CreatedTime    time.Time
	UpdatedTime    time.Time
	Versions       map[int]VersionMetadata
}

// VersionMetadata is one version's entry in Metadata. DeletionTime is zero
// for a version that is not deleted.
type VersionMetadata struct {
	CreatedTime  time.Time
	DeletionTime time.Time
	Destroyed    bool
}

// checkWrite refuses, before any request, what the store would accept and
// then get wrong (ErrInvalidValue):
//
//   - a negative check-and-set version;
//   - an empty key, or a key or value that is not valid UTF-8, which JSON
//     would silently rewrite to U+FFFD, so a different secret would be stored;
//   - a value that parses as an RFC 3339 time, which ADR-0010's S1 table says
//     the store's audit log writes in clear rather than HMACed.
func checkWrite(data map[string]secret.Value, cas int) error {
	if cas < 0 {
		return fmt.Errorf("check-and-set version %d is negative", cas)
	}
	for k, v := range data {
		if k == "" || !utf8.ValidString(k) {
			return errors.New("a key is empty or not valid UTF-8")
		}
		if err := checkValue(v); err != nil {
			return fmt.Errorf("the value for key %q %w", k, err)
		}
	}
	return nil
}

// checkValue is checkWrite's test of one value.
func checkValue(v secret.Value) error {
	b := v.Reveal()
	if !utf8.Valid(b) {
		return errors.New("is not valid UTF-8")
	}
	// time.Parse takes a string, and a string copy of a secret cannot be
	// zeroed, so only a value that could be a timestamp is copied: at least
	// as long as the shortest RFC 3339 time, and starting with a year digit.
	// (There is no upper bound: time.Parse accepts any number of fractional
	// second digits.)
	if len(b) < len("2006-01-02T15:04:05Z") || b[0] < '0' || b[0] > '9' {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, string(b)); err == nil {
		return errors.New("parses as an RFC 3339 time, which the audit log writes in clear")
	}
	return nil
}
