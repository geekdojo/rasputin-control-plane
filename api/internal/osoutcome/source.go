// Package osoutcome turns the outcome records rasputin-os writes before the
// api starts into terminal jobs in the job ledger, and derives a crit alert
// from the newest job of each record's kind (geekdojo/geekdojo-brain#833).
//
// A record is a small KEY=VALUE file under /run that a oneshot unit writes on
// every run: the seal key (#803), the store's first init (#804) and the
// store provisioner (#805). Each is declared once, as a Source; the reader
// has no per-source code, so a new record is one more declaration.
//
// The ledger is the one source of truth. A record becomes exactly one job per
// idempotency key and outcome, with an ID derived from both, written by a
// single INSERT ... ON CONFLICT DO NOTHING, so a re-read is never a second
// job. The alert is computed on read from the newest job of the kind: it
// stands while that job failed and clears when a newer record reports an
// outcome that does not alert. No timer is involved.
package osoutcome

// Verdict is what an outcome word means.
type Verdict int

const (
	// OK is an outcome that records a succeeded job and raises no alert.
	OK Verdict = iota + 1
	// Alert is an outcome that records a failed job and raises the crit alert.
	Alert
)

// The fields a record may carry besides outcome. The set is closed: a
// declaration naming any other field is refused by New.
const (
	FieldBootID = "boot_id"
	FieldRunID  = "run_id"
	FieldKeyID  = "key_id"
	FieldReason = "reason"
)

// fieldOutcome is the line every record carries.
const fieldOutcome = "outcome"

// OutcomeUnreadable is the outcome recorded for a record that exists but
// cannot be read or parsed. It always alerts.
const OutcomeUnreadable = "unreadable"

// knownFields is the closed field set.
var knownFields = map[string]bool{FieldBootID: true, FieldRunID: true, FieldKeyID: true, FieldReason: true}

// keyFields are the fields that may be a record's idempotency key.
var keyFields = map[string]bool{FieldBootID: true, FieldRunID: true}

// Source declares one outcome record.
type Source struct {
	// Kind is the job kind, for example os.seal_key.
	Kind string
	// Path is the record file.
	Path string
	// Fields are the keys the record carries besides outcome.
	Fields []string
	// KeyField is the idempotency key: FieldBootID or FieldRunID.
	KeyField string
	// Outcomes maps each outcome word to its verdict.
	Outcomes map[string]Verdict
	// Title is the alert title.
	Title string
	// AfterStoreRestart is whether the record is read again after the api
	// restarts the secret store.
	AfterStoreRestart bool
	// StartUnit, when set, is started before the after-restart read.
	StartUnit string
}

// has reports whether the source declares field.
func (s Source) has(field string) bool {
	for _, f := range s.Fields {
		if f == field {
			return true
		}
	}
	return false
}
