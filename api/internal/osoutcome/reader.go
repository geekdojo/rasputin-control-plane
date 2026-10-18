package osoutcome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// createdBy is the CreatedBy of every job the reader records.
const createdBy = "rasputin-os"

// Ledger is the slice of the job ledger the reader uses. *jobs.Store
// satisfies it.
type Ledger interface {
	RecordFinishedJob(ctx context.Context, j *jobs.Job) (bool, error)
	ListJobsByKind(ctx context.Context, kind string, limit int) ([]*jobs.Job, error)
}

// Deps are the reader's collaborators. New refuses a nil one.
type Deps struct {
	Ledger Ledger
	Log    *slog.Logger
	Now    func() time.Time
	// BootID returns the api's own boot id. It is called only for a record
	// that cannot be read, whose key it becomes.
	BootID func() (string, error)
	// StartUnit starts a systemd unit and returns when the start job ends.
	StartUnit func(ctx context.Context, unit string) error
}

// Reader reads the declared records into the ledger and derives their alert.
// It holds no mutable state: each record is one atomic INSERT, so concurrent
// reads (the start read and a store restart's) need no lock.
type Reader struct {
	d    Deps
	srcs []Source
}

// Spec is the spec of every job the reader records.
type Spec struct {
	Source  string `json:"source"`
	Outcome string `json:"outcome"`
	BootID  string `json:"bootId,omitempty"`
	RunID   string `json:"runId,omitempty"`
	KeyID   string `json:"keyId,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Path    string `json:"path"`
}

// New returns a Reader over srcs, or an error for a nil collaborator or a
// declaration it cannot read records with.
func New(d Deps, srcs []Source) (*Reader, error) {
	switch {
	case d.Ledger == nil:
		return nil, errors.New("osoutcome: the ledger is nil")
	case d.Log == nil:
		return nil, errors.New("osoutcome: the logger is nil")
	case d.Now == nil:
		return nil, errors.New("osoutcome: the clock is nil")
	case d.BootID == nil:
		return nil, errors.New("osoutcome: the boot id source is nil")
	case d.StartUnit == nil:
		return nil, errors.New("osoutcome: the unit starter is nil")
	}
	kinds := make(map[string]bool, len(srcs))
	for _, s := range srcs {
		if err := checkSource(s); err != nil {
			return nil, fmt.Errorf("osoutcome: source %q: %w", s.Kind, err)
		}
		if kinds[s.Kind] {
			return nil, fmt.Errorf("osoutcome: source %q is declared twice", s.Kind)
		}
		kinds[s.Kind] = true
	}
	return &Reader{d: d, srcs: append([]Source(nil), srcs...)}, nil
}

// checkSource refuses a declaration the parser cannot honour.
func checkSource(s Source) error {
	if s.Kind == "" || s.Path == "" {
		return errors.New("kind and path are required")
	}
	seen := make(map[string]bool, len(s.Fields))
	for _, f := range s.Fields {
		if !knownFields[f] {
			return fmt.Errorf("the field %q is not one a record carries", f)
		}
		if seen[f] {
			return fmt.Errorf("the field %q is declared twice", f)
		}
		seen[f] = true
	}
	if !keyFields[s.KeyField] || !seen[s.KeyField] {
		return fmt.Errorf("the key field %q is not a declared boot_id or run_id", s.KeyField)
	}
	if len(s.Outcomes) == 0 {
		return errors.New("the outcome vocabulary is empty")
	}
	for w, v := range s.Outcomes {
		if v != OK && v != Alert {
			return fmt.Errorf("the outcome %q has no verdict", w)
		}
	}
	return nil
}

// Kinds are the job kinds the reader records.
func (r *Reader) Kinds() []string {
	out := make([]string, len(r.srcs))
	for i, s := range r.srcs {
		out[i] = s.Kind
	}
	return out
}

// ReadAtStart reads every declared record. It makes no systemctl call, so
// nothing on the path to READY waits on systemd.
func (r *Reader) ReadAtStart(ctx context.Context) {
	for _, s := range r.srcs {
		r.read(ctx, s)
	}
}

// AfterStoreRestart reads each record declared to follow a store restart,
// starting its unit first when one is declared. It is the hook every store
// restart the api performs runs once the restart returns.
func (r *Reader) AfterStoreRestart(ctx context.Context) {
	for _, s := range r.srcs {
		if !s.AfterStoreRestart {
			continue
		}
		if s.StartUnit != "" {
			// The record is still read: a oneshot that failed records its own
			// failed outcome, and a unit that did not start leaves the last one.
			if err := r.d.StartUnit(ctx, s.StartUnit); err != nil {
				r.d.Log.WarnContext(ctx, "os outcome unit did not start",
					"source", s.Kind, "path", s.Path, "unit", s.StartUnit, "err", err.Error())
			}
		}
		r.read(ctx, s)
	}
}

// read records one source's record.
func (r *Reader) read(ctx context.Context, s Source) {
	b, err := readCapped(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		r.d.Log.DebugContext(ctx, "os outcome record absent", "source", s.Kind, "path", s.Path)
		return
	}
	var rec Record
	if err == nil {
		rec, err = Parse(s, b)
	}
	if err != nil {
		r.unreadable(ctx, s, err)
		return
	}
	key := rec.BootID
	if s.KeyField == FieldRunID {
		key = rec.RunID
	}
	r.record(ctx, s, rec, key, s.Outcomes[rec.Outcome] == OK, nil)
}

// readCapped reads at most one byte past maxRecord, so an oversized record
// is refused by Parse without being read whole.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxRecord+1))
}

// unreadable records a record that exists but cannot be read, keyed to the
// api's own boot. With no boot id there is no key, and a key-less job would
// be recorded again on every start, so nothing is recorded.
func (r *Reader) unreadable(ctx context.Context, s Source, cause error) {
	bootID, err := r.d.BootID()
	if err != nil {
		r.d.Log.ErrorContext(ctx, "os outcome record unreadable and not recorded: the api's boot id is unreadable",
			"source", s.Kind, "path", s.Path, "err", cause.Error(), "boot_id_err", err.Error())
		return
	}
	rec := Record{
		Outcome: OutcomeUnreadable,
		BootID:  bootID,
		Reason:  fmt.Sprintf("The %s record at %s could not be read: %v.", s.Kind, s.Path, cause),
	}
	r.record(ctx, s, rec, bootID+"-unreadable", false, cause)
}

// record writes rec as one terminal job and logs what happened. cause is set
// for an unreadable record.
func (r *Reader) record(ctx context.Context, s Source, rec Record, key string, ok bool, cause error) {
	id := jobID(s.Kind, key, rec.Outcome)
	attrs := r.attrs(s, rec, id)
	if cause != nil {
		attrs = append(attrs, "err", cause.Error())
	}
	spec, err := json.Marshal(Spec{Source: s.Kind, Outcome: rec.Outcome, BootID: rec.BootID, RunID: rec.RunID,
		KeyID: rec.KeyID, Reason: rec.Reason, Path: s.Path})
	if err == nil {
		now := r.d.Now().UTC()
		j := &jobs.Job{ID: id, Kind: s.Kind, Spec: spec, Status: jobs.StatusSucceeded, CreatedBy: createdBy,
			CreatedAt: now, StartedAt: &now, FinishedAt: &now}
		if !ok {
			j.Status, j.Error = jobs.StatusFailed, rec.Reason
		}
		var inserted bool
		inserted, err = r.d.Ledger.RecordFinishedJob(ctx, j)
		if err == nil && !inserted {
			r.d.Log.DebugContext(ctx, "os outcome already recorded", attrs...)
			return
		}
	}
	if err != nil {
		// The outcome is in this line, so the journal still carries it. The
		// error goes no further: startup continues to READY, because holding
		// it back would take the cluster down over bookkeeping, and the
		// watchdog already probes the database.
		r.d.Log.ErrorContext(ctx, "os outcome not recorded: the job ledger refused it",
			append(attrs, "ledger_err", err.Error())...)
		return
	}
	switch {
	case cause != nil:
		r.d.Log.ErrorContext(ctx, "os outcome record unreadable", attrs...)
	case ok:
		r.d.Log.InfoContext(ctx, "os outcome recorded", attrs...)
	default:
		r.d.Log.ErrorContext(ctx, "os outcome recorded", attrs...)
	}
}

// attrs are the fields every line about rec carries: the declared fields
// only, so a line never shows a field the record does not have.
func (r *Reader) attrs(s Source, rec Record, id string) []any {
	a := []any{"source", s.Kind, "path", s.Path, "outcome", rec.Outcome, "job_id", id}
	if s.has(FieldBootID) || rec.Outcome == OutcomeUnreadable {
		a = append(a, "boot_id", rec.BootID)
	}
	if s.has(FieldRunID) {
		a = append(a, "run_id", rec.RunID)
	}
	if s.has(FieldKeyID) {
		a = append(a, "key_id", rec.KeyID)
	}
	if s.has(FieldReason) || rec.Outcome == OutcomeUnreadable {
		a = append(a, "reason", rec.Reason)
	}
	return a
}

// jobID is os- and the first 32 hex characters of sha256(kind, key,
// outcome), each NUL-terminated so no two triples share a preimage.
func jobID(kind, key, outcome string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + key + "\x00" + outcome + "\x00"))
	return "os-" + hex.EncodeToString(sum[:])[:32]
}
