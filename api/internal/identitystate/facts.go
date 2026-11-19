package identitystate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
)

// The facts the Monitor reads, as #973's unit hooks leave them (plan's
// Contract for #973, geekdojo/geekdojo-brain#979): the two units' systemd
// properties, one exit record per Keycloak invocation with a `last` pointer,
// the start hold's record and the version marker. Each adapter here reads
// files through an fs.FS rooted at "/", so a test can count what is opened.

// RunFunc runs a command and returns its combined output
// (execrun.CombinedOutput's shape).
type RunFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// Unit is one unit's systemd properties (sysunit.Unit).
type Unit = sysunit.Unit

// Units are Keycloak's unit and its database's.
type Units struct {
	KC, DB Unit
}

// SystemctlUnits reads both units' properties with one
// `systemctl show --property=ActiveState,SubState,InvocationID <kc> <db>`
// (sysunit.Show).
func SystemctlUnits(run RunFunc, kcUnit, dbUnit string) func(ctx context.Context) (Units, error) {
	return func(ctx context.Context) (Units, error) {
		u, err := sysunit.Show(ctx, run, kcUnit, dbUnit)
		if err != nil {
			return Units{}, err
		}
		return Units{KC: u[0], DB: u[1]}, nil
	}
}

// ParseUnits parses `systemctl show` output for two units (sysunit.ParseUnits),
// Keycloak's first.
func ParseUnits(out []byte) (Units, error) {
	u, err := sysunit.ParseUnits(out, 2)
	if err != nil {
		return Units{}, err
	}
	return Units{KC: u[0], DB: u[1]}, nil
}

// The pair's states, as unitrecover reads a unit's ActiveState.
const (
	PairFailed     = "failed"
	PairActivating = "activating"
	PairActive     = "active"
)

// PairState is the one state unitrecover reads for the identity pair
// (F-979-02): failed when the database is failed or Keycloak is not active,
// because a database that restarts by itself never starts a Keycloak left
// inactive; activating while the database is activating under an active
// Keycloak; active when both are.
func PairState(u Units) string {
	switch {
	case u.DB.ActiveState == "failed", u.KC.ActiveState != "active":
		return PairFailed
	case u.DB.ActiveState == "activating":
		return PairActivating
	case u.DB.ActiveState == "active":
		return PairActive
	}
	return u.DB.ActiveState
}

// PairStateOf reads units and returns PairState, for unitrecover's
// UnitState.
func PairStateOf(units func(context.Context) (Units, error)) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		u, err := units(ctx)
		if err != nil {
			return "", err
		}
		return PairState(u), nil
	}
}

// ExitKind is the job kind of an out-of-memory exit.
const ExitKind = "identity.service_exit"

// exitSource declares the exit record for osoutcome.Parse: outcome is
// systemd's $SERVICE_RESULT. It is never handed to an osoutcome.Reader,
// which reads one file per kind; this kind has one file per invocation.
var exitSource = osoutcome.Source{
	Kind:   ExitKind,
	Fields: []string{osoutcome.FieldInvocationID, osoutcome.FieldExitCode, osoutcome.FieldExitStatus},
	Outcomes: map[string]osoutcome.Verdict{
		"success": osoutcome.OK, "protocol": osoutcome.Alert, "timeout": osoutcome.Alert,
		"exit-code": osoutcome.Alert, "signal": osoutcome.Alert, "core-dump": osoutcome.Alert,
		"watchdog": osoutcome.Alert, "start-limit-hit": osoutcome.Alert, "resources": osoutcome.Alert,
		"oom-kill": osoutcome.Alert,
	},
}

// maxFile is the most the adapters read of any one file: osoutcome's record
// cap. A larger exit record is refused by Parse.
const maxFile = 4096

// lastName is the pointer to the newest complete exit record.
const lastName = "last"

// ExitRecord is one parsed exit record.
type ExitRecord struct {
	// ID is the invocation the record ends, which is also its file name.
	ID         string
	Outcome    string
	ExitCode   string
	ExitStatus string
	// Written is the record file's mtime.
	Written time.Time
}

// OutOfMemory reports whether the run ran out of memory: systemd's oom-kill,
// or the JVM's own -XX:+ExitOnOutOfMemoryError exit, status 3 (K-OOMEXIT).
func (r ExitRecord) OutOfMemory() bool {
	return r.Outcome == "oom-kill" || (r.ExitCode == "exited" && r.ExitStatus == "3")
}

// Success reports an orderly stop: kc.sh exits 143 on SIGTERM, which the unit
// lists in SuccessExitStatus=.
func (r ExitRecord) Success() bool { return r.Outcome == "success" }

// BadRecord is an exit record that exists and does not parse.
type BadRecord struct {
	Path string
	Err  error
}

// ExitDir is the exits directory as one reading found it.
type ExitDir struct {
	// Records are the complete records that parse, by ID.
	Records []ExitRecord
	// Last is the record `last` names, or nil when `last` is missing,
	// malformed, or names a record that is missing or does not parse.
	Last *ExitRecord
	// Bad are the records that do not parse.
	Bad []BadRecord
}

// rel is an absolute path as a path in an fs.FS rooted at "/".
func rel(p string) string { return strings.TrimPrefix(path.Clean(p), "/") }

// readCapped reads at most maxFile+1 bytes of name.
func readCapped(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(rel(name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxFile+1))
}

// ExitRecords lists dir and parses each exit record with osoutcome.Parse,
// then reads `last`. The listing comes first, so a record written after it is
// never taken for `last` without having been listed. A directory that does
// not exist holds no record (no stop yet this boot); any other listing error
// is an error.
func ExitRecords(fsys fs.FS, dir string) func(ctx context.Context) (ExitDir, error) {
	return func(context.Context) (ExitDir, error) {
		ents, err := fs.ReadDir(fsys, rel(dir))
		if errors.Is(err, fs.ErrNotExist) {
			return ExitDir{}, nil
		}
		if err != nil {
			return ExitDir{}, fmt.Errorf("listing the identity exit records: %w", err)
		}
		var d ExitDir
		for _, e := range ents {
			name := e.Name()
			if name == lastName || strings.HasSuffix(name, ".tmp") || e.IsDir() {
				continue
			}
			p := path.Join(dir, name)
			rec, err := readExitRecord(fsys, p, e)
			if err != nil {
				d.Bad = append(d.Bad, BadRecord{Path: p, Err: err})
				continue
			}
			d.Records = append(d.Records, rec)
		}
		sort.Slice(d.Records, func(i, j int) bool { return d.Records[i].ID < d.Records[j].ID })
		if id, ok := readLast(fsys, dir); ok {
			for i := range d.Records {
				if d.Records[i].ID == id {
					d.Last = &d.Records[i]
				}
			}
		}
		return d, nil
	}
}

// readExitRecord parses one record and checks that its invocation_id is its
// file name.
func readExitRecord(fsys fs.FS, p string, e fs.DirEntry) (ExitRecord, error) {
	info, err := e.Info()
	if err != nil {
		return ExitRecord{}, err
	}
	b, err := readCapped(fsys, p)
	if err != nil {
		return ExitRecord{}, err
	}
	rec, err := osoutcome.Parse(exitSource, b)
	if err != nil {
		return ExitRecord{}, err
	}
	if rec.InvocationID != path.Base(p) {
		return ExitRecord{}, errors.New("invocation_id is not the record's file name")
	}
	return ExitRecord{
		ID: rec.InvocationID, Outcome: rec.Outcome, ExitCode: rec.ExitCode, ExitStatus: rec.ExitStatus,
		Written: info.ModTime(),
	}, nil
}

// readLast is the ID `last` names: 32 lowercase hex characters, with or
// without a newline. Anything else is no `last`.
func readLast(fsys fs.FS, dir string) (string, bool) {
	b, err := readCapped(fsys, path.Join(dir, lastName))
	if err != nil {
		return "", false
	}
	id := strings.TrimSuffix(string(b), "\n")
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", false
	}
	return id, true
}

// RemoveExitRecord removes one consumed record from dir through remove
// (os.Remove), by its invocation ID. It never touches `last`.
func RemoveExitRecord(remove func(name string) error, dir string) func(ctx context.Context, id string) error {
	return func(_ context.Context, id string) error {
		if id == lastName || id == "" || strings.ContainsAny(id, "/.") {
			return fmt.Errorf("refusing to remove the exit record %q", id)
		}
		return remove(path.Join(dir, id))
	}
}

// StartHold is the start hold's record, which #973's ExecStartPre= writes
// when it refuses a start.
type StartHold struct {
	Refused bool
	Reason  string
}

// startHoldSource declares the start hold's record for osoutcome.Parse.
var startHoldSource = osoutcome.Source{
	Kind:     "identity.start_hold",
	Fields:   []string{osoutcome.FieldBootID, osoutcome.FieldReason},
	Outcomes: map[string]osoutcome.Verdict{"refused": osoutcome.Alert},
}

// StartHoldRecord reads the start hold's record at p. An absent record is no
// hold; one that does not parse is an error.
func StartHoldRecord(fsys fs.FS, p string) func(ctx context.Context) (StartHold, error) {
	return func(context.Context) (StartHold, error) {
		b, err := readCapped(fsys, p)
		if errors.Is(err, fs.ErrNotExist) {
			return StartHold{}, nil
		}
		if err != nil {
			return StartHold{}, fmt.Errorf("reading the start hold's record: %w", err)
		}
		rec, err := osoutcome.Parse(startHoldSource, b)
		if err != nil {
			return StartHold{}, fmt.Errorf("the start hold's record: %w", err)
		}
		return StartHold{Refused: true, Reason: rec.Reason}, nil
	}
}

// MarkerFile reads the version marker at p: the Keycloak version the version
// gate last let start, one line. A marker that is absent, empty or over
// maxFile bytes is an error.
func MarkerFile(fsys fs.FS, p string) func(ctx context.Context) (string, error) {
	return func(context.Context) (string, error) {
		b, err := readCapped(fsys, p)
		if err != nil {
			return "", fmt.Errorf("reading the version marker: %w", err)
		}
		if len(b) > maxFile {
			return "", errors.New("the version marker is over 4096 bytes")
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", errors.New("the version marker is empty")
		}
		return v, nil
	}
}
