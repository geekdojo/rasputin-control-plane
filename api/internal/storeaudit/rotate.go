// Package storeaudit keeps the secret store's audit file bounded (ADR-0010
// S11; geekdojo/geekdojo-brain#799). It rotates the file when it passes a
// size, trims the rotated copies to a byte cap, and reports low free space on
// the data partition as an alert.
//
// The rotation is a Rasputin job, never copytruncate: the store appends
// through an O_APPEND descriptor it keeps open, so anything written between a
// copy and a truncate would be lost. Instead the live file gets a second name
// (a hard link, which never replaces anything), its old name is removed, and
// the store is told to reopen with SIGHUP. The store keeps writing to the same
// inode, now named as the copy, until it reopens, and the reopen creates a new
// file at the live path. The rotator waits for that fact, a regular file at
// the live path with another inode, and rolls the rename back when it does not
// come.
//
// Copies are named audit.log.<n>, where n is one more than the highest number
// already there. The number comes from the names, never from the clock, which
// can sit at its floor at boot.
package storeaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

const (
	// RotateKind is the rotation job's workflow kind.
	RotateKind = "secretstore.audit_rotate"
	// DirName is the audit directory under the api's data dir. The store owns
	// it; #804's audit stanza writes LiveName in it.
	DirName = "openbao-audit"
	// LiveName is the file the store appends to.
	LiveName = "audit.log"

	// RotateAt is the size at which the live file is rotated, and KeepBytes the
	// most the rotated copies may total, so the audit uses about 512 MiB in
	// all. They mirror the image's journald SystemMaxFileSize=64M and
	// SystemMaxUse=512M: bounded in bytes, so the partition's size does not
	// change them, and a trim removes at most one 64 MiB copy at a time
	// (ADR-0010 S11).
	RotateAt int64 = 64 << 20
	// KeepBytes: see RotateAt.
	KeepBytes int64 = 448 << 20
	// ReopenWait bounds the wait for the store to reopen after the signal.
	// Expiry rolls the rename back; it is timer-audit row K23.
	ReopenWait = 30 * time.Second

	// rotateTimeout bounds the rotate step. It must exceed ReopenWait, so the
	// wait's own expiry, not the step's, decides a missed reopen, and the
	// rollback still has time to run.
	rotateTimeout = time.Minute
	// pruneTimeout bounds the prune step: a directory listing and a few
	// removes.
	pruneTimeout = 30 * time.Second
	// reopenRecheck is how often the wait re-checks the live path. It decides
	// nothing: the wait ends on the new inode or on ReopenWait.
	reopenRecheck = 50 * time.Millisecond
)

// copyName matches a rotated copy and captures its number. Anything else in
// the directory is never touched or counted.
var copyName = regexp.MustCompile(`^audit\.log\.(\d{1,19})$`)

// Config is the rotator's settings. Production uses Defaults.
type Config struct {
	// Dir is the audit directory, <dataDir>/openbao-audit.
	Dir string
	// RotateAt is the live file's rotation threshold, in bytes.
	RotateAt int64
	// KeepBytes caps the rotated copies' total, in bytes.
	KeepBytes int64
	// ReopenWait bounds the wait for the store's reopen.
	ReopenWait time.Duration
}

// Defaults is the production Config for the audit directory under dataDir.
func Defaults(dataDir string) Config {
	return Config{Dir: filepath.Join(dataDir, DirName), RotateAt: RotateAt, KeepBytes: KeepBytes, ReopenWait: ReopenWait}
}

// Store is the one store call the rotator makes: is the store active?
type Store interface {
	Health(ctx context.Context) (secretstore.Health, error)
}

// Deps are the rotator's collaborators. None may be nil.
type Deps struct {
	Store  Store
	Reopen Reopener
	Files  Files
	Log    *slog.Logger
}

// Rotator rotates and prunes the audit file. Its memory of failures is
// in-process and resets when the api restarts.
type Rotator struct {
	cfg   Config
	store Store
	open  Reopener
	files Files
	log   *slog.Logger

	// run serialises the steps, so two jobs never rename at once.
	run sync.Mutex

	// mu guards the failure memory below, which Due reads on the scheduler's
	// goroutine.
	mu sync.Mutex
	// failedRotate is the live file's inode and size when a rotation of it
	// last failed, or nil.
	failedRotate *rotateFailure
	// failedPrune is the copy set's signature when a prune of it last failed,
	// or "".
	failedPrune string
}

type rotateFailure struct {
	inode uint64
	size  int64
}

// NewRotator checks cfg and deps and returns a Rotator. It does no I/O.
func NewRotator(cfg Config, d Deps) (*Rotator, error) {
	switch {
	case d.Store == nil:
		return nil, errors.New("storeaudit: Deps.Store is nil")
	case d.Reopen == nil:
		return nil, errors.New("storeaudit: Deps.Reopen is nil")
	case d.Files == nil:
		return nil, errors.New("storeaudit: Deps.Files is nil")
	case d.Log == nil:
		return nil, errors.New("storeaudit: Deps.Log is nil")
	case cfg.Dir == "":
		return nil, errors.New("storeaudit: Config.Dir is empty")
	case cfg.RotateAt <= 0:
		return nil, fmt.Errorf("storeaudit: Config.RotateAt %d is not positive", cfg.RotateAt)
	case cfg.KeepBytes < cfg.RotateAt:
		return nil, fmt.Errorf("storeaudit: Config.KeepBytes %d is below RotateAt %d", cfg.KeepBytes, cfg.RotateAt)
	case cfg.ReopenWait <= 0 || cfg.ReopenWait >= rotateTimeout:
		return nil, fmt.Errorf("storeaudit: Config.ReopenWait %s is not between 0 and the step's %s", cfg.ReopenWait, rotateTimeout)
	}
	return &Rotator{
		cfg: cfg, store: d.Store, open: d.Reopen, files: d.Files,
		log: d.Log.With("component", "storeaudit"),
	}, nil
}

func (r *Rotator) live() string { return filepath.Join(r.cfg.Dir, LiveName) }

// Workflow is the rotation job: rotate, then prune.
func (r *Rotator) Workflow() jobs.Workflow {
	return jobs.Workflow{Kind: RotateKind, Steps: []jobs.WorkflowStep{
		{Name: "rotate", Do: r.rotateStep, Timeout: rotateTimeout},
		{Name: "prune", Do: r.pruneStep, Timeout: pruneTimeout},
	}}
}

// Due is the scheduler's gate. It is true when the live file is at or past
// RotateAt, or when the copies are over KeepBytes and a prune could remove
// one. A failure is retried only on a fact the job can act on: the live
// file's inode changed or it grew by RotateAt since the failed rotation, or
// the copy set changed since the failed prune. A file or directory that does
// not exist (a cluster before #804) is false with no reason, so nothing is
// logged; any other error reading them is false with a reason and one WARN.
func (r *Rotator) Due(ctx context.Context) (bool, string) {
	live := r.live()
	fi, err := r.files.Stat(live)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		r.log.WarnContext(ctx, "audit file could not be read; no rotation submitted", "file", live, "err", err.Error())
		return false, "the audit file could not be read"
	case fi.Mode().IsRegular() && fi.Size() >= r.cfg.RotateAt && r.rotateRetryAllowed(fi):
		return true, fmt.Sprintf("the audit file is %d bytes", fi.Size())
	}

	copies, err := r.listCopies()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, ""
	case err != nil:
		r.log.WarnContext(ctx, "audit directory could not be listed; no prune submitted", "file", r.cfg.Dir, "err", err.Error())
		return false, "the audit directory could not be listed"
	}
	if len(planPrune(copies, r.cfg.KeepBytes)) == 0 {
		return false, ""
	}
	r.mu.Lock()
	failed := r.failedPrune
	r.mu.Unlock()
	if failed != "" && failed == signature(copies) {
		return false, ""
	}
	return true, "the rotated audit copies are over their cap"
}

// rotateRetryAllowed is false only while the live file is the one whose
// rotation failed and it has grown by less than RotateAt since.
func (r *Rotator) rotateRetryAllowed(fi fs.FileInfo) bool {
	r.mu.Lock()
	f := r.failedRotate
	r.mu.Unlock()
	if f == nil {
		return true
	}
	ino, ok := inodeOf(fi)
	if !ok || ino != f.inode {
		return true
	}
	return fi.Size() >= f.size+r.cfg.RotateAt
}

// stepLog writes one event to both pipelines: the job's step log, which a
// person reads on the Tasks page and so carries only safe text, and the
// injected logger, which carries the fields an operator acts on.
func (r *Rotator) stepLog(sc *jobs.StepCtx, level slog.Level, msg string, attrs ...any) {
	r.log.Log(sc.Ctx, level, msg, append([]any{"job_id", sc.JobID}, attrs...)...)
	if sc.Log == nil {
		return
	}
	lvl := "info"
	switch {
	case level >= slog.LevelError:
		lvl = "error"
	case level >= slog.LevelWarn:
		lvl = "warn"
	}
	sc.Log(lvl, msg)
}

// fail logs an ERROR carrying the internal detail and returns the sentence
// the job records.
func (r *Rotator) fail(sc *jobs.StepCtx, e jobError, msg string, attrs ...any) error {
	r.stepLog(sc, slog.LevelError, msg, attrs...)
	return e
}

func (r *Rotator) rotateStep(sc *jobs.StepCtx) (json.RawMessage, error) {
	r.run.Lock()
	defer r.run.Unlock()

	// A sealed store has no audit reload to run, so a rename now would leave
	// it appending to the copy with nothing to reopen it.
	h, err := r.store.Health(sc.Ctx)
	if kind := inactiveKind(h, err); kind != "" {
		r.stepLog(sc, slog.LevelWarn, "secret store not active; audit file not rotated", "kind", kind)
		return nil, jobs.ErrStopWorkflow
	}

	live := r.live()
	fi, err := r.files.Stat(live)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, r.fail(sc, errNotChecked, "audit file could not be read", "file", live, "err", err.Error())
	}
	if !fi.Mode().IsRegular() || fi.Size() < r.cfg.RotateAt {
		return nil, nil
	}
	ino, ok := inodeOf(fi)
	if !ok {
		return nil, r.fail(sc, errNotChecked, "audit file has no inode to follow", "file", live)
	}
	copies, err := r.listCopies()
	if err != nil {
		return nil, r.fail(sc, errNotChecked, "audit directory could not be listed", "file", r.cfg.Dir, "err", err.Error())
	}
	seq := nextSeq(copies)
	cp := filepath.Join(r.cfg.Dir, LiveName+"."+strconv.FormatUint(seq, 10))

	if err := r.files.Link(live, cp); err != nil {
		return nil, r.fail(sc, errNotMoved, "audit file could not be linked aside", "file", live, "copy", cp, "err", err.Error())
	}
	if err := r.files.Remove(live); err != nil {
		attrs := []any{"file", live, "copy", cp, "err", err.Error()}
		if uerr := r.files.Remove(cp); uerr != nil {
			attrs = append(attrs, "undo_err", uerr.Error())
		}
		return nil, r.fail(sc, errNotMoved, "audit file's old name could not be removed; the link was undone", attrs...)
	}

	reopenErr := r.open.Reopen(sc.Ctx)
	if reopenErr == nil {
		reopenErr = r.waitReopen(sc.Ctx, ino)
	}
	if reopenErr == nil {
		r.forgetRotate()
		r.stepLog(sc, slog.LevelInfo, "audit file rotated", "copy", filepath.Base(cp), "bytes", fi.Size(), "seq", seq)
		return nil, nil
	}
	return nil, r.rollback(sc, live, cp, ino, fi.Size(), seq, reopenErr)
}

// rollback puts the copy back at the live path after a failed signal or
// wait. A link that finds the live path taken means the store did reopen,
// late: the rotation stands.
func (r *Rotator) rollback(sc *jobs.StepCtx, live, cp string, ino uint64, size int64, seq uint64, cause error) error {
	err := r.files.Link(cp, live)
	if errors.Is(err, fs.ErrExist) {
		r.forgetRotate()
		r.stepLog(sc, slog.LevelWarn, "secret store reopened its audit file after the wait; rotation kept",
			"copy", filepath.Base(cp), "bytes", size, "seq", seq, "err", cause.Error())
		return nil
	}
	if err != nil {
		r.rememberRotate(ino, size)
		return r.fail(sc, errRollbackFailed, "audit rotation could not be rolled back; the store is writing to the copy",
			"file", live, "copy", cp, "err", cause.Error(), "rollback_err", err.Error())
	}
	attrs := []any{"file", live, "copy", cp, "err", cause.Error()}
	if rerr := r.files.Remove(cp); rerr != nil {
		attrs = append(attrs, "leftover_copy_err", rerr.Error())
	}
	if after, serr := r.files.Stat(live); serr == nil {
		size = after.Size()
	}
	r.rememberRotate(ino, size)
	return r.fail(sc, errRolledBack, "secret store did not reopen its audit file; rotation rolled back", attrs...)
}

// waitReopen returns once a regular file other than the copy's inode is at the
// live path, or ReopenWait's error.
func (r *Rotator) waitReopen(ctx context.Context, copyIno uint64) error {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.ReopenWait)
	defer cancel()
	t := time.NewTicker(reopenRecheck)
	defer t.Stop()
	for {
		if fi, err := r.files.Stat(r.live()); err == nil && fi.Mode().IsRegular() {
			if ino, ok := inodeOf(fi); ok && ino != copyIno {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("storeaudit: no new audit file after %s: %w", r.cfg.ReopenWait, ctx.Err())
		case <-t.C:
		}
	}
}

func (r *Rotator) rememberRotate(ino uint64, size int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failedRotate = &rotateFailure{inode: ino, size: size}
}

func (r *Rotator) forgetRotate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failedRotate = nil
}

func (r *Rotator) pruneStep(sc *jobs.StepCtx) (json.RawMessage, error) {
	r.run.Lock()
	defer r.run.Unlock()

	copies, err := r.listCopies()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, r.fail(sc, errListFailed, "audit directory could not be listed", "file", r.cfg.Dir, "err", err.Error())
	}
	doomed := planPrune(copies, r.cfg.KeepBytes)
	var freed int64
	for i, c := range doomed {
		path := filepath.Join(r.cfg.Dir, c.name)
		if err := r.files.Remove(path); err != nil {
			left := append(append([]auditCopy{}, doomed[i:]...), copies[len(doomed):]...)
			r.mu.Lock()
			r.failedPrune = signature(left)
			r.mu.Unlock()
			return nil, r.fail(sc, errPruneFailed, "rotated audit copy could not be removed",
				"file", path, "removed", i, "err", err.Error())
		}
		freed += c.size
	}
	r.mu.Lock()
	r.failedPrune = ""
	r.mu.Unlock()
	if len(doomed) > 0 {
		r.stepLog(sc, slog.LevelInfo, "rotated audit copies removed", "removed", len(doomed), "bytes", freed)
	}
	return nil, nil
}

// auditCopy is one rotated copy.
type auditCopy struct {
	name string
	seq  uint64
	size int64
}

// listCopies returns the rotated copies in ascending numeric order. Names
// that do not match copyName are skipped.
func (r *Rotator) listCopies() ([]auditCopy, error) {
	entries, err := r.files.ReadDir(r.cfg.Dir)
	if err != nil {
		return nil, err
	}
	var out []auditCopy
	for _, e := range entries {
		m := copyName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		seq, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			continue // 19 digits past MaxUint64 is no copy this rotator made
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		out = append(out, auditCopy{name: e.Name(), seq: seq, size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out, nil
}

// nextSeq is one more than the highest copy number, or 1.
func nextSeq(copies []auditCopy) uint64 {
	if len(copies) == 0 {
		return 1
	}
	return copies[len(copies)-1].seq + 1
}

// planPrune picks the copies to remove, oldest first, until the rest total
// keep or less. The newest copy is always kept. copies is in ascending order.
func planPrune(copies []auditCopy, keep int64) []auditCopy {
	var total int64
	for _, c := range copies {
		total += c.size
	}
	n := 0
	for n < len(copies)-1 && total > keep {
		total -= copies[n].size
		n++
	}
	return copies[:n]
}

// signature identifies a copy set by its names and sizes.
func signature(copies []auditCopy) string {
	var b strings.Builder
	for _, c := range copies {
		fmt.Fprintf(&b, "%s=%d;", c.name, c.size)
	}
	return b.String()
}

// inactiveKind names why the store is not active, or "" when it is
// initialised and unsealed.
func inactiveKind(h secretstore.Health, err error) string {
	switch {
	case errors.Is(err, secretstore.ErrSealed):
		return "sealed"
	case errors.Is(err, secretstore.ErrUninitialised):
		return "uninitialised"
	case errors.Is(err, secretstore.ErrUnreachable):
		return "unreachable"
	case errors.Is(err, secretstore.ErrDisabled):
		return "disabled"
	case err != nil:
		return "error"
	case !h.Initialized:
		return "uninitialised"
	case h.Sealed:
		return "sealed"
	}
	return ""
}
