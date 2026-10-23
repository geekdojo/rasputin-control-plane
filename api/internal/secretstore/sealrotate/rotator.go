// Package sealrotate rotates the secret store's seal key on demand and
// re-wraps the store's root key under the new key at once
// (geekdojo/geekdojo-brain#830; ADR-0010 S10).
//
// The seal key and its fragment are #803's files in /var/lib/rasputin/
// openbao-seal/. A new key is staged in rotation/<key id>, which
// openbao.service loads as the seal-rotation credential directory, and the
// fragment is the single commit point: each of its three shapes (Clean,
// Staged, Verify) names only key files whose bytes match their ids. One run
// is six steps:
//
//  1. validate: refuse, or take the backup capture gate, quiesce the store
//     and log in as the rotation role. Nothing is written.
//  2. stage: mint a key id and 32 bytes, write rotation/<new>, then the
//     Staged fragment (new current, old previous).
//  3. unseal_staged: restart the store and wait for sys/health to answer
//  200. A fresh run that gets no 200 rolls back to Clean: no re-wrap has
//     been sent, so the old key alone still opens the store.
//  4. rewrap: sys/rotate/root, so the root key is wrapped by the new key.
//     A failure keeps Staged and never restarts the store.
//  5. verify: write Verify (the new key alone), restart, wait for 200.
//  6. settle: copy the new key over seal-key, write Clean, restart, wait for
//     200, and empty rotation/.
//
// A run that finds any tree but a Clean, empty one finishes it and mints
// nothing; its outcome is "resumed", and a new rotation is a fresh run. A
// run that finds Staged with the store answering 200 re-wraps the running
// store first, because after a failed re-wrap only that store may hold a
// good keyring, and only then restarts it on Staged, re-wraps again and
// verifies. A run that finds Staged with the store down restarts it on
// Staged, then re-wraps and verifies.
//
// The seal key is only ever a secret.Value. Files.writeKey is the one place
// its bytes leave, into a 0600 file through atrest.
package sealrotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	// Kind is the rotation job's workflow kind. It has no scheduler entry:
	// an operator starts it through POST /api/jobs.
	Kind = "secretstore.seal_rotate"
	// RotationRole is the store's cert role for the rotation, created by the
	// store's self-init with the rasputin-seal-rotate policy (#804), and the
	// CommonName of the leaf the rotation client presents.
	RotationRole = "rasputin-seal-rotate"
	// UnsealWait bounds each wait for the store to answer 200 after a
	// restart. Its expiry leads to a rollback or a hold, never to carrying on
	// (timer-audit row K24).
	UnsealWait = 30 * time.Second

	// ioSlack bounds the non-waiting part of a step: file writes, a restart
	// command, a login and a re-wrap.
	ioSlack = time.Minute
)

// Config is the rotator's settings.
type Config struct {
	// Enabled is true only when the store backend is openbao. Otherwise every
	// run is refused at validate before any collaborator is called.
	Enabled bool
	// UnsealWait bounds each wait for a 200; production uses UnsealWait.
	UnsealWait time.Duration
}

// Store is the store call the rotator makes on the api's own client.
type Store interface {
	Health(ctx context.Context) (secretstore.Health, error)
}

// Rotate is the rotation role's client: its own login and the re-wrap.
type Rotate interface {
	CertLogin(ctx context.Context, role string) (secret.Value, error)
	RotateRoot(ctx context.Context, token secret.Value) error
}

// SealFiles is the seal directory, as Files serves it.
type SealFiles interface {
	State() (Tree, error)
	WriteRotationKey(id KeyID, key secret.Value) error
	WriteSealKey(key secret.Value) error
	ReadRotationKey(id KeyID) (secret.Value, error)
	WriteFragment(f Fragment) error
	RemoveRotation() error
}

// CaptureGate is the backup capture lock, as the rotation uses it.
type CaptureGate interface {
	TryAcquire(jobID string) error
	Release(jobID string)
	RotationHolder() string
}

// Restores reports a restore in progress.
type Restores interface {
	Active() (jobID string, active bool)
}

// Deps are the rotator's collaborators. None may be nil.
type Deps struct {
	Store  Store
	Rotate Rotate
	// Restart runs reset-failed and restart on the store's unit.
	Restart func(ctx context.Context) error
	Files   SealFiles
	Gate    CaptureGate
	// Quiesce holds the store quiesced for the job; the returned func ends
	// the hold.
	Quiesce  func(jobID string, reason storestate.QuiesceReason) (release func())
	Restores Restores
	// Rand is the key's randomness: crypto/rand.Reader.
	Rand io.Reader
	// KeyID makes a new key id: KernelKeyID.
	KeyID func() (KeyID, error)
	Log   *slog.Logger
	// JobRunning is the job ledger's running fact.
	JobRunning func(ctx context.Context, jobID string) (bool, error)
	// Now stamps when the incomplete-rotation alert was first seen.
	Now func() time.Time
}

// Rotator runs the rotation job and reports an incomplete one as an alert.
type Rotator struct {
	cfg Config
	d   Deps

	mu   sync.Mutex
	runs map[string]*run
	// since is when the incomplete-rotation alert was first raised, or zero.
	since time.Time
}

// run is one job's state between its steps. The runner runs a job's steps in
// order on one goroutine; mu guards the map, not the run.
type run struct {
	tree    Tree
	fresh   bool
	cur     KeyID // the new key once staged; the tree's current on a resume
	prev    KeyID // the key being replaced, when known
	token   secret.Value
	gated   bool
	release func()
	storeUp bool
}

// NewRotator checks cfg and d and returns a Rotator. It does no I/O.
func NewRotator(cfg Config, d Deps) (*Rotator, error) {
	switch {
	case d.Store == nil:
		return nil, errors.New("sealrotate: Deps.Store is nil")
	case d.Rotate == nil:
		return nil, errors.New("sealrotate: Deps.Rotate is nil")
	case d.Restart == nil:
		return nil, errors.New("sealrotate: Deps.Restart is nil")
	case d.Files == nil:
		return nil, errors.New("sealrotate: Deps.Files is nil")
	case d.Gate == nil:
		return nil, errors.New("sealrotate: Deps.Gate is nil")
	case d.Quiesce == nil:
		return nil, errors.New("sealrotate: Deps.Quiesce is nil")
	case d.Restores == nil:
		return nil, errors.New("sealrotate: Deps.Restores is nil")
	case d.Rand == nil:
		return nil, errors.New("sealrotate: Deps.Rand is nil")
	case d.KeyID == nil:
		return nil, errors.New("sealrotate: Deps.KeyID is nil")
	case d.Log == nil:
		return nil, errors.New("sealrotate: Deps.Log is nil")
	case d.JobRunning == nil:
		return nil, errors.New("sealrotate: Deps.JobRunning is nil")
	case d.Now == nil:
		return nil, errors.New("sealrotate: Deps.Now is nil")
	case cfg.UnsealWait <= 0:
		return nil, fmt.Errorf("sealrotate: Config.UnsealWait %s is not positive", cfg.UnsealWait)
	}
	return &Rotator{cfg: cfg, d: d, runs: map[string]*run{}}, nil
}

// Workflow is the rotation job. stage is Irreversible: it mints, so a replay
// is refused rather than minting a second key.
func (r *Rotator) Workflow() jobs.Workflow {
	w := r.cfg.UnsealWait
	return jobs.Workflow{Kind: Kind, Steps: []jobs.WorkflowStep{
		{Name: "validate", Do: r.validate, Timeout: ioSlack},
		{Name: "stage", Do: r.stage, Timeout: ioSlack, Irreversible: true},
		{Name: "unseal_staged", Do: r.unsealStaged, Timeout: 2*w + ioSlack},
		{Name: "rewrap", Do: r.rewrap, Timeout: ioSlack},
		{Name: "verify", Do: r.verify, Timeout: 3*w + ioSlack},
		{Name: "settle", Do: r.settle, Timeout: w + ioSlack},
	}, OnTerminal: r.onTerminal}
}

func (r *Rotator) get(jobID string) *run {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runs[jobID]
}

// log writes one record with the fields every record carries, and the same
// message to the job's step log. msg is safe text: ids, never key bytes.
func (r *Rotator) log(sc *jobs.StepCtx, level slog.Level, phase, msg string, ru *run, attrs ...any) {
	var cur, prev string
	if ru != nil {
		cur, prev = string(ru.cur), string(ru.prev)
	}
	base := []any{"component", "secretstore", "event", "secretstore.seal_rotate." + phase,
		"job_id", sc.JobID, "key_id", cur, "previous_key_id", prev}
	r.d.Log.Log(sc.Ctx, level, msg, append(base, attrs...)...)
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

// refuse logs one WARN and returns the refusal.
func (r *Rotator) refuse(sc *jobs.StepCtx, phase string, e jobError, ru *run, attrs ...any) error {
	r.log(sc, slog.LevelWarn, phase, "seal-key rotation refused", ru, append([]any{"reason", string(e)}, attrs...)...)
	return e
}

// fail logs one ERROR and returns the failure.
func (r *Rotator) fail(sc *jobs.StepCtx, phase string, e jobError, ru *run, attrs ...any) error {
	r.log(sc, slog.LevelError, phase, "seal-key rotation failed", ru, append([]any{"reason", string(e)}, attrs...)...)
	return e
}

// errAttrs is err's log attributes: a store error's fields, or its text.
func errAttrs(err error) []any {
	var se *secretstore.Error
	if errors.As(err, &se) {
		out := make([]any, 0, len(se.LogAttrs()))
		for _, a := range se.LogAttrs() {
			out = append(out, a)
		}
		return out
	}
	return []any{"err", err.Error()}
}

type validateResult struct {
	Resume string `json:"resume"`
	Shape  string `json:"shape"`
	KeyID  string `json:"key_id"`
}

// validate refuses, or takes the gate and the quiesce and proves the login.
// It writes nothing. A tree other than Clean resumes; a Staged or Verify tree
// may be resumed with the store down, because finishing it restarts the
// store.
func (r *Rotator) validate(sc *jobs.StepCtx) (json.RawMessage, error) {
	const phase = "validate"
	if !r.cfg.Enabled {
		return nil, r.refuse(sc, phase, errNotOpenBao, nil)
	}
	if id, active := r.d.Restores.Active(); active {
		return nil, r.refuse(sc, phase, errRestoreActive, nil, "restore_job_id", id)
	}
	tree, err := r.d.Files.State()
	if err != nil {
		return nil, r.refuse(sc, phase, errSealUnrecognised, nil, "err", err.Error())
	}
	ru := &run{tree: tree, fresh: tree.Resume == Fresh, cur: tree.Fragment.Current, prev: tree.Fragment.Previous}
	h, herr := r.d.Store.Health(sc.Ctx)
	kind := secretstore.InactiveReason(h, herr)
	ru.storeUp = kind == ""
	if !ru.storeUp && (tree.Resume == Fresh || tree.Resume == CleanUp) {
		return nil, r.refuse(sc, phase, errStoreNotReady, ru, "kind", kind)
	}
	if err := r.d.Gate.TryAcquire(sc.JobID); err != nil {
		var e jobError
		if !errors.As(err, &e) {
			e = errAnotherRotation
		}
		return nil, r.refuse(sc, phase, e, ru)
	}
	ru.gated = true
	ru.release = r.d.Quiesce(sc.JobID, storestate.QuiesceSealRotation)
	r.mu.Lock()
	r.runs[sc.JobID] = ru
	r.mu.Unlock()

	if ru.storeUp && (tree.Resume == Fresh || tree.Resume == RewrapFirst) {
		tok, err := r.d.Rotate.CertLogin(sc.Ctx, RotationRole)
		if err != nil {
			e := errLoginUnreachable
			if errors.Is(err, secretstore.ErrDenied) {
				e = errLoginDenied
			}
			return nil, r.refuse(sc, phase, e, ru, errAttrs(err)...)
		}
		ru.token = tok
	}
	if !ru.fresh {
		r.log(sc, slog.LevelInfo, phase, "an unfinished seal-key rotation will be finished; no new key is made", ru,
			"resume", tree.Resume.String(), "shape", tree.Fragment.Shape.String())
	}
	return json.Marshal(validateResult{Resume: tree.Resume.String(), Shape: tree.Fragment.Shape.String(), KeyID: string(tree.Fragment.Current)})
}

type stageResult struct {
	KeyID         string `json:"key_id"`
	PreviousKeyID string `json:"previous_key_id"`
}

// stage mints the key id and the key, then writes rotation/<new> and the
// Staged fragment. Both mints happen before any write, so a failure of
// either leaves nothing written (F-830-07). A resume skips it.
func (r *Rotator) stage(sc *jobs.StepCtx) (json.RawMessage, error) {
	const phase = "stage"
	ru := r.get(sc.JobID)
	if ru == nil || !ru.fresh {
		return nil, nil
	}
	newID, err := r.d.KeyID()
	if err != nil {
		return nil, r.refuse(sc, phase, errNoKeyID, ru, "err", err.Error())
	}
	if newID == ru.cur {
		return nil, r.refuse(sc, phase, errNoKeyID, ru, "err", "the new key id is the current one")
	}
	buf := make([]byte, KeyBytes)
	if _, err := io.ReadFull(r.d.Rand, buf); err != nil {
		clear(buf)
		return nil, r.refuse(sc, phase, errNoKey, ru, "err", err.Error())
	}
	key := secret.New(buf)
	clear(buf)
	defer key.Destroy()

	ru.prev, ru.cur = ru.cur, newID
	if err := r.d.Files.WriteRotationKey(newID, key); err != nil {
		return nil, r.stageFailed(sc, ru, err)
	}
	if err := r.d.Files.WriteFragment(Fragment{Shape: Staged, Current: newID, Previous: ru.prev}); err != nil {
		return nil, r.stageFailed(sc, ru, err)
	}
	r.log(sc, slog.LevelInfo, phase, "new seal key staged", ru)
	return json.Marshal(stageResult{KeyID: string(newID), PreviousKeyID: string(ru.prev)})
}

// stageFailed removes the staged key; the fragment's write is atomic, so a
// failed one left the old fragment.
func (r *Rotator) stageFailed(sc *jobs.StepCtx, ru *run, cause error) error {
	attrs := []any{"err", cause.Error()}
	if err := r.d.Files.RemoveRotation(); err != nil {
		attrs = append(attrs, "cleanup_err", err.Error())
	}
	return r.fail(sc, "stage", errStageWrite, ru, attrs...)
}

// unsealStaged restarts the store on the Staged fragment and waits for 200.
// A fresh run that gets none rolls back to Clean.
//
// A resume of a Staged tree restarts it too, so the rewrap step re-wraps a
// store that loaded Staged and verify opens first time (F-830-14). When the
// store answered 200 at validate, the running store is re-wrapped before
// that restart (F-830-16): after a re-wrap that failed part way only the
// running store may hold a good keyring, and a restart before it is
// repaired would leave a store that cannot open. A re-wrap under the old
// key alone is harmless, because the restart that follows still loads the
// old key as previous. A failure of that re-wrap keeps Staged and never
// restarts the store.
func (r *Rotator) unsealStaged(sc *jobs.StepCtx) (json.RawMessage, error) {
	const phase = "unseal_staged"
	ru := r.get(sc.JobID)
	if ru == nil {
		return nil, nil
	}
	switch {
	case ru.fresh:
	case ru.tree.Resume == RewrapFirst:
		if ru.storeUp {
			if err := r.rotateRoot(sc.Ctx, ru); err != nil {
				return nil, r.rewrapFailed(sc, phase, ru, err)
			}
			r.log(sc, slog.LevelInfo, phase, "running secret store re-wrapped before its restart under the staged key", ru)
		}
		if err := r.restartAndWait(sc.Ctx); err != nil {
			return nil, r.fail(sc, phase, errStagedResume, ru, "err", err.Error())
		}
		return nil, nil
	default:
		return nil, nil
	}
	err := r.restartAndWait(sc.Ctx)
	if err == nil {
		r.log(sc, slog.LevelInfo, phase, "secret store open with the new seal key staged", ru)
		return nil, nil
	}
	// No re-wrap has been sent, so the old key alone still opens the store.
	attrs := []any{"err", err.Error()}
	if werr := r.d.Files.WriteFragment(Fragment{Shape: Clean, Current: ru.prev}); werr != nil {
		return nil, r.fail(sc, phase, errStagedRollbackFailed, ru, append(attrs, "rollback_err", werr.Error())...)
	}
	if rerr := r.d.Restart(sc.Ctx); rerr != nil {
		attrs = append(attrs, "restart_err", rerr.Error())
	}
	if rerr := r.d.Files.RemoveRotation(); rerr != nil {
		attrs = append(attrs, "cleanup_err", rerr.Error())
	}
	return nil, r.fail(sc, phase, errStagedRolledBack, ru, attrs...)
}

// rewrap re-wraps the root key under the new key. A failure keeps Staged and
// never restarts the store.
func (r *Rotator) rewrap(sc *jobs.StepCtx) (json.RawMessage, error) {
	const phase = "rewrap"
	ru := r.get(sc.JobID)
	if ru == nil || !(ru.fresh || ru.tree.Resume == RewrapFirst) {
		return nil, nil
	}
	if err := r.rotateRoot(sc.Ctx, ru); err != nil {
		return nil, r.rewrapFailed(sc, phase, ru, err)
	}
	r.log(sc, slog.LevelInfo, phase, "root key re-wrapped under the new seal key", ru)
	return nil, nil
}

// rewrapFailed logs one ERROR for a failed re-wrap and returns its sentence.
// The caller keeps Staged and does not restart the store.
func (r *Rotator) rewrapFailed(sc *jobs.StepCtx, phase string, ru *run, err error) error {
	e := errRewrap
	if errors.Is(err, errLoginFailed) {
		e = errRewrapLogin
	}
	return r.fail(sc, phase, e, ru, errAttrs(err)...)
}

// errLoginFailed marks a re-wrap that never reached sys/rotate/root.
var errLoginFailed = errors.New("sealrotate: rotation login failed")

// rotateRoot logs in when the run holds no token yet (a resume whose store
// was down at validate), then re-wraps.
func (r *Rotator) rotateRoot(ctx context.Context, ru *run) error {
	if ru.token.Len() == 0 {
		tok, err := r.d.Rotate.CertLogin(ctx, RotationRole)
		if err != nil {
			return fmt.Errorf("%w: %w", errLoginFailed, err)
		}
		ru.token = tok
	}
	return r.d.Rotate.RotateRoot(ctx, ru.token)
}

// verify writes Verify, restarts and waits for 200. When the store does not
// open and the old key is known, Staged is put back, the store re-wrapped,
// and Verify tried once more.
func (r *Rotator) verify(sc *jobs.StepCtx) (json.RawMessage, error) {
	const phase = "verify"
	ru := r.get(sc.JobID)
	if ru == nil || ru.tree.Resume == CleanUp {
		return nil, nil
	}
	err := r.writeAndOpen(sc.Ctx, Fragment{Shape: Verify, Current: ru.cur})
	if err == nil {
		r.log(sc, slog.LevelInfo, phase, "secret store open with the new seal key alone", ru)
		return nil, nil
	}
	if ru.prev == "" {
		return nil, r.fail(sc, phase, errVerify, ru, "err", err.Error())
	}
	r.log(sc, slog.LevelWarn, phase, "secret store did not open with the new seal key alone; re-wrapping and trying once more", ru, "err", err.Error())
	retry := r.writeAndOpen(sc.Ctx, Fragment{Shape: Staged, Current: ru.cur, Previous: ru.prev})
	if retry == nil {
		retry = r.rotateRoot(sc.Ctx, ru)
	}
	if retry == nil {
		retry = r.writeAndOpen(sc.Ctx, Fragment{Shape: Verify, Current: ru.cur})
	}
	if retry != nil {
		return nil, r.fail(sc, phase, errVerify, ru, "err", err.Error(), "retry_err", retry.Error())
	}
	r.log(sc, slog.LevelInfo, phase, "secret store open with the new seal key alone", ru)
	return nil, nil
}

type settleResult struct {
	Outcome       string `json:"outcome"`
	KeyID         string `json:"key_id"`
	PreviousKeyID string `json:"previous_key_id,omitempty"`
}

// settle makes the new key the only key: seal-key gets its bytes, the
// fragment goes back to Clean, the store is restarted, and rotation/ is
// emptied. A Clean tree with leftovers only has them removed.
func (r *Rotator) settle(sc *jobs.StepCtx) (json.RawMessage, error) {
	const phase = "settle"
	ru := r.get(sc.JobID)
	if ru == nil {
		return nil, nil
	}
	if ru.tree.Resume != CleanUp {
		if err := r.makeOnlyKey(sc.Ctx, ru.cur); err != nil {
			return nil, r.fail(sc, phase, errSettle, ru, "err", err.Error())
		}
	}
	if err := r.d.Files.RemoveRotation(); err != nil {
		return nil, r.fail(sc, phase, errSettle, ru, "err", err.Error())
	}
	res := settleResult{Outcome: "rotated", KeyID: string(ru.cur), PreviousKeyID: string(ru.prev)}
	if ru.fresh {
		r.log(sc, slog.LevelInfo, phase, "seal key rotated", ru)
	} else {
		res.Outcome = "resumed"
		r.log(sc, slog.LevelInfo, phase,
			"A seal-key rotation that had stopped was finished. No new key was made; start the rotation again for a new key.", ru)
	}
	return json.Marshal(res)
}

// makeOnlyKey copies rotation/<id> over seal-key, writes Clean and opens the
// store on it. The key read back is destroyed once written.
func (r *Rotator) makeOnlyKey(ctx context.Context, id KeyID) error {
	key, err := r.d.Files.ReadRotationKey(id)
	if err != nil {
		return err
	}
	err = r.d.Files.WriteSealKey(key)
	key.Destroy()
	if err != nil {
		return err
	}
	return r.writeAndOpen(ctx, Fragment{Shape: Clean, Current: id})
}

// writeAndOpen writes f, restarts the store and waits for 200.
func (r *Rotator) writeAndOpen(ctx context.Context, f Fragment) error {
	if err := r.d.Files.WriteFragment(f); err != nil {
		return err
	}
	return r.restartAndWait(ctx)
}

// restartAndWait restarts the store and waits for 200.
func (r *Rotator) restartAndWait(ctx context.Context) error {
	if err := r.d.Restart(ctx); err != nil {
		return fmt.Errorf("restart the secret store: %w", err)
	}
	return r.waitReady(ctx)
}

// waitReady returns once sys/health answers 200, or UnsealWait's error.
func (r *Rotator) waitReady(ctx context.Context) error {
	return secretstore.WaitReady(ctx, r.d.Store, r.cfg.UnsealWait)
}

// onTerminal releases what validate took: the gate, the quiesce and the
// token. It is idempotent.
func (r *Rotator) onTerminal(_ context.Context, jobID string, _ bool, _ string) {
	r.mu.Lock()
	ru := r.runs[jobID]
	delete(r.runs, jobID)
	r.mu.Unlock()
	if ru == nil {
		return
	}
	if ru.gated {
		r.d.Gate.Release(jobID)
	}
	if ru.release != nil {
		ru.release()
	}
	ru.token.Destroy()
}
