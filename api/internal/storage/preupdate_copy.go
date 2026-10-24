package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
)

// The secret store's copy before an OS update (geekdojo/geekdojo-brain#800).
//
// A store binary may not open data a newer release wrote, so an update that
// moves the store's data forward is one-way. Before node.update installs on
// the store's host, the copier takes a cold copy of the store's data, in the
// same layout as the backup's staged store tar (store/data/<rel> and
// store/openbao-version), and publishes it at one path. A fallback to the
// slot the update left puts that copy back (#801). The previous copy is only
// ever replaced by a complete new one: the new copy is staged beside it and
// renamed over it once the store has started again and answered ready. The
// copy lives until the api commits the update that took it: RetireCopy
// deletes it then, so a fallback after the commit finds no copy and the
// rollback gate refuses rather than putting old data back (#873).

// UpdateLock is the capture lock as the pre-update copy takes it (ARCH-ISP):
// sealrotate.Gate, whose refusals name the OS update.
type UpdateLock interface {
	// AcquireForUpdate waits for the lock and takes it for jobID, or refuses
	// with an error whose text is a sentence, or returns ctx's error.
	AcquireForUpdate(ctx context.Context, jobID string) error
	// Release frees the lock when jobID holds it; it is idempotent.
	Release(jobID string)
}

// PreUpdateCopierDeps is everything a PreUpdateCopier needs.
// NewPreUpdateCopier refuses a nil or empty one.
type PreUpdateCopierDeps struct {
	// Store is the running store, quiescing for an OS update.
	Store SecretStore
	Lock  UpdateLock
	// DataDir is the store's data directory; CopyPath is where the copy is
	// published.
	DataDir  string
	CopyPath string
	Log      *slog.Logger
}

// PreUpdateCopier copies the store before an OS update of its host.
type PreUpdateCopier struct {
	store    SecretStore
	lock     UpdateLock
	dataDir  string
	copyPath string
	log      *slog.Logger
}

// NewPreUpdateCopier checks d and returns a copier. It does no I/O.
func NewPreUpdateCopier(d PreUpdateCopierDeps) (*PreUpdateCopier, error) {
	switch {
	case d.Store == nil:
		return nil, errors.New("storage: NewPreUpdateCopier: Deps.Store is nil")
	case d.Lock == nil:
		return nil, errors.New("storage: NewPreUpdateCopier: Deps.Lock is nil")
	case strings.TrimSpace(d.DataDir) == "":
		return nil, errors.New("storage: NewPreUpdateCopier: Deps.DataDir is empty")
	case strings.TrimSpace(d.CopyPath) == "":
		return nil, errors.New("storage: NewPreUpdateCopier: Deps.CopyPath is empty")
	case d.Log == nil:
		return nil, errors.New("storage: NewPreUpdateCopier: Deps.Log is nil")
	}
	return &PreUpdateCopier{store: d.Store, lock: d.Lock, dataDir: d.DataDir, copyPath: d.CopyPath, log: d.Log}, nil
}

// preUpdateCopyResult is the copy_store step's result: counts and the
// version, nothing from the data.
type preUpdateCopyResult struct {
	Copied    bool   `json:"copied"`
	Version   string `json:"version"`
	Files     int    `json:"files"`
	SizeBytes uint64 `json:"sizeBytes"`
}

// The copier's refusals. Each opens with the sentence every OS update
// refusal for the store shares, and carries no path or store text
// (ERR-MESSAGE); the cause goes to the job feed and the log.
const (
	errUpdateLockWait         = sentenceError(sealrotate.UpdateCopyRefused + " The update waited for a backup or a seal-key rotation to finish and ran out of time.")
	errUpdateReadinessUnknown = sentenceError(sealrotate.UpdateCopyRefused + " The store's readiness could not be read; run the update again once the store is ready.")
	errUpdateVersionUnknown   = sentenceError(sealrotate.UpdateCopyRefused + " The store's version could not be read; run the update again once the store is ready.")
	errUpdatePrepareFailed    = sentenceError(sealrotate.UpdateCopyRefused + " The copy's file could not be prepared; the api log names the cause.")
	errUpdateStopFailed       = sentenceError(sealrotate.UpdateCopyRefused + " The store could not be stopped for its copy; it was started again, and the job feed names the cause.")
	errUpdateCopyFailed       = sentenceError(sealrotate.UpdateCopyRefused + " The store's data could not be copied; the store was started again, and the job feed names the cause.")
	errUpdateStartFailed      = sentenceError(sealrotate.UpdateCopyRefused + " The store did not come back after its copy; its own unit keeps restarting it, and the secret store alert says when it is back.")
	errUpdatePublishFailed    = sentenceError(sealrotate.UpdateCopyRefused + " The copy could not be saved; the job feed names the cause.")
)

// updateStoreNotReady is the refusal for a store whose readiness names a
// state.
func updateStoreNotReady(clause string) error {
	return sentenceError(sealrotate.UpdateCopyRefused + " The secret store " + clause + "; run the update again once it is ready.")
}

// CopyBeforeUpdate takes the capture lock for sc's job, checks the store is
// ready and reads its version, takes the cold copy, and publishes it once
// the store is ready again. It fails closed: any refusal leaves the previous
// copy byte-identical and no staged file behind, the lock is released on
// every path, and coldCopy starts a store it stopped.
func (c *PreUpdateCopier) CopyBeforeUpdate(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := jobs.ContextWithJobID(sc.Ctx, sc.JobID)
	if err := c.lock.AcquireForUpdate(sc.Ctx, sc.JobID); err != nil {
		if sc.Ctx.Err() != nil {
			return nil, c.refuse(ctx, sc, "lock", err, errUpdateLockWait)
		}
		return nil, c.refuse(ctx, sc, "lock", err, err)
	}
	defer c.lock.Release(sc.JobID)

	notReady, err := c.store.Readiness(sc.Ctx)
	if err != nil {
		return nil, c.refuse(ctx, sc, "readiness", err, errUpdateReadinessUnknown)
	}
	if notReady != "" {
		return nil, c.refuse(ctx, sc, "readiness", errors.New("the store is not ready"), updateStoreNotReady(notReady))
	}
	version, err := c.store.Version(sc.Ctx)
	if err == nil && (strings.TrimSpace(version) == "" || len(version) > storeCaptureVersionLimit) {
		err = fmt.Errorf("the store reported an unusable version of %d byte(s)", len(version))
	}
	if err != nil {
		return nil, c.refuse(ctx, sc, "version", err, errUpdateVersionUnknown)
	}

	partial := c.copyPath + ".partial"
	// stageStoreCapture creates its file exclusively, so a leftover from a
	// crashed copy would block every later one.
	if err := os.Remove(partial); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, c.refuse(ctx, sc, "prepare", err, errUpdatePrepareFailed)
	}
	files, size, stage, err := coldCopy(sc, c.store, partial, c.dataDir, version)
	switch stage {
	case coldCopyStop:
		return nil, c.refuse(ctx, sc, string(stage), err, errUpdateStopFailed)
	case coldCopyCopy:
		return nil, c.refuse(ctx, sc, string(stage), err, errUpdateCopyFailed)
	case coldCopyStart, coldCopyReady:
		return nil, c.refuse(ctx, sc, string(stage), err, errUpdateStartFailed)
	}
	if err := publishCopy(partial, c.copyPath); err != nil {
		_ = os.Remove(partial)
		sc.Log("error", fmt.Sprintf("saving the secret store's copy failed: %v", err))
		return nil, c.refuse(ctx, sc, "publish", err, errUpdatePublishFailed)
	}
	c.log.LogAttrs(ctx, slog.LevelInfo, "secret store copied before an OS update",
		slog.String("component", "secretstore"), slog.String("event", "secretstore.preupdate_copy"),
		slog.String("outcome", "copied"), slog.String("version", version), slog.Int("files", files),
		slog.Int64("bytes", size), slog.String("job_id", sc.JobID))
	sc.Log("info", fmt.Sprintf("secret store copied before the update: version %s, %d file(s) (%s)", version, files, humanBytes(byteCount(size))))
	return json.Marshal(preUpdateCopyResult{Copied: true, Version: version, Files: files, SizeBytes: byteCount(size)})
}

// refuse logs a refusal at stage at ERROR, with its cause, and returns the
// sentence the job records.
func (c *PreUpdateCopier) refuse(ctx context.Context, sc *jobs.StepCtx, stage string, cause, sentence error) error {
	c.log.LogAttrs(ctx, slog.LevelError, "secret store not copied before an OS update; the update was refused",
		slog.String("component", "secretstore"), slog.String("event", "secretstore.preupdate_copy"),
		slog.String("outcome", "refused"), slog.String("stage", stage), slog.String("job_id", sc.JobID),
		slog.String("err", cause.Error()))
	return sentence
}

// publishCopy renames the staged copy, already synced, over the published
// one and syncs the directory, so the published path holds the old copy or
// the new one and never a part.
func publishCopy(partial, published string) error {
	if err := os.Rename(partial, published); err != nil {
		return err
	}
	return syncDir(filepath.Dir(published))
}

// RetireCopy deletes the published copy once the api has committed the
// update that took it (#873), and syncs the directory so the deletion
// survives a power cut. A copy that is already gone is retired: a repeat
// call, or an update whose copy_store had no store to copy. A failure is
// logged at ERROR and returned; it leaves the copy where it was, as every
// node was before #873, until the next update replaces and retires it.
func (c *PreUpdateCopier) RetireCopy(ctx context.Context, jobID string) error {
	ctx = jobs.ContextWithJobID(ctx, jobID)
	err := os.Remove(c.copyPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c.log.LogAttrs(ctx, slog.LevelInfo, "no secret store pre-update copy to retire; the update committed",
			slog.String("component", "secretstore"), slog.String("event", "secretstore.preupdate_copy"),
			slog.String("outcome", "absent"), slog.String("job_id", jobID))
		return nil
	case err != nil:
		return c.retireFailed(ctx, jobID, "remove", err)
	}
	if err := syncDir(filepath.Dir(c.copyPath)); err != nil {
		return c.retireFailed(ctx, jobID, "sync", err)
	}
	c.log.LogAttrs(ctx, slog.LevelInfo, "secret store's pre-update copy retired; the update committed",
		slog.String("component", "secretstore"), slog.String("event", "secretstore.preupdate_copy"),
		slog.String("outcome", "retired"), slog.String("job_id", jobID))
	return nil
}

// retireFailed logs a retirement that failed at stage at ERROR, with its
// cause, and returns the cause.
func (c *PreUpdateCopier) retireFailed(ctx context.Context, jobID, stage string, cause error) error {
	c.log.LogAttrs(ctx, slog.LevelError, "secret store's pre-update copy not retired after the update committed",
		slog.String("component", "secretstore"), slog.String("event", "secretstore.preupdate_copy"),
		slog.String("outcome", "retire_failed"), slog.String("stage", stage), slog.String("job_id", jobID),
		slog.String("err", cause.Error()))
	return fmt.Errorf("storage: retire the pre-update copy (%s): %w", stage, cause)
}
