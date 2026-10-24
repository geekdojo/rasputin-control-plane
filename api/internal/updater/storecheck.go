package updater

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// StoreHealth is the one secret-store call the self-update commit makes
// (ARCH-ISP): the unauthenticated sys/health, through the api's own client.
type StoreHealth interface {
	Health(ctx context.Context) (secretstore.Health, error)
}

// selfStoreNotReady is the fixed sentence a self-update that the store blocked
// records on its job, row and event. The store's own error text goes to the
// log only (ERR-BOUNDARY).
const selfStoreNotReady = "the secret store did not report ready after the update"

// CopyRetirer deletes the secret store's pre-update copy once the update
// that took it has committed (ARCH-ISP): storage.PreUpdateCopier. It logs
// its own failure; the error is for the caller to see, not to act on.
type CopyRetirer interface {
	RetireCopy(ctx context.Context, jobID string) error
}

// SelfStoreCheck does the two store jobs of a control plane's update of
// itself, which both exist only on the store's host and only for its own
// update:
//
//   - Before the commit, it is the extra health gate
//     (geekdojo/geekdojo-brain#767): this api's own secret store must answer
//     sys/health 200 (initialised, unsealed, active) within the self-update
//     window. Any other outcome refuses the commit, so the update goes down
//     the mark-bad path (ERR-CLOSED). The agent takes no part: the api asks
//     its own store.
//   - After the commit, it retires the store's pre-update copy
//     (geekdojo/geekdojo-brain#873), so a fallback to the old slot after the
//     commit cannot put the old copy back.
type SelfStoreCheck struct {
	store   StoreHealth
	retirer CopyRetirer
	log     *slog.Logger
	// window is the longest the store is waited for: selfUpdateWindow, the
	// window the whole post-reboot finish shares. A field only so a test of
	// the job's end-to-end path need not wait five minutes for it.
	window time.Duration
}

// NewSelfStoreCheck builds the check. Every collaborator is required.
func NewSelfStoreCheck(store StoreHealth, retirer CopyRetirer, log *slog.Logger) (*SelfStoreCheck, error) {
	switch {
	case store == nil:
		return nil, errors.New("updater: self-update store check: the store is nil")
	case retirer == nil:
		return nil, errors.New("updater: self-update store check: the copy retirer is nil")
	case log == nil:
		return nil, errors.New("updater: self-update store check: the logger is nil")
	}
	return &SelfStoreCheck{store: store, retirer: retirer, log: log, window: selfUpdateWindow}, nil
}

// committed retires the store's pre-update copy once the agent has accepted
// mark-good for jobID. A failed retirement does not undo the commit: the
// retirer has logged it at ERROR, mark-good cannot be taken back on a Pi,
// and the copy left behind is replaced by the next self-update.
func (c *SelfStoreCheck) committed(ctx context.Context, jobID string) {
	_ = c.retirer.RetireCopy(ctx, jobID)
}

// ready waits for the store to answer 200, bounded by the time left before
// ctx's deadline, or by the self-update window when ctx has none (or a later
// one). The wait ends on the store's answer (secretstore.WaitReady,
// timer-audit row K24); a window that runs out first is a refusal, never a
// commit. It returns false and the fixed sentence on every outcome other than
// ready.
func (c *SelfStoreCheck) ready(ctx context.Context, nodeID, jobID string) (bool, string) {
	bound := c.window
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < bound {
			bound = left
		}
	}
	if err := secretstore.WaitReady(ctx, c.store, bound); err != nil {
		c.log.WarnContext(ctx, "secret store not ready; marking the self-update bad",
			"component", "updater", "event", "updater.self_update_store_not_ready",
			"node_id", nodeID, "job_id", jobID, "err", err.Error())
		return false, selfStoreNotReady
	}
	c.log.InfoContext(ctx, "secret store ready for the self-update commit",
		"component", "updater", "event", "updater.self_update_store_ready",
		"node_id", nodeID, "job_id", jobID)
	return true, ""
}
