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

// SelfStoreCheck is the extra health gate a control plane's update of itself
// passes before it commits (geekdojo/geekdojo-brain#767): this api's own
// secret store must answer sys/health 200 (initialised, unsealed, active)
// within the self-update window. Any other outcome refuses the commit, so the
// update goes down the mark-bad path (ERR-CLOSED). The agent takes no part:
// the api asks its own store.
type SelfStoreCheck struct {
	store StoreHealth
	log   *slog.Logger
	// window is the longest the store is waited for: selfUpdateWindow, the
	// window the whole post-reboot finish shares. A field only so a test of
	// the job's end-to-end path need not wait five minutes for it.
	window time.Duration
}

// NewSelfStoreCheck builds the check. Both collaborators are required.
func NewSelfStoreCheck(store StoreHealth, log *slog.Logger) (*SelfStoreCheck, error) {
	switch {
	case store == nil:
		return nil, errors.New("updater: self-update store check: the store is nil")
	case log == nil:
		return nil, errors.New("updater: self-update store check: the logger is nil")
	}
	return &SelfStoreCheck{store: store, log: log, window: selfUpdateWindow}, nil
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
