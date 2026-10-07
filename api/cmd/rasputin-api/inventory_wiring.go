package main

import (
	"context"
	"errors"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
)

// openInventory opens the inventory store with its clock injected before any
// reader runs: the node presence trust.converge selects on, and the elapsed
// times ExplainNoResponder renders, are read at now (ARCH-IOC). main passes
// time.Now. A nil clock is refused rather than left to the store's fallback.
func openInventory(ctx context.Context, dbPath string, now func() time.Time) (*inventory.Store, error) {
	if now == nil {
		return nil, errors.New("inventory store: no clock")
	}
	s, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	s.SetNow(now)
	return s, nil
}
