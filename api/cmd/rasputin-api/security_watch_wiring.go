package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const (
	// securityCheckEvery is how often the newest OS manifest is read for its
	// security floor (geekdojo/geekdojo-brain#772). The tick only sets how
	// soon a new floor is seen (timer-audit row K03); the alert raises and
	// clears on inventory, on each alerts read.
	securityCheckEvery = 24 * time.Hour
	// securityCheckStartDelay is the scheduler's startup stagger, so a
	// restarted api reads the floor soon instead of a day later. Zero would
	// default to securityCheckEvery.
	securityCheckStartDelay = 3 * time.Minute
)

// securityWatch is what securityWatchWiring built.
type securityWatch struct {
	workflow jobs.Workflow
	entry    scheduler.Entry
	alerts   func(ctx context.Context, now time.Time) ([]proto.Alert, error)
}

// securityWatchWiring builds the OS security-floor watch over the release
// source the update check uses and the inventory.
func securityWatchWiring(src releases.Source, nodes interface {
	List(context.Context) ([]*proto.Node, error)
}, channel string, logger *slog.Logger) (securityWatch, error) {
	w, err := releases.NewSecurityWatch(releases.SecurityDeps{
		Source: src, Nodes: nodes, Channel: channel, Log: logger, Now: time.Now,
	})
	if err != nil {
		return securityWatch{}, fmt.Errorf("security watch: %w", err)
	}
	return securityWatch{
		workflow: w.Workflow(),
		entry:    scheduler.Entry{Kind: releases.SecurityCheckKind, Interval: securityCheckEvery, InitialDelay: securityCheckStartDelay},
		alerts:   w.Alerts,
	}, nil
}
