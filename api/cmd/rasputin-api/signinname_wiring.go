package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/signinname"
)

// The home sign-in name's responder (geekdojo/geekdojo-brain#995): it
// publishes doorTable.Home.Host, sso-<cid>.local, over mDNS beside
// systemd-resolved. The same door table feeds the leaf, the records and this
// name (signin-origin.md §15.1).

// wireSigninName builds and starts the responder from the door table's
// result. With no cluster id it returns nil: no responder, no alert, no
// metric. A refused cluster id gets a refused responder, which publishes
// nothing and raises only the refused alert; wireDoorTable has already logged
// the configfault. Otherwise the responder is started on addrs with open and
// clock. The returned value's Wait is nil-safe.
func wireSigninName(ctx context.Context, logger *slog.Logger, table doors.Table, doorErr error,
	addrs signinname.Addresses, open func(ifindex int) (signinname.Conn, error), clock signinname.Clock) *signinname.Responder {
	var refused *doors.RefusedError
	switch {
	case errors.Is(doorErr, doors.ErrNoClusterID):
		logger.InfoContext(ctx, "sign-in name responder off: no cluster id", "component", "signinname")
		return nil
	case errors.As(doorErr, &refused):
		return signinname.NewRefused(refused.ClusterID, refused.Err, clock)
	case doorErr != nil:
		return signinname.NewRefused("", doorErr, clock)
	}
	r, err := signinname.New(signinname.Config{
		Name:  table.Home.Host,
		Addrs: addrs,
		Open:  open,
		Clock: clock,
		Log:   logger,
	})
	if err != nil {
		// Every collaborator is main's own; this is a wiring bug.
		logger.ErrorContext(ctx, "sign-in name responder off: wiring", "component", "signinname", "err", err.Error())
		return nil
	}
	go r.Run(ctx)
	return r
}

// signinNameFanout adds the sign-in name's state metric to the control
// plane's own sample. With no responder or no self node id it returns inner
// unchanged.
func signinNameFanout(inner metrics.Sink, vm *obs.VMSink, r *signinname.Responder, selfNodeID string, logger *slog.Logger) metrics.Sink {
	if r == nil || selfNodeID == "" || vm == nil {
		return inner
	}
	sink, err := obs.NewSigninNameSink(inner, vm, obs.SigninNameDeps{
		Reading:    r,
		SelfNodeID: selfNodeID,
		Now:        time.Now,
		Log:        logger,
	})
	if err != nil {
		logger.Error("sign-in name metric off", "component", "obs", "reason", "wiring", "err", err.Error())
		return inner
	}
	return sink
}
