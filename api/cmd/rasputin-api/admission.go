package main

import (
	"context"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/logkit"
)

// admitAgents starts admitting agents to the bus through start
// (busauth.StartAdmission, bound to the api's bus, issuer and token store) and
// returns its stop, for main to defer.
//
// It fails closed. Admission that cannot start means no node can join, so it
// logs FATAL and calls exit(1). exit is os.Exit in main; the stop returned
// after it does nothing.
func admitAgents(ctx context.Context, logger *slog.Logger, exit func(int), start func() (stop func(), err error)) (stop func()) {
	stop, err := start()
	if err != nil {
		logger.Log(ctx, logkit.LevelFatal, "rasputin-api: bus admission did not start; no node can join", "err", err.Error())
		exit(1)
		return func() {}
	}
	return stop
}
