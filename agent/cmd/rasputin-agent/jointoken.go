package main

import (
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
)

// logJoinTokenSource writes the agent's one startup record about its bus join
// token, at the level the outcome deserves (geekdojo/geekdojo-brain#539):
//
//   - ERROR when the node presents no token. A bus that enforces auth refuses
//     it, so the node never registers and shows offline; the record says how
//     to fix that. The agent does not exit: it stays reachable and updateable,
//     and it re-reads the token file on every connect attempt.
//   - WARN when a token file is used and the retired RASPUTIN_CP_JOIN_TOKEN is
//     still set: the node joins, but its configuration says something this
//     agent no longer does.
//   - INFO otherwise.
//
// describe is bus.ResolveTokenSource's description and never carries the
// token. legacySet is whether the retired variable is set; its value is never
// passed here.
func logJoinTokenSource(logger *slog.Logger, describe string, none, legacySet bool) {
	switch {
	case none:
		logger.Error("no bus join token; a bus that enforces auth refuses this node",
			"source", describe,
			"retired_variable_set", legacySet,
			"fix", "put the token in a 0600 file named by "+bus.EnvJoinTokenFile)
	case legacySet:
		logger.Warn(bus.EnvJoinToken+" is set and not read; the token file is used",
			"source", describe)
	default:
		logger.Info("bus join token source", "source", describe)
	}
}
