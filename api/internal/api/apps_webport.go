package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
)

// A custom app's web port (geekdojo/geekdojo-brain#1089): one optional
// "webPort" on POST /api/apps and beside "composeYaml" on
// PUT /api/apps/{id}/compose. It is stored where a tile's web port is
// (published_port), so the leaf, route and exposure machinery treat the app
// as they treat a tile's.

// The refusals' messages. The console form (geekdojo/geekdojo-brain#1090)
// shows them as they are, so they are part of the contract.
const (
	msgWebPortInvalid        = "The web port must be a whole number from 1 to 65535."
	msgWebPortWithoutCompose = `A web port is set only with a custom compose, so "webPort" goes only beside "composeYaml".`
	// msgWebPortComposeUnreadable answers a compose that is not YAML or not a
	// compose's shape while a web port is in effect (F-1091-01).
	msgWebPortComposeUnreadable = "The Compose file could not be read, so the web port it publishes cannot be checked."
)

// maxWebPort is the highest TCP port.
const maxWebPort = 65535

// parseWebPort reads a decoded "webPort". nil is (0, true): no port was
// declared. 1-65535 is (port, true). Anything else is (0, false).
func parseWebPort(raw *int) (int, bool) {
	if raw == nil {
		return 0, true
	}
	if *raw < 1 || *raw > maxWebPort {
		return 0, false
	}
	return *raw, true
}

// isWebPortTypeError reports whether a body failed to decode because its
// "webPort" is not a JSON integer: a string, a fraction, 8080.0, a boolean or
// an object.
func isWebPortTypeError(err error) bool {
	var te *json.UnmarshalTypeError
	return errors.As(err, &te) && te.Field == "webPort"
}

// refuseWebPortPublish answers a coded 400, and reports true, when compose
// does not publish port, the web port in effect, on loopback only
// (geekdojo/geekdojo-brain#1091). Port 0 is no web port and is not checked.
// attrs go on the refusal's log record beside its fixed cause.
//
// Neither the compose nor the decoder's error is logged or returned: a
// compose can carry credentials (ADR-0009), and a YAML error can quote the
// line it failed on. The cause names which refusal it was, and that is all
// the record needs.
func (s *Server) refuseWebPortPublish(w http.ResponseWriter, r *http.Request, compose string, port int, attrs ...slog.Attr) bool {
	err := apps.CheckWebPortPublish(compose, port)
	if err == nil {
		return false
	}
	var bind *apps.WebPortBindError
	switch {
	case errors.Is(err, apps.ErrComposeUnreadable):
		s.writeCodedError(w, r, http.StatusBadRequest, codeWebPortComposeUnreadable, msgWebPortComposeUnreadable,
			append(attrs, slog.String("cause", "yaml"))...)
	case errors.As(err, &bind):
		s.writeCodedError(w, r, http.StatusBadRequest, codeWebPortNotLoopback, bind.Error(),
			append(attrs, slog.String("cause", "bind"))...)
	default:
		// CheckWebPortPublish returns no other error; one that appears is
		// refused rather than let through unchecked (ERR-CLOSED).
		writeError(w, http.StatusInternalServerError, "the web port could not be checked")
	}
	return true
}
