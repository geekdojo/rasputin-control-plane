package api

import (
	"encoding/json"
	"errors"
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
