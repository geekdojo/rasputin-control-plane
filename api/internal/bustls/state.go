package bustls

import (
	"errors"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// State is what the api knows about its bus TLS at start: the key it serves,
// or which file failed and why. The bus accepts only TLS
// (geekdojo/geekdojo-brain#517), so a State with no key means no bus listener
// at all, no pin for a seed, and a standing alert.
//
// It is a value type, built once at the composition root, so there is no
// typed-nil to mistake for "available": the zero State, and Available(nil),
// are unavailable.
type State struct {
	key  *Key
	file string
	err  error
}

// errNoKey is the Fault of a State that was never given a key or a cause.
var errNoKey = errors.New("bustls: no bus key was loaded")

// Available is the State of an api serving key.
func Available(key *Key) State {
	if key == nil {
		return State{}
	}
	return State{key: key}
}

// Unavailable is the State of an api whose bus key or certificate could not be
// used: file names which one, and err says why.
func Unavailable(file string, err error) State {
	if err == nil {
		err = errNoKey
	}
	return State{file: file, err: err}
}

// Pin is the live pin, and whether there is one.
func (s State) Pin() (pin string, ok bool) {
	if s.key == nil {
		return "", false
	}
	return s.key.Pin(), true
}

// Fault is which file failed and why; ("", nil) when the bus is available.
func (s State) Fault() (file string, err error) {
	if s.key != nil {
		return "", nil
	}
	if s.err == nil {
		return s.file, errNoKey
	}
	return s.file, s.err
}

// AlertID is the standing alert of an unavailable bus.
const AlertID = "bus-tls-unavailable"

// Alert is the standing alert the State deserves: nil when the bus is
// available, and otherwise a crit alert naming the file that failed. It is the
// function the alerts service calls on every listing.
func (s State) Alert(now time.Time) *proto.Alert {
	if s.key != nil {
		return nil
	}
	what := "its bus key"
	if s.file != "" {
		what = s.file
	}
	return &proto.Alert{
		ID:       AlertID,
		Severity: proto.AlertCrit,
		Source:   proto.AlertSourceSecurity,
		Title:    "Node bus is down",
		Detail: "The control plane could not use " + what + ", so its node bus serves no listener and no node, " +
			"this control plane's own agent included, can join it. The api log names the error; " +
			"restoring the identity backup puts the bus key and certificate back.",
		Since: now,
	}
}
