package apps

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"gopkg.in/yaml.v3"
)

// A custom app's web port is held to the tile's loopback rule
// (geekdojo/geekdojo-brain#1091): the compose must publish it on
// tileschema.WebPublishHost only, so the node proxy is the one way in. The
// rule is tileschema.ValidateWebPortBind, fed by the grammar the catalog
// publisher reads tiles with (tileschema.ParsePortEntry).

// ErrComposeUnreadable is a compose that is not YAML, or not the shape a
// compose has (services as a map of services, each one's ports a list), so
// the web port it publishes cannot be checked. It wraps the decoder's error,
// which can quote the compose and so never reaches a client or a log.
var ErrComposeUnreadable = errors.New("compose could not be read")

// WebPortBindError is a compose that does not publish its web port on
// loopback only. Error is the refusal as a sentence, which the console shows
// as it is.
type WebPortBindError struct{ msg string }

func (e *WebPortBindError) Error() string { return e.msg }

// CheckWebPortPublish refuses a compose that does not publish port, its web
// port, on loopback only. Port 0 is no web port: the compose is not read and
// nil is returned, as before the rule existed.
//
// A refusal is a *WebPortBindError, or ErrComposeUnreadable when the compose
// cannot be read. Only the declared port is judged: a ports entry the grammar
// cannot read is skipped, not refused. When the port is published only in
// such a form, the refusal says so rather than calling it unpublished.
func CheckWebPortPublish(compose string, port int) error {
	if port == 0 {
		return nil
	}
	facts, skipped, err := composePortFacts(compose)
	if err != nil {
		return err
	}
	tile := tileschema.Tile{Ports: []tileschema.Port{{Published: port, Container: port, Web: true}}}
	verdict := tileschema.ValidateWebPortBind(tile, facts)
	if verdict == nil {
		return nil
	}
	if skipped && !publishes(facts, port) {
		return &WebPortBindError{msg: fmt.Sprintf(
			"Web port %d is not published in a form that can be checked: write it as %q, with no protocol suffix, variable or long syntax.",
			port, fmt.Sprintf("%s:%d:<container>", tileschema.WebPublishHost, port))}
	}
	return &WebPortBindError{msg: sentence(verdict.Error())}
}

// composePortFacts is the control plane's one read of a compose's YAML: the
// host port bindings and host networking the web-port rule judges. skipped
// reports an entry ParsePortEntry could not read, which is left out of the
// facts. A compose that does not decode is ErrComposeUnreadable.
func composePortFacts(compose string) (facts tileschema.SafetyFacts, skipped bool, err error) {
	var doc struct {
		Services map[string]struct {
			NetworkMode string `yaml:"network_mode"`
			Ports       []any  `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return tileschema.SafetyFacts{}, false, fmt.Errorf("%w: %w", ErrComposeUnreadable, err)
	}
	for _, svc := range doc.Services {
		if svc.NetworkMode == "host" {
			facts.HostNetwork = true
		}
		for _, e := range svc.Ports {
			b, ok := tileschema.ParsePortEntry(e)
			if !ok {
				skipped = true
				continue
			}
			facts.PortBindings = append(facts.PortBindings, b)
		}
	}
	return facts, skipped, nil
}

// publishes reports whether any read binding is for port.
func publishes(f tileschema.SafetyFacts, port int) bool {
	for _, b := range f.PortBindings {
		if b.Published == port {
			return true
		}
	}
	return false
}

// sentence makes a lowercase error text a sentence: first letter upper-cased,
// a full stop at the end.
func sentence(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[n:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
