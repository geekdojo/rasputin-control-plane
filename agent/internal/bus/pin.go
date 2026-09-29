package bus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Where a node's bus pin comes from (docs/bus-tls-contract.md):
//
//  1. RASPUTIN_BUS_PIN in the agent's environment — from the node's seed, put
//     there by the OS firstboot (node.env) or the firewall's apply-seed (UCI →
//     procd env). A provisioned set and an Add-node seed carry it.
//  2. Otherwise the saved pin FILE under the agent's state dir. An agent of
//     2026.09.5 or older wrote it when the controlplane delivered the pin over
//     the bus to a node enrolled before the pin existed; nodes migrated in
//     place hold their pin only here. Nothing writes it any more
//     (geekdojo/geekdojo-brain#517), and it is still read. The state dir is
//     persistent on both images — /var/lib/rasputin/agent-state on Rasputin
//     OS, /etc/rasputin/agent-state on the firewall (kept across sysupgrade).
//  3. On the CONTROLPLANE's own agent only: the file the api writes beside its
//     bus key on every start (proto.BusAgentPinPath). A controlplane that
//     self-initialised has no seed, so nothing put a pin in its environment.
//     See proto/busagenttoken.go.
//
// The env pin wins when several exist: it is what the operator seeded.
//
// A node with no usable pin from any source does not dial at all. The bus
// accepts only TLS, and the pin is the only check on the server's key.

// EnvPin is the node's seeded pin.
const EnvPin = "RASPUTIN_BUS_PIN"

// PinFilePath is the saved pin file for a state dir.
func PinFilePath(stateDir string) string { return filepath.Join(stateDir, "bus", "pin") }

// ReadPinFile returns the pin in path, "" when the file does not exist.
func ReadPinFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Resolution is where a node's bus pin came from, and why any source was
// skipped.
type Resolution struct {
	// Pin is the value to dial with, "" when no source produced a usable one.
	// A node whose Pin is "" does not dial the bus.
	Pin string
	// Source names it: "env", "file", "controlplane", or "" for none.
	Source string
	// EnvErr, FileErr and CPErr are why a source was skipped. Each is a
	// configuration fault the caller reports.
	EnvErr, FileErr, CPErr error
}

// Faults lists every source error, in resolution order.
func (r Resolution) Faults() []error {
	var out []error
	for _, e := range []error{r.EnvErr, r.FileErr, r.CPErr} {
		if e != nil {
			out = append(out, e)
		}
	}
	return out
}

// ResolvePin decides the pin a node starts with: the env value when it is a
// valid pin, else the saved pin file's, else — on the controlplane's own agent
// — the file the api writes beside its bus key (cpPinFile; "" on every other
// node, which has no such file).
//
// A value that does not parse is recorded on the Resolution and otherwise
// skipped, so the caller can report it as a configuration fault: a bad env pin
// still falls through to a saved pin, which is the right one to use while the
// typo is fixed. Resolution.Pin empty means no source produced a pin, and the
// caller refuses to dial.
func ResolvePin(env, pinFile, cpPinFile string) Resolution {
	var r Resolution
	if v := strings.TrimSpace(env); v != "" {
		_, perr := proto.ParseBusPin(v)
		if perr == nil {
			r.Pin, r.Source = v, "env"
			return r
		}
		r.EnvErr = perr
	}
	if v, ok := readSource(pinFile, &r.FileErr); ok {
		r.Pin, r.Source = v, "file"
		return r
	}
	if v, ok := readSource(cpPinFile, &r.CPErr); ok {
		r.Pin, r.Source = v, "controlplane"
		return r
	}
	return r
}

// readSource reads one pin file. A file that is absent contributes nothing. A
// file that is present but unreadable, empty or unparseable sets *srcErr and
// yields no pin.
//
// Empty is a fault, not an absence: the api's bustls.WriteAgentPinFile, and
// the agents that wrote the saved file, write a whole pin or nothing, so a pin
// file that exists and holds nothing was truncated by something else
// (geekdojo/geekdojo-brain#510, fail-open F09).
func readSource(path string, srcErr *error) (string, bool) {
	if strings.TrimSpace(path) == "" {
		return "", false
	}
	v, rerr := ReadPinFile(path)
	switch {
	case rerr != nil:
		*srcErr = fmt.Errorf("read %s: %w", path, rerr)
		return "", false
	case v == "":
		// ReadPinFile says "" for a file that is absent AND for one that is
		// present and blank; only the first contributes nothing.
		_, serr := os.Stat(path)
		if errors.Is(serr, os.ErrNotExist) {
			return "", false
		}
		if serr != nil {
			*srcErr = fmt.Errorf("stat %s: %w", path, serr)
		} else {
			*srcErr = fmt.Errorf("%s: the pin file is present but empty", path)
		}
		return "", false
	}
	if _, perr := proto.ParseBusPin(v); perr != nil {
		*srcErr = fmt.Errorf("%s: %w", path, perr)
		return "", false
	}
	return v, true
}
