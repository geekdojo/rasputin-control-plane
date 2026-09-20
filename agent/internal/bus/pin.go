package bus

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Where a node's bus pin comes from (docs/bus-tls-contract.md):
//
//  1. RASPUTIN_BUS_PIN in the agent's environment — from the node's seed, put
//     there by the OS firstboot (node.env) or the firewall's apply-seed (UCI →
//     procd env). A provisioned set and an Add-node seed carry it.
//  2. Otherwise the pin FILE under the agent's state dir, written by the agent
//     itself when the controlplane delivers the pin over the bus (bus.pin) to
//     a node enrolled before the pin existed. The state dir is persistent on
//     both images — /var/lib/rasputin/agent-state on Rasputin OS,
//     /etc/rasputin/agent-state on the firewall (kept across sysupgrade) — so
//     no image change is needed for a delivered pin to survive a reboot.
//
//  3. On the CONTROLPLANE's own agent only: the file the api writes beside its
//     bus key on every start (proto.BusAgentPinPath). A controlplane that
//     self-initialised has no seed, so nothing put a pin in its environment,
//     and a controlplane whose bus already refuses plaintext can never deliver
//     one over the bus. See proto/busagenttoken.go.
//
// The env pin wins when several exist: it is what the operator seeded, and a
// delivery never writes a pin that differs from the one the node holds.

// EnvPin is the node's seeded pin.
const EnvPin = "RASPUTIN_BUS_PIN"

// PinFilePath is the delivered-pin file for a state dir.
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

// WritePinFile persists pin atomically (temp file, fsync, rename), so a power
// cut leaves the old file or the new one and never half of one.
func WritePinFile(path, pin string) error {
	if _, err := proto.ParseBusPin(pin); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pin-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.WriteString(strings.TrimSpace(pin) + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Resolution is where a node's bus pin came from, and what the answer means
// for a node that ended up without one.
type Resolution struct {
	// Pin is the value to dial with, "" when no source produced a usable one.
	Pin string
	// Source names it: "env", "file", "controlplane", or "" for none.
	Source string
	// Configured is true when this node was GIVEN a pin — a seeded env value,
	// a delivered pin file, or the controlplane's own pin file — whether or
	// not it turned out to be usable.
	Configured bool
	// EnvErr, FileErr and CPErr are why a source was skipped. Each is a
	// configuration fault the caller reports.
	EnvErr, FileErr, CPErr error
}

// Plaintext reports whether this node may dial the bus unencrypted.
//
// It is false exactly when a pin was configured and none of the sources
// produced a usable value. Such a node must NOT fall back to plaintext: it was
// pinned, so the only reason it has no pin now is a fault, and dialing anyway
// would send its join token in the clear to whatever answered on :4222 — the
// one thing the pin exists to prevent (geekdojo/geekdojo-brain#510, F09).
//
// A node that was never given a pin is a different case and still dials
// plaintext: that is how a fleet enrolled before the pin existed reaches a
// controlplane in offer or migrate, and how it receives its pin at all.
func (r Resolution) Plaintext() bool { return r.Pin == "" && !r.Configured }

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
// valid pin, else the delivered pin file's, else — on the controlplane's own
// agent — the file the api writes beside its bus key (cpPinFile; "" on every
// other node, which has no such file).
//
// A value that does not parse is recorded on the Resolution and otherwise
// skipped, so the caller can report it as a configuration fault: a bad env pin
// still falls through to a delivered pin, which is the right one to use while
// the typo is fixed.
//
// What it does NOT do any more is fall through to plaintext. Resolution.Pin
// empty with Resolution.Configured true is the fail-closed answer, and the
// caller refuses to dial; see Plaintext.
func ResolvePin(env, pinFile, cpPinFile string) Resolution {
	var r Resolution
	if v := strings.TrimSpace(env); v != "" {
		r.Configured = true
		_, perr := proto.ParseBusPin(v)
		if perr == nil {
			r.Pin, r.Source = v, "env"
			return r
		}
		r.EnvErr = perr
	}
	if v, ok := readSource(pinFile, &r.Configured, &r.FileErr); ok {
		r.Pin, r.Source = v, "file"
		return r
	}
	if v, ok := readSource(cpPinFile, &r.Configured, &r.CPErr); ok {
		r.Pin, r.Source = v, "controlplane"
		return r
	}
	return r
}

// readSource reads one pin file. A file that is absent contributes nothing. A
// file that is present sets configured — the node holds a pin — and a file that
// is present but unreadable or unparseable sets *srcErr and yields no pin,
// which is what makes the node refuse plaintext rather than downgrade to it.
func readSource(path string, configured *bool, srcErr *error) (string, bool) {
	if strings.TrimSpace(path) == "" {
		return "", false
	}
	v, rerr := ReadPinFile(path)
	switch {
	case rerr != nil:
		*configured = true
		*srcErr = fmt.Errorf("read %s: %w", path, rerr)
		return "", false
	case v == "":
		return "", false
	}
	*configured = true
	if _, perr := proto.ParseBusPin(v); perr != nil {
		*srcErr = fmt.Errorf("%s: %w", path, perr)
		return "", false
	}
	return v, true
}

// PinSubscriber returns the onConn subscriber for rasputin.node.<id>.cmd.bus.pin.
// pinFile is where a delivered pin is persisted.
func (c *Client) PinSubscriber(nodeID, pinFile string) func(*nats.Conn) error {
	subj := proto.NodeCmdSubject(nodeID, proto.BusPinVerb)
	return func(nc *nats.Conn) error {
		if _, err := nc.Subscribe(subj, func(m *nats.Msg) { c.handlePin(nc, m, nodeID, pinFile) }); err != nil {
			return fmt.Errorf("subscribe %s: %w", subj, err)
		}
		return nil
	}
}

// handlePin takes a delivered pin.
//
// It refuses a pin that differs from the one the node already holds: that is
// key rotation, the server holds one key, and taking it would strand the node.
// A pin it already holds is acknowledged and changes nothing. A new pin is
// persisted FIRST — a node that switched to TLS on a pin it could not save
// would come back plaintext after a reboot, which a TLS-required bus refuses —
// then acknowledged, flushed, and only then is the connection replaced, so the
// reply is on the wire before the conn it travels on is closed.
func (c *Client) handlePin(nc *nats.Conn, m *nats.Msg, nodeID, pinFile string) {
	ack := proto.BusPinAck{NodeID: nodeID}
	var cmd proto.BusPinCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		ack.Detail = "bad command: " + err.Error()
		ack.Pin = c.Pin()
		Respond(m, ack)
		return
	}
	want := strings.TrimSpace(cmd.Pin)
	if _, err := proto.ParseBusPin(want); err != nil {
		ack.Detail = err.Error()
		ack.Pin = c.Pin()
		Respond(m, ack)
		return
	}
	cur := c.Pin()
	switch {
	case cur == want:
		ack.OK, ack.Pin = true, cur
		ack.Detail = "already pinned"
		Respond(m, ack)
		return
	case cur != "":
		ack.Pin = cur
		ack.Detail = fmt.Sprintf("this node already pins %s; replacing a pin is key rotation, which the bus cannot serve — refusing rather than stranding the node", cur)
		log.Printf("agent/bus: REFUSED a bus pin delivery: holds %q, offered %q", cur, want)
		Respond(m, ack)
		return
	}
	if err := WritePinFile(pinFile, want); err != nil {
		ack.Detail = fmt.Sprintf("could not persist the pin to %s: %v — staying on the current connection rather than switching to a pin a reboot would forget", pinFile, err)
		log.Printf("agent/bus: %q", ack.Detail)
		Respond(m, ack)
		return
	}
	ack.OK, ack.Pin, ack.Reconnecting = true, want, true
	Respond(m, ack)
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		log.Printf("agent/bus: flush before re-dialing over TLS: %v", err)
	}
	log.Printf("agent/bus: bus pin %q delivered and saved to %q", want, pinFile)
	// The pin is set before this handler returns, so a second delivery racing
	// the re-dial reads "already pinned" rather than writing it again. The
	// close is not on the subscription's goroutine: closing a conn from inside
	// its own message callback would wait on itself.
	if err := c.SetPin(want); err != nil {
		log.Printf("agent/bus: switch to the delivered pin: %v", err)
		return
	}
	go c.redialUnderPin(nc)
}
