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
// The env pin wins when both exist: it is what the operator seeded, and a
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

// ResolvePin decides the pin a node starts with: the env value when it is a
// valid pin, else the file's. source says which ("env", "file", or "" for
// none).
//
// A value that does not parse is returned as envErr / fileErr and otherwise
// skipped, so the caller can report it as a configuration fault and keep
// going — a node that survives a typo and says so, rather than one that cannot
// start (#89). A bad env pin falls through to the file: a pin the controlplane
// delivered is still the right one to use while the typo is fixed.
func ResolvePin(env, pinFile string) (pin, source string, envErr, fileErr error) {
	if v := strings.TrimSpace(env); v != "" {
		_, perr := proto.ParseBusPin(v)
		if perr == nil {
			return v, "env", nil, nil
		}
		envErr = perr
	}
	v, rerr := ReadPinFile(pinFile)
	switch {
	case rerr != nil:
		return "", "", envErr, fmt.Errorf("read %s: %w", pinFile, rerr)
	case v == "":
		return "", "", envErr, nil
	}
	if _, perr := proto.ParseBusPin(v); perr != nil {
		return "", "", envErr, fmt.Errorf("%s: %w", pinFile, perr)
	}
	return v, "file", envErr, nil
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
		log.Printf("agent/bus: REFUSED a bus pin delivery: holds %s, offered %s", cur, want)
		Respond(m, ack)
		return
	}
	if err := WritePinFile(pinFile, want); err != nil {
		ack.Detail = fmt.Sprintf("could not persist the pin to %s: %v — staying on the current connection rather than switching to a pin a reboot would forget", pinFile, err)
		log.Printf("agent/bus: %s", ack.Detail)
		Respond(m, ack)
		return
	}
	ack.OK, ack.Pin, ack.Reconnecting = true, want, true
	Respond(m, ack)
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		log.Printf("agent/bus: flush before re-dialing over TLS: %v", err)
	}
	log.Printf("agent/bus: bus pin %s delivered and saved to %s", want, pinFile)
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
