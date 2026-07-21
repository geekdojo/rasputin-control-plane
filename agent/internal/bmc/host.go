package bmc

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// hostConfigFile persists the last settings-pushed selection so a BMC
// host that reboots independently of the control plane comes back
// configured without an api round-trip (bmc-settings.md §4).
const hostConfigFile = "config.json"

// Host owns the agent's BMC lifecycle (bmc-settings.md §4–5): which
// backend (if any) is active, its handler subscriptions, and the
// persisted settings-pushed selection. Every agent runs a Host — even
// with BMC off — so a bmc.configure push can turn BMC on; the power/SoL
// handlers exist only while a backend is active. An env pin
// (RASPUTIN_BMC_BACKEND) freezes the selection: pushes are nacked with
// a typed detail and the pin is advertised.
type Host struct {
	nodeID   string
	stateDir string
	pinned   bool

	mu      sync.Mutex
	nc      *nats.Conn
	backend Backend
	h       *handler
	subs    []*nats.Subscription
	cfgSub  *nats.Subscription
	hash    string
	rereg   func()
}

// Advertisement is the Host's contribution to the registration event:
// the bmc-targets capability list plus the applied config hash / pin
// marker (proto.MetadataBMC*). Nil means BMC is off — advertise nothing.
type Advertisement struct {
	Targets    []string
	ConfigHash string
	Pinned     bool
}

// NewHost resolves the boot-time selection: the env pin wins; else the
// persisted settings push; else off. Any selected backend is
// constructed immediately — before the bus connects — so the first
// registration can advertise bmc-targets. A pin that fails to construct
// is fatal (same as the pre-Host env path); a persisted selection that
// fails logs and comes up off (the api re-pushes on registration, and a
// hardware fault shouldn't crash-loop the whole agent).
func NewHost(nodeID, stateDir, envKind string, envCfg Config) (*Host, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("bmc host: mkdir %s: %w", stateDir, err)
	}
	host := &Host{nodeID: nodeID, stateDir: stateDir}

	if envKind != "" && envKind != BackendNone {
		b, err := New(envKind, envCfg)
		if err != nil {
			return nil, fmt.Errorf("bmc host: env-pinned backend: %w", err)
		}
		host.backend = b
		host.pinned = true
		return host, nil
	}

	sel, err := loadPersistedSelection(stateDir)
	if err != nil {
		log.Printf("rasputin-agent: bmc: persisted selection unreadable (%v) — coming up off", err)
		return host, nil
	}
	if sel == nil {
		return host, nil
	}
	b, err := NewFromSelection(sel.Kind, sel.Config, stateDir)
	if err != nil {
		log.Printf("rasputin-agent: bmc: persisted selection %q failed to apply (%v) — coming up off", sel.Kind, err)
		return host, nil
	}
	host.backend = b
	host.hash = sel.ConfigHash
	return host, nil
}

// Active reports whether a backend is currently running.
func (h *Host) Active() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.backend != nil
}

// Name returns the active backend's name, "" when off.
func (h *Host) Name() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.backend == nil {
		return ""
	}
	return h.backend.Name()
}

// Advertisement returns the registration contribution, nil when off.
func (h *Host) Advertisement() *Advertisement {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.backend == nil {
		return nil
	}
	return &Advertisement{
		Targets:    h.backend.Targets(),
		ConfigHash: h.hash,
		Pinned:     h.pinned,
	}
}

// Attach wires the Host to the bus: the bmc.configure subscription on
// every agent (so a push can turn BMC on, and a pinned host can nack
// with a typed reply), plus power/SoL handlers when a backend was
// boot-resolved. rereg re-publishes the registration event after a
// swap so the advertisement updates immediately.
func (h *Host) Attach(nc *nats.Conn, rereg func()) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nc = nc
	h.rereg = rereg

	cfgSub, err := nc.Subscribe(proto.BMCConfigureSubject(h.nodeID), h.handleConfigure)
	if err != nil {
		return fmt.Errorf("bmc host: subscribe configure: %w", err)
	}
	h.cfgSub = cfgSub
	log.Printf("rasputin-agent: subscribed to %s", proto.BMCConfigureSubject(h.nodeID))

	if h.backend != nil {
		if err := h.registerLocked(); err != nil {
			return err
		}
	}
	return nil
}

// registerLocked registers power/SoL handlers for the current backend.
// Caller holds h.mu.
func (h *Host) registerLocked() error {
	hd, subs, err := registerHandlers(h.nc, h.nodeID, h.backend)
	if err != nil {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
		return fmt.Errorf("bmc host: register handlers: %w", err)
	}
	h.h = hd
	h.subs = subs
	return nil
}

// teardownLocked drains sessions, unsubscribes handlers, and closes the
// backend. Caller holds h.mu.
func (h *Host) teardownLocked(reason string) {
	if h.h != nil {
		h.h.closeAll(reason)
		h.h = nil
	}
	for _, s := range h.subs {
		_ = s.Unsubscribe()
	}
	h.subs = nil
	if c, ok := h.backend.(io.Closer); ok {
		_ = c.Close()
	}
	h.backend = nil
	h.hash = ""
}

func (h *Host) handleConfigure(m *nats.Msg) {
	var cmd proto.BMCConfigureCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.BMCConfigureAck{OK: false, Detail: "bad cmd: " + err.Error()})
		return
	}
	if h.pinned {
		respond(m, proto.BMCConfigureAck{OK: false,
			Detail: "pinned by RASPUTIN_BMC_BACKEND on this node — remove the env var to manage BMC from Settings"})
		return
	}

	h.mu.Lock()
	prev, _ := loadPersistedSelection(h.stateDir)

	if cmd.Kind == "" || cmd.Kind == BackendNone {
		// Deconfigure: hard off, restored.
		h.teardownLocked("BMC deconfigured from Settings")
		if err := clearPersistedSelection(h.stateDir); err != nil {
			log.Printf("rasputin-agent: bmc: clear persisted selection: %v", err)
		}
		h.mu.Unlock()
		h.rereg()
		respond(m, proto.BMCConfigureAck{OK: true})
		log.Printf("rasputin-agent: bmc: deconfigured (off)")
		return
	}

	// Swap: teardown first (same-device drivers can't double-open the
	// serial line), then construct. On failure, best-effort rollback to
	// the previous persisted selection so a bad push doesn't strand a
	// working setup.
	h.teardownLocked("BMC reconfigured from Settings")
	b, err := NewFromSelection(cmd.Kind, cmd.Config, h.stateDir)
	if err != nil {
		detail := err.Error()
		if prev != nil {
			if rb, rerr := NewFromSelection(prev.Kind, prev.Config, h.stateDir); rerr == nil {
				h.backend = rb
				h.hash = prev.ConfigHash
				if regErr := h.registerLocked(); regErr != nil {
					log.Printf("rasputin-agent: bmc: rollback register: %v", regErr)
				}
				detail += " (previous selection restored)"
			} else {
				detail += " (rollback also failed: " + rerr.Error() + " — BMC is off)"
			}
		}
		h.mu.Unlock()
		h.rereg()
		respond(m, proto.BMCConfigureAck{OK: false, Detail: detail})
		return
	}
	h.backend = b
	h.hash = cmd.ConfigHash
	if err := h.registerLocked(); err != nil {
		h.teardownLocked("BMC configure failed")
		h.mu.Unlock()
		h.rereg()
		respond(m, proto.BMCConfigureAck{OK: false, Detail: err.Error()})
		return
	}
	if err := persistSelection(h.stateDir, cmd); err != nil {
		// Applied but not persisted: still running; a reboot loses it and
		// the api's registration reconcile re-pushes. Log, don't fail.
		log.Printf("rasputin-agent: bmc: persist selection: %v", err)
	}
	h.mu.Unlock()
	h.rereg()
	respond(m, proto.BMCConfigureAck{OK: true, ConfigHash: cmd.ConfigHash})
	log.Printf("rasputin-agent: bmc: configured backend=%s targets=%d", cmd.Kind, len(b.Targets()))
}

// Shutdown releases everything on agent exit.
func (h *Host) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfgSub != nil {
		_ = h.cfgSub.Unsubscribe()
		h.cfgSub = nil
	}
	h.teardownLocked("agent shutting down")
}

func loadPersistedSelection(stateDir string) (*proto.BMCConfigureCmd, error) {
	buf, err := os.ReadFile(filepath.Join(stateDir, hostConfigFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cmd proto.BMCConfigureCmd
	if err := json.Unmarshal(buf, &cmd); err != nil {
		return nil, err
	}
	return &cmd, nil
}

func persistSelection(stateDir string, cmd proto.BMCConfigureCmd) error {
	buf, err := json.MarshalIndent(cmd, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(stateDir, hostConfigFile+".tmp")
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir, hostConfigFile))
}

func clearPersistedSelection(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, hostConfigFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
