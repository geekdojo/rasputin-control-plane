package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// MockBackend file-backs per-target power state in <stateDir>/bmc.json.
// SOL sessions emit a banner + a periodic line so the UI sees activity.
//
// Power semantics:
//   - on:    sets state=on
//   - off:   sets state=off
//   - cycle: sets state=on (no off blip in mock — fine, this is dev)
//   - reset: sets state=on
//   - status: read-only, no state change
type MockBackend struct {
	mu        sync.Mutex
	statePath string
	state     mockState
}

type mockState struct {
	// Power state per target node id.
	Power map[string]proto.BMCPowerState `json:"power"`
}

func NewMockBackend(stateDir string) (*MockBackend, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("bmc mock: mkdir %s: %w", stateDir, err)
	}
	mb := &MockBackend{
		statePath: filepath.Join(stateDir, "bmc.json"),
		state:     mockState{Power: map[string]proto.BMCPowerState{}},
	}
	if err := mb.load(); err != nil {
		return nil, err
	}
	return mb, nil
}

func (m *MockBackend) Name() string { return "mock" }

func (m *MockBackend) load() error {
	buf, err := os.ReadFile(m.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m.persistLocked()
		}
		return err
	}
	if err := json.Unmarshal(buf, &m.state); err != nil {
		return err
	}
	if m.state.Power == nil {
		m.state.Power = map[string]proto.BMCPowerState{}
	}
	return nil
}

func (m *MockBackend) persistLocked() error {
	tmp := m.statePath + ".tmp"
	buf, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath)
}

func (m *MockBackend) Power(_ context.Context, target string, verb proto.BMCPowerVerb) (proto.BMCPowerState, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.state.Power[target]
	if cur == "" {
		cur = proto.BMCStateUnknown
	}
	var next proto.BMCPowerState
	detail := ""
	switch verb {
	case proto.BMCPowerOn:
		next = proto.BMCStateOn
		detail = "powered on"
	case proto.BMCPowerOff:
		next = proto.BMCStateOff
		detail = "powered off"
	case proto.BMCPowerCycle:
		next = proto.BMCStateOn
		detail = "cycled"
	case proto.BMCPowerReset:
		next = proto.BMCStateOn
		detail = "reset signal sent"
	case proto.BMCPowerQuery:
		return cur, "queried", nil
	default:
		return cur, "", fmt.Errorf("unsupported verb %q", verb)
	}
	m.state.Power[target] = next
	if err := m.persistLocked(); err != nil {
		return cur, "", err
	}
	return next, detail, nil
}

// mockSOL emits a banner immediately and then a uptime-style line every
// 2 s. Anything written via Write() is echoed back ("\r\nmock-echo: %s\r\n")
// to make the UI feel alive during dev.
type mockSOL struct {
	id     string
	target string
	out    chan []byte
	cancel context.CancelFunc
	done   chan struct{}
}

func (m *MockBackend) OpenSOL(ctx context.Context, target, sessionID string) (SOL, error) {
	sessCtx, cancel := context.WithCancel(context.Background())
	s := &mockSOL{
		id:     sessionID,
		target: target,
		out:    make(chan []byte, 256),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go s.run(sessCtx)
	return s, nil
}

func (s *mockSOL) run(ctx context.Context) {
	defer close(s.done)
	banner := fmt.Sprintf("\r\n[mock-bmc] sol session %s for %s\r\n[mock-bmc] uptime 0s\r\n",
		s.id[:12], s.target)
	select {
	case s.out <- []byte(banner):
	case <-ctx.Done():
		return
	}
	start := time.Now()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			line := fmt.Sprintf("[mock-bmc] uptime %s\r\n", now.Sub(start).Round(time.Second))
			select {
			case s.out <- []byte(line):
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *mockSOL) SessionID() string  { return s.id }
func (s *mockSOL) Out() <-chan []byte { return s.out }
func (s *mockSOL) Write(p []byte) error {
	// Echo back so the operator sees what they typed.
	select {
	case s.out <- []byte(fmt.Sprintf("\r\nmock-echo: %s\r\n", string(p))):
	default:
	}
	return nil
}
func (s *mockSOL) Close() error {
	s.cancel()
	<-s.done
	return nil
}
