package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MockBackend file-backs state in <stateDir>/tailscale.json. Mimics the
// shape of `tailscale status --json` enough to drive the api saga.
type MockBackend struct {
	mu        sync.Mutex
	statePath string
	state     mockTSState
}

type mockTSState struct {
	Enrolled   bool      `json:"enrolled"`
	Hostname   string    `json:"hostname"`
	TailnetIP  string    `json:"tailnetIp"`
	Routes     []string  `json:"routes"`
	EnrolledAt time.Time `json:"enrolledAt"`
}

func NewMockBackend(stateDir string) (*MockBackend, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("tailscale mock: mkdir %s: %w", stateDir, err)
	}
	b := &MockBackend{statePath: filepath.Join(stateDir, "tailscale.json")}
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *MockBackend) Name() string { return "mock" }

func (b *MockBackend) load() error {
	buf, err := os.ReadFile(b.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return b.persistLocked()
		}
		return err
	}
	return json.Unmarshal(buf, &b.state)
}

func (b *MockBackend) persistLocked() error {
	tmp := b.statePath + ".tmp"
	buf, err := json.MarshalIndent(b.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.statePath)
}

func (b *MockBackend) Enroll(_ context.Context, in EnrollInput) (Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if in.AuthKey == "" {
		return Status{}, errors.New("tailscale mock: empty auth key")
	}
	b.state = mockTSState{
		Enrolled:   true,
		Hostname:   in.Hostname,
		TailnetIP:  "", // the api fills this in for mock mode (no real Headscale to assign)
		Routes:     append([]string{}, in.AdvertiseRoutes...),
		EnrolledAt: time.Now().UTC(),
	}
	if err := b.persistLocked(); err != nil {
		return Status{}, err
	}
	return Status{
		Enrolled:  true,
		Hostname:  in.Hostname,
		Routes:    b.state.Routes,
		PeerCount: 0,
	}, nil
}

func (b *MockBackend) Leave(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = mockTSState{}
	return b.persistLocked()
}

func (b *MockBackend) Status(_ context.Context) (Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Status{
		Enrolled:  b.state.Enrolled,
		Hostname:  b.state.Hostname,
		TailnetIP: b.state.TailnetIP,
		Routes:    b.state.Routes,
	}, nil
}
