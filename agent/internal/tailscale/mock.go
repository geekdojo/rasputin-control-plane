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

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
)

// MockBackend file-backs state in <stateDir>/tailscale.json. Mimics the
// shape of `tailscale status --json` enough to drive the api saga.
type MockBackend struct {
	mu        sync.Mutex
	statePath string
	trust     TrustInstaller // the node's trust bundle, for a legacy enroll's bundle
	state     mockTSState
}

type mockTSState struct {
	Enrolled   bool      `json:"enrolled"`
	Hostname   string    `json:"hostname"`
	TailnetIP  string    `json:"tailnetIp"`
	Routes     []string  `json:"routes"`
	EnrolledAt time.Time `json:"enrolledAt"`
}

// NewMockBackend file-backs the mock in stateDir, installing a legacy
// enroll's bundle through trust.
func NewMockBackend(stateDir string, trust TrustInstaller) (*MockBackend, error) {
	if trust == nil {
		return nil, errors.New("tailscale mock: a TrustInstaller is required")
	}
	if err := atrest.EnsureSecretDir(stateDir); err != nil {
		return nil, fmt.Errorf("tailscale mock: mkdir %s: %w", stateDir, err)
	}
	b := &MockBackend{
		statePath: filepath.Join(stateDir, "tailscale.json"),
		trust:     trust,
	}
	// An existing install's file was written 0644 by an older agent and is
	// not rewritten until something changes it. Tighten it at start.
	if err := atrest.TightenIfExists(b.statePath); err != nil {
		return nil, fmt.Errorf("tailscale mock: %w", err)
	}
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *MockBackend) Name() string { return "mock" }

// TrustFingerprint is the fingerprint of the node's trust bundle.
func (b *MockBackend) TrustFingerprint() string { return b.trust.Fingerprint() }

// ReloadTrust is a no-op: there is no tailscaled to reload.
func (b *MockBackend) ReloadTrust(context.Context) error { return nil }

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
	buf, err := json.MarshalIndent(b.state, "", "  ")
	if err != nil {
		return err
	}
	return atrest.WriteSecretFile(b.statePath, buf)
}

func (b *MockBackend) Enroll(_ context.Context, in EnrollInput) (Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if in.AuthKey == "" {
		return Status{}, errors.New("tailscale mock: empty auth key")
	}
	// Keep a legacy enroll's bundle the way the real backend does (minus
	// the tailscaled restart, there being no tailscaled).
	if len(in.LegacyTrustBundlePEM) > 0 {
		if _, err := b.trust.Install(in.LegacyTrustBundlePEM); err != nil {
			return Status{}, fmt.Errorf("tailscale mock: install trust bundle: %w", err)
		}
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
