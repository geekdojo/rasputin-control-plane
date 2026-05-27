package mesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Client is the small surface we use to talk to Headscale. v0 ships a
// MockClient that file-backs everything; the real client (TODO v1) wraps
// Headscale's REST/gRPC API. The interface is shaped to fit Headscale's
// real surface so swapping is a drop-in.
type Client interface {
	// Backend returns "headscale" or "mock". Surfaced in change events.
	Backend() string

	// CreatePreAuthKey mints a key for the given user. Returns the
	// Headscale-side id and the plaintext key value (only available at
	// creation time).
	CreatePreAuthKey(ctx context.Context, in CreatePreAuthKeyInput) (id, value string, err error)

	// ExpirePreAuthKey revokes a key by id. Subsequent uses are rejected.
	ExpirePreAuthKey(ctx context.Context, id string) error

	// ListPreAuthKeys returns every key Headscale knows about for the
	// given user (or all users if user is "").
	ListPreAuthKeys(ctx context.Context, user string) ([]HSPreAuthKey, error)

	// ListNodes returns every device registered with Headscale.
	ListNodes(ctx context.Context) ([]HSNode, error)

	// SetNodeRoutes approves a set of advertised routes on a node. The
	// node has to have already advertised them via `tailscale up
	// --advertise-routes`; this is the approval step.
	SetNodeRoutes(ctx context.Context, nodeID string, cidrs []string) error

	// EnsureUser creates the user if it doesn't exist; idempotent.
	EnsureUser(ctx context.Context, name string) error
}

// CreatePreAuthKeyInput captures the params for a key.
type CreatePreAuthKeyInput struct {
	User      string
	Reusable  bool
	Ephemeral bool
	Expiry    time.Time
	Tags      []string
}

// HSPreAuthKey is the Headscale-side view of a key. Mirrors the upstream
// API's PreAuthKey response shape but trims fields we don't use.
type HSPreAuthKey struct {
	ID         string    `json:"id"`
	User       string    `json:"user"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	Tags       []string  `json:"tags"`
	// Plaintext is only set on the response from Create; subsequent List
	// calls leave it empty.
	Plaintext string `json:"plaintext,omitempty"`
}

// HSNode is the Headscale-side view of a registered device.
type HSNode struct {
	ID                string    `json:"id"`
	User              string    `json:"user"`
	Hostname          string    `json:"hostname"`
	GivenName         string    `json:"givenName"`
	IPv4              string    `json:"ipv4"`
	IPv6              string    `json:"ipv6"`
	Tags              []string  `json:"tags"`
	AdvertisedRoutes  []string  `json:"advertisedRoutes"`
	ApprovedRoutes    []string  `json:"approvedRoutes"`
	RegisteredAt      time.Time `json:"registeredAt"`
	LastSeen          time.Time `json:"lastSeen"`
}

// ----- MockClient ---------------------------------------------------------

// MockClient is a file-backed Headscale stand-in. State lives in
// <stateDir>/headscale.json. Concurrency-safe under a mutex.
//
// Behaviors that match real Headscale closely enough for the saga to
// exercise apply / reconcile paths:
//
//   - CreatePreAuthKey persists the key with a generated value and id.
//     The value is `mock-<ulid>` to be visually distinct from real keys.
//   - ListNodes returns devices recorded via UpsertMockNode (the agent
//     simulator calls that in dev to register itself "into the tailnet").
//   - SetNodeRoutes overwrites the approved set on the node.
//
// In production the real Headscale client supersedes this; the interface
// shape is identical so callers don't change.
type MockClient struct {
	mu       sync.Mutex
	statePath string
	state    mockState
}

type mockState struct {
	Users        map[string]bool         `json:"users"`
	PreAuthKeys  map[string]HSPreAuthKey `json:"preauth_keys"`
	Nodes        map[string]HSNode       `json:"nodes"`
}

func NewMockClient(stateDir string) (*MockClient, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("mesh mock: mkdir %s: %w", stateDir, err)
	}
	mc := &MockClient{
		statePath: filepath.Join(stateDir, "headscale.json"),
		state: mockState{
			Users:       map[string]bool{},
			PreAuthKeys: map[string]HSPreAuthKey{},
			Nodes:       map[string]HSNode{},
		},
	}
	if err := mc.load(); err != nil {
		return nil, err
	}
	return mc, nil
}

func (m *MockClient) Backend() string { return "mock" }

func (m *MockClient) load() error {
	buf, err := os.ReadFile(m.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m.persistLocked()
		}
		return err
	}
	return json.Unmarshal(buf, &m.state)
}

func (m *MockClient) persistLocked() error {
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

func (m *MockClient) EnsureUser(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.state.Users[name] {
		m.state.Users[name] = true
		return m.persistLocked()
	}
	return nil
}

func (m *MockClient) CreatePreAuthKey(_ context.Context, in CreatePreAuthKeyInput) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.state.Users[in.User] {
		m.state.Users[in.User] = true
	}
	id := ulid.Make().String()
	value := "mock-" + ulid.Make().String()
	tagsCopy := append([]string{}, in.Tags...)
	sort.Strings(tagsCopy)
	m.state.PreAuthKeys[id] = HSPreAuthKey{
		ID:         id,
		User:       in.User,
		Reusable:   in.Reusable,
		Ephemeral:  in.Ephemeral,
		Used:       false,
		Expiration: in.Expiry,
		CreatedAt:  time.Now().UTC(),
		Tags:       tagsCopy,
	}
	if err := m.persistLocked(); err != nil {
		return "", "", err
	}
	return id, value, nil
}

func (m *MockClient) ExpirePreAuthKey(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.state.PreAuthKeys[id]
	if !ok {
		return errors.New("preauth key not found")
	}
	k.Expiration = time.Now().Add(-time.Second).UTC()
	m.state.PreAuthKeys[id] = k
	return m.persistLocked()
}

func (m *MockClient) ListPreAuthKeys(_ context.Context, user string) ([]HSPreAuthKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HSPreAuthKey, 0, len(m.state.PreAuthKeys))
	for _, k := range m.state.PreAuthKeys {
		if user != "" && k.User != user {
			continue
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MockClient) ListNodes(_ context.Context) ([]HSNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HSNode, 0, len(m.state.Nodes))
	for _, n := range m.state.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MockClient) SetNodeRoutes(_ context.Context, nodeID string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.state.Nodes[nodeID]
	if !ok {
		return fmt.Errorf("node %s not found", nodeID)
	}
	cp := append([]string{}, cidrs...)
	sort.Strings(cp)
	n.ApprovedRoutes = cp
	m.state.Nodes[nodeID] = n
	return m.persistLocked()
}

// UpsertMockNode is a dev helper called by the api when an agent reports
// successful (mock) enrollment. Lets the mock client mirror what a real
// Headscale would do when an agent ran `tailscale up`.
func (m *MockClient) UpsertMockNode(n HSNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n.ID == "" {
		// Derive a stable id from hostname+user so re-enrollment is idempotent.
		h := sha256.Sum256([]byte(n.User + "|" + n.Hostname))
		n.ID = "mock-" + hex.EncodeToString(h[:8])
	}
	if n.RegisteredAt.IsZero() {
		n.RegisteredAt = time.Now().UTC()
	}
	n.LastSeen = time.Now().UTC()
	m.state.Nodes[n.ID] = n
	return m.persistLocked()
}
