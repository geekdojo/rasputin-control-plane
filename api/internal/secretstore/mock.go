package secretstore

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Mock is an in-memory kv-v2 store with the client's semantics: check-and-set
// on every write, numbered versions from 1, latest or a given version on
// read, and ErrNotFound for a path or version that does not exist. It is used
// only when a configuration selects it by name. Values are copied in and out,
// so neither a caller's later change nor its Destroy reaches what the mock
// holds. Tokens are accepted and ignored.
type Mock struct {
	now func() time.Time

	mu      sync.Mutex
	secrets map[KVPath]*mockSecret
}

type mockSecret struct {
	created, updated time.Time
	versions         []mockVersion // versions[i] is version i+1
}

type mockVersion struct {
	data    map[string]secret.Value
	created time.Time
}

// NewMock returns an empty Mock that dates versions with now. A nil now is a
// wiring mistake and panics here rather than at the first write.
func NewMock(now func() time.Time) *Mock {
	if now == nil {
		panic("secretstore: NewMock: now is nil")
	}
	return &Mock{now: now, secrets: map[KVPath]*mockSecret{}}
}

// Health reports an initialised, unsealed store.
func (m *Mock) Health(context.Context) (Health, error) {
	return Health{Initialized: true}, nil
}

// Read returns a copy of version of the secret at p, or of the latest when
// version is 0.
func (m *Mock) Read(_ context.Context, _ secret.Value, p KVPath, version int) (KV, error) {
	const op = "read"
	if !p.valid() {
		return KV{}, fail(op, p, ErrInvalidValue, errors.New("the path is the zero KVPath"))
	}
	if version < 0 {
		return KV{}, fail(op, p, ErrInvalidValue, errors.New("version is negative"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[p]
	if !ok {
		return KV{}, fail(op, p, ErrNotFound, nil)
	}
	if version == 0 {
		version = len(s.versions)
	}
	if version > len(s.versions) {
		return KV{}, fail(op, p, ErrNotFound, errors.New("no such version"))
	}
	v := s.versions[version-1]
	return KV{Data: copyValues(v.data), Version: version, CreatedTime: v.created}, nil
}

// Write stores a copy of data as a new version when cas is the current
// version (0 for a secret that does not exist yet).
func (m *Mock) Write(_ context.Context, _ secret.Value, p KVPath, data map[string]secret.Value, cas int) (int, error) {
	const op = "write"
	if !p.valid() {
		return 0, fail(op, p, ErrInvalidValue, errors.New("the path is the zero KVPath"))
	}
	if err := checkWrite(data, cas); err != nil {
		return 0, fail(op, p, ErrInvalidValue, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[p]
	current := 0
	if ok {
		current = len(s.versions)
	}
	if cas != current {
		return 0, fail(op, p, ErrCASMismatch, nil)
	}
	now := m.now()
	if !ok {
		s = &mockSecret{created: now}
		m.secrets[p] = s
	}
	s.updated = now
	s.versions = append(s.versions, mockVersion{data: copyValues(data), created: now})
	return len(s.versions), nil
}

// Versions returns the version history of the secret at p.
func (m *Mock) Versions(_ context.Context, _ secret.Value, p KVPath) (Metadata, error) {
	const op = "versions"
	if !p.valid() {
		return Metadata{}, fail(op, p, ErrInvalidValue, errors.New("the path is the zero KVPath"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[p]
	if !ok {
		return Metadata{}, fail(op, p, ErrNotFound, nil)
	}
	md := Metadata{
		CurrentVersion: len(s.versions),
		OldestVersion:  1,
		CreatedTime:    s.created,
		UpdatedTime:    s.updated,
		Versions:       make(map[int]VersionMetadata, len(s.versions)),
	}
	for i, v := range s.versions {
		md.Versions[i+1] = VersionMetadata{CreatedTime: v.created}
	}
	return md, nil
}

// copyValues gives every value its own payload, so the copy outlives a
// Destroy of the original and the original outlives a Destroy of the copy.
func copyValues(in map[string]secret.Value) map[string]secret.Value {
	out := make(map[string]secret.Value, len(in))
	for k, v := range in {
		out[k] = secret.New(v.Reveal())
	}
	return out
}
