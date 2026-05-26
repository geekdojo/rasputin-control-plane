package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// MockBackend persists per-app state to disk without running any real
// containers. Used when Docker isn't available or RASPUTIN_DOCKER_BACKEND=mock.
type MockBackend struct {
	mu  sync.Mutex
	dir string
}

func NewMockBackend(dir string) (*MockBackend, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("docker-mock: mkdir: %w", err)
	}
	return &MockBackend{dir: dir}, nil
}

func (m *MockBackend) Name() string { return "mock" }

type mockState struct {
	AppID     string    `json:"appId"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	DeployedAt time.Time `json:"deployedAt,omitempty"`
	StoppedAt  time.Time `json:"stoppedAt,omitempty"`
}

func (m *MockBackend) appDir(appID string) string {
	return filepath.Join(m.dir, appID)
}

func (m *MockBackend) statePath(appID string) string {
	return filepath.Join(m.appDir(appID), "state.json")
}

func (m *MockBackend) composePath(appID string) string {
	return filepath.Join(m.appDir(appID), "docker-compose.yml")
}

func (m *MockBackend) loadState(appID string) (*mockState, error) {
	b, err := os.ReadFile(m.statePath(appID))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &mockState{AppID: appID, Status: string(proto.AppStatusStopped)}, nil
		}
		return nil, err
	}
	var s mockState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (m *MockBackend) saveState(s *mockState) error {
	if err := os.MkdirAll(m.appDir(s.AppID), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.statePath(s.AppID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath(s.AppID))
}

func (m *MockBackend) Deploy(ctx context.Context, appID, name, composeYAML string) (proto.AppStatus, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.MkdirAll(m.appDir(appID), 0o755); err != nil {
		return proto.AppStatusFailed, "mkdir: " + err.Error(), err
	}
	if err := os.WriteFile(m.composePath(appID), []byte(composeYAML), 0o644); err != nil {
		return proto.AppStatusFailed, "write compose: " + err.Error(), err
	}
	s := &mockState{
		AppID:      appID,
		Name:       name,
		Status:     string(proto.AppStatusRunning),
		DeployedAt: time.Now().UTC(),
	}
	if err := m.saveState(s); err != nil {
		return proto.AppStatusFailed, "save state: " + err.Error(), err
	}
	return proto.AppStatusRunning, "mock backend: pretend-deployed", nil
}

func (m *MockBackend) Stop(ctx context.Context, appID string) (proto.AppStatus, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.loadState(appID)
	if err != nil {
		return proto.AppStatusUnknown, err.Error(), err
	}
	s.Status = string(proto.AppStatusStopped)
	s.StoppedAt = time.Now().UTC()
	if err := m.saveState(s); err != nil {
		return proto.AppStatusFailed, "save state: " + err.Error(), err
	}
	return proto.AppStatusStopped, "mock backend: pretend-stopped", nil
}

func (m *MockBackend) Status(ctx context.Context, appID string) (proto.AppStatus, []proto.AppServiceStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.loadState(appID)
	if err != nil {
		return proto.AppStatusUnknown, nil, err
	}
	return proto.AppStatus(s.Status), nil, nil
}
