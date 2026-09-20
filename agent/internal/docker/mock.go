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

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// MockBackend persists per-app state to disk without running any real
// containers. Used when Docker isn't available or RASPUTIN_DOCKER_BACKEND=mock.
type MockBackend struct {
	mu  sync.Mutex
	dir string
}

// NewMockBackend roots the mock at dir. The at-rest rules are the real
// backend's (0700 directories, 0600 files): the mock writes the same compose
// the real one would, and a dev box running it is a node like any other.
func NewMockBackend(dir string) (*MockBackend, error) {
	if err := atrest.EnsureSecretDir(dir); err != nil {
		return nil, fmt.Errorf("docker-mock: mkdir: %w", err)
	}
	TightenAppState(dir)
	return &MockBackend{dir: dir}, nil
}

func (m *MockBackend) Name() string { return "mock" }

type mockState struct {
	AppID      string    `json:"appId"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	DeployedAt time.Time `json:"deployedAt,omitempty"`
	StoppedAt  time.Time `json:"stoppedAt,omitempty"`
	// VolumesDeleted records that the last Stop asked for `down -v`. The mock
	// has no volumes; this is so a test can see the flag arrived.
	VolumesDeleted bool `json:"volumesDeleted,omitempty"`
}

func (m *MockBackend) appDir(appID string) string {
	return filepath.Join(m.dir, appID)
}

// mockStateFileName is the mock backend's per-app state file. Named so
// TightenAppState, which serves both backends, can reach it.
const mockStateFileName = "state.json"

func (m *MockBackend) statePath(appID string) string {
	return filepath.Join(m.appDir(appID), mockStateFileName)
}

func (m *MockBackend) composePath(appID string) string {
	return filepath.Join(m.appDir(appID), composeFileName)
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
	if err := atrest.EnsureSecretDir(m.appDir(s.AppID)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atrest.WriteSecretFile(m.statePath(s.AppID), b)
}

func (m *MockBackend) Deploy(ctx context.Context, appID, name, composeYAML string) (proto.AppStatus, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := atrest.EnsureSecretDir(m.appDir(appID)); err != nil {
		return proto.AppStatusFailed, "mkdir: " + err.Error(), err
	}
	if err := atrest.WriteSecretFile(m.composePath(appID), []byte(composeYAML)); err != nil {
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

// Pull pretends to fetch the images. It writes nothing — in particular not the
// app's compose file, which is the contract the real backend keeps.
func (m *MockBackend) Pull(ctx context.Context, appID, composeYAML string) (string, error) {
	return "", nil
}

// CheckVolumes answers that the mock drops nothing: it runs no containers and
// has no volumes, so no compose can orphan one. Nothing is declared either —
// the mock cannot read a compose the way Compose does, and says nothing rather
// than guess.
func (m *MockBackend) CheckVolumes(ctx context.Context, appID, composeYAML string) ([]string, []proto.AppDroppedVolume, error) {
	return []string{}, []proto.AppDroppedVolume{}, nil
}

func (m *MockBackend) Stop(ctx context.Context, appID string, deleteVolumes bool) (proto.AppStatus, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.loadState(appID)
	if err != nil {
		return proto.AppStatusUnknown, err.Error(), err
	}
	s.Status = string(proto.AppStatusStopped)
	s.StoppedAt = time.Now().UTC()
	s.VolumesDeleted = deleteVolumes
	if err := m.saveState(s); err != nil {
		return proto.AppStatusFailed, "save state: " + err.Error(), err
	}
	if deleteVolumes {
		return proto.AppStatusStopped, "mock backend: pretend-stopped, pretend-deleted volumes", nil
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
