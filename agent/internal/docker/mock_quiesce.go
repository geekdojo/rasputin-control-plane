package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The mock half of the quiesce seam — see quiesce.go for the real one.
//
// The mock's volumes are ordinary directories at
// <dir>/<appID>/volumes/<volume>, so a dev control plane or a test gets a
// real path with real files in it, and the drivers' copy code — the part that
// runs unchanged on hardware — is exercised against a real filesystem. What
// the mock stands in for is the container runtime: stop and start flip the
// persisted status, and a "snapshot" is a file copy standing in for what a
// real container's SQLite would do through its own locks.
//
// Two fidelity rules that matter to the drivers' tests:
//
//   - SnapshotSQLite REFUSES when the app is not running, exactly as `docker
//     exec` has no container to run in. The sqlite driver's fallback for a
//     stopped app (a plain copy, which is consistent because nothing writes)
//     is only testable if the mock says no here.
//   - StopApp/StartApp are the compose stop/start pair and leave the compose
//     file in place; Stop (the Backend method, `down`) still marks the app
//     stopped too. AppRunning reads the same persisted status either way.
//
// Failure injection, mirroring the storage mock's RASPUTIN_STORAGE_FAIL_MODE:
//
//	RASPUTIN_DOCKER_FAIL_MODE=none      — happy path (default)
//	RASPUTIN_DOCKER_FAIL_MODE=stop      — StopApp fails; the app stays running
//	RASPUTIN_DOCKER_FAIL_MODE=start     — StartApp fails; the app stays stopped
//	                                      (the watchdog's retry case)
//	RASPUTIN_DOCKER_FAIL_MODE=snapshot  — SnapshotSQLite fails
//
// Read per call rather than at construction, so a test can flip it with
// t.Setenv between steps of one scenario.
const mockFailModeEnv = "RASPUTIN_DOCKER_FAIL_MODE"

func mockFailMode() string { return strings.TrimSpace(os.Getenv(mockFailModeEnv)) }

// VolumeDir returns the host directory that stands in for the app's compose
// volume, creating it. This is how a test or a dev seed puts files "in the
// volume"; ResolveVolume only ever finds what this created.
func (m *MockBackend) VolumeDir(appID, volume string) (string, error) {
	dir := filepath.Join(m.appDir(appID), "volumes", volume)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// ResolveVolume returns the volume directory if it exists, and
// ErrVolumeNotFound if it does not — a tile that declares a volume its stack
// never created is the same refusal on the real backend.
func (m *MockBackend) ResolveVolume(_ context.Context, appID, volume string) (string, error) {
	dir := filepath.Join(m.appDir(appID), "volumes", volume)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: app %s, volume %q", ErrVolumeNotFound, appID, volume)
	}
	return dir, nil
}

// AppRunning reads the persisted status.
func (m *MockBackend) AppRunning(_ context.Context, appID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.loadState(appID)
	if err != nil {
		return false, err
	}
	return s.Status == string(proto.AppStatusRunning) || s.Status == string(proto.AppStatusDeploying), nil
}

// StopApp is `compose stop`: the app reads as stopped, and its compose file
// and volumes stay where they are.
func (m *MockBackend) StopApp(_ context.Context, appID string, _ int) error {
	if mockFailMode() == "stop" {
		return errors.New("mock backend: injected stop failure (RASPUTIN_DOCKER_FAIL_MODE=stop)")
	}
	return m.setStatus(appID, proto.AppStatusStopped)
}

// StartApp is `compose start`.
func (m *MockBackend) StartApp(_ context.Context, appID string) error {
	if mockFailMode() == "start" {
		return errors.New("mock backend: injected start failure (RASPUTIN_DOCKER_FAIL_MODE=start)")
	}
	return m.setStatus(appID, proto.AppStatusRunning)
}

func (m *MockBackend) setStatus(appID string, status proto.AppStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.loadState(appID)
	if err != nil {
		return err
	}
	s.Status = string(status)
	return m.saveState(s)
}

// SnapshotSQLite copies the database file to the destination, standing in for
// a container-side VACUUM INTO. Refuses when the app is not running, because
// the real one has no container to exec into then.
func (m *MockBackend) SnapshotSQLite(ctx context.Context, appID, volume, dbRel, dstRel string) (string, error) {
	if mockFailMode() == "snapshot" {
		return "", errors.New("mock backend: injected snapshot failure (RASPUTIN_DOCKER_FAIL_MODE=snapshot)")
	}
	running, err := m.AppRunning(ctx, appID)
	if err != nil {
		return "", err
	}
	if !running {
		return "", fmt.Errorf("%w: app %s is not running", ErrNoRunningContainer, appID)
	}
	root, err := m.ResolveVolume(ctx, appID, volume)
	if err != nil {
		return "", err
	}
	src := filepath.Join(root, filepath.FromSlash(dbRel))
	dst := filepath.Join(root, filepath.FromSlash(dstRel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", err
	}
	return "mock", out.Close()
}
