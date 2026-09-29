package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/system"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// MockBackend simulates the RAUC lifecycle with file-backed state. State
// lives at <stateDir>/state.json and bundles are cached at
// <stateDir>/bundles/<sha>.bin.
//
// The mock supports a "force-fail" mode for test scenarios: setting
// RASPUTIN_UPDATE_FAIL_MODE controls deterministic failure injection.
//
//	"none"      — happy path (default)
//	"panic"     — after reboot, mock comes back on the old slot (scenario A)
//	"health"    — health check fails after reboot (scenario B); the saga
//	              will then send mark-bad, and we reboot back to old slot
//	"download"  — Download() returns an error
type MockBackend struct {
	stateDir string
	mu       sync.Mutex
	// rebooter is the agent's one reboot function. With the mock selected on
	// a dev image it SIMULATES (system.Rebooter.EnableSimulation), and calls
	// back into afterSimulatedBoot to flip the slot model.
	rebooter Rebooter
}

// State persisted between agent restarts so the slot model survives.
type mockState struct {
	ActiveSlot     proto.UpdateSlot `json:"activeSlot"`
	InactiveSlot   proto.UpdateSlot `json:"inactiveSlot"`
	CurrentVersion string           `json:"currentVersion"`
	// PendingSlot is set by Install; consumed by Reboot. Empty means
	// "no install pending."
	PendingSlot    proto.UpdateSlot `json:"pendingSlot"`
	PendingVersion string           `json:"pendingVersion"`
	PendingBundle  string           `json:"pendingBundle"`
	// Marks tracks the per-slot good/bad state. RAUC has its own model;
	// we keep a minimal one.
	Marks map[proto.UpdateSlot]proto.UpdateSlotState `json:"marks"`
}

// NewMockBackend opens (and initialises) a MockBackend rooted at stateDir.
// The first run writes a sensible default state.
func NewMockBackend(stateDir string) (*MockBackend, error) {
	if err := atrest.EnsureSecretDir(filepath.Join(stateDir, "bundles")); err != nil {
		return nil, err
	}
	m := &MockBackend{stateDir: stateDir}
	// An existing install's file was written 0644 by an older agent and is
	// not rewritten until something changes it. Tighten it at start.
	if err := atrest.TightenIfExists(m.statePath()); err != nil {
		return nil, err
	}
	if _, err := m.loadState(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		// Seed default.
		st := mockState{
			ActiveSlot:     proto.SlotA,
			InactiveSlot:   proto.SlotB,
			CurrentVersion: "0.0.0-dev",
			Marks: map[proto.UpdateSlot]proto.UpdateSlotState{
				proto.SlotA: proto.SlotStateGood,
				proto.SlotB: proto.SlotStateInactive,
			},
		}
		if err := m.saveState(&st); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// SetRebooter wires the agent's one reboot function.
func (m *MockBackend) SetRebooter(rb Rebooter) { m.rebooter = rb }

func (m *MockBackend) statePath() string { return filepath.Join(m.stateDir, "state.json") }

func (m *MockBackend) loadState() (*mockState, error) {
	b, err := os.ReadFile(m.statePath())
	if err != nil {
		return nil, err
	}
	var st mockState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if st.Marks == nil {
		st.Marks = map[proto.UpdateSlot]proto.UpdateSlotState{}
	}
	return &st, nil
}

func (m *MockBackend) saveState(st *mockState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atrest.WriteSecretFile(m.statePath(), b)
}

func (m *MockBackend) Name() string { return "mock" }

func (m *MockBackend) Precheck(ctx context.Context) (*proto.UpdatePrecheckAck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.loadState()
	if err != nil {
		return &proto.UpdatePrecheckAck{OK: false, Detail: err.Error()}, nil
	}
	// "Available bytes" is a believable made-up number for the inactive
	// slot. Real backends report from statfs.
	return &proto.UpdatePrecheckAck{
		OK:             true,
		ActiveSlot:     st.ActiveSlot,
		InactiveSlot:   st.InactiveSlot,
		CurrentVersion: st.CurrentVersion,
		AvailableBytes: 16 * (1 << 30), // 16 GiB
		Backend:        "mock",
	}, nil
}

// Download ignores sigURL: the mock backend exists for dev and CI, where the
// artifact is a synthetic blob nobody signed. It is never selected on the
// firewall — main.go picks it only by explicit RASPUTIN_UPDATE_BACKEND=mock —
// so ignoring the signature here cannot weaken a shipping node.
func (m *MockBackend) Download(ctx context.Context, bundleID, url, _, expectedSHA string, sizeBytes int64,
	progressFn func(bytesCompleted, bytesTotal int64)) (string, string, error) {

	if os.Getenv("RASPUTIN_UPDATE_FAIL_MODE") == "download" {
		return "", "", errors.New("simulated download failure (RASPUTIN_UPDATE_FAIL_MODE=download)")
	}

	// Same rule as the real backends, deliberately: the mock is what dev and
	// CI exercise, so a path check it does not share is one nothing tests.
	dest, err := resolveBundlePath(m.stateDir, bundleID, "", ".bin")
	if err != nil {
		return "", "", err
	}
	// Same rule as the real backends, for the same reason given above: a check
	// the mock skips is a check dev and CI never exercise.
	if err := requireExpectedSHA(bundleID, expectedSHA); err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("http %d", resp.StatusCode)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(dest), "download-*.tmp")
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	total := resp.ContentLength
	if total <= 0 {
		total = sizeBytes
	}
	hasher := sha256.New()
	mw := io.MultiWriter(tmpFile, hasher)
	written := int64(0)
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := mw.Write(buf[:n]); werr != nil {
				tmpFile.Close()
				return "", "", werr
			}
			written += int64(n)
			if progressFn != nil {
				progressFn(written, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			tmpFile.Close()
			return "", "", rerr
		}
	}
	if err := tmpFile.Close(); err != nil {
		return "", "", err
	}
	observed := hex.EncodeToString(hasher.Sum(nil))
	// Unconditional — see requireExpectedSHA.
	if observed != expectedSHA {
		return "", observed, fmt.Errorf("sha mismatch: expected %s got %s", expectedSHA, observed)
	}
	if err := os.Rename(tmpFile.Name(), dest); err != nil {
		return "", "", err
	}
	return dest, observed, nil
}

func (m *MockBackend) Install(ctx context.Context, bundleID, localPath string, targetSlot proto.UpdateSlot,
	progressFn func(phase string, percent int)) (string, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	// Resolve localPath from cache if the api didn't give us one, and refuse
	// one that points outside the bundle store — same rule as the real
	// backends.
	localPath, err := resolveBundlePath(m.stateDir, bundleID, localPath, ".bin")
	if err != nil {
		return "", err
	}
	buf, err := os.ReadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("read bundle: %w", err)
	}
	// Parse the mock envelope to get the manifest. Real RAUC would do
	// this from its squashfs manifest.
	var env struct {
		Manifest proto.BundleManifest `json:"manifest"`
	}
	if err := json.Unmarshal(buf, &env); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}

	// Simulate install phases.
	phases := []struct {
		name    string
		percent int
		sleep   time.Duration
	}{
		{"verify", 10, 200 * time.Millisecond},
		{"extract", 40, 400 * time.Millisecond},
		{"write", 80, 400 * time.Millisecond},
		{"post-install", 100, 200 * time.Millisecond},
	}
	for _, p := range phases {
		if progressFn != nil {
			progressFn(p.name, p.percent)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(p.sleep):
		}
	}

	st, err := m.loadState()
	if err != nil {
		return "", err
	}
	st.PendingSlot = targetSlot
	st.PendingVersion = env.Manifest.Version
	st.PendingBundle = bundleID
	st.Marks[targetSlot] = proto.SlotStateInactive
	if err := m.saveState(st); err != nil {
		return "", err
	}
	return env.Manifest.Version, nil
}

func (m *MockBackend) Reboot(ctx context.Context, bundleID string, delaySeconds int) (int, error) {
	// The mock has no reboot of its own. It asks the agent's one reboot
	// function, which SIMULATES when the dev mock was selected and then calls
	// afterSimulatedBoot; heartbeat mute and re-registration are the
	// Rebooter's, exactly as for a real reboot.
	return requestReboot(m.rebooter, system.RebootRequest{
		Reason:             rebootReason("update.reboot", bundleID),
		Mode:               system.RebootPlain,
		DelaySeconds:       delaySeconds,
		AfterSimulatedBoot: m.afterSimulatedBoot,
	})
}

// afterSimulatedBoot flips the slot model the way a boot into the pending
// slot would. It runs only inside a simulated reboot.
func (m *MockBackend) afterSimulatedBoot() {
	m.mu.Lock()
	st, err := m.loadState()
	if err != nil {
		m.mu.Unlock()
		return
	}
	failMode := os.Getenv("RASPUTIN_UPDATE_FAIL_MODE")
	switch failMode {
	case "panic":
		// Scenario A: bootloader rolls back. The pending slot is dropped;
		// the active slot stays where it was.
		st.Marks[st.PendingSlot] = proto.SlotStateBad
		st.PendingSlot = proto.SlotUnknown
		st.PendingVersion = ""
		st.PendingBundle = ""
	default:
		// Normal boot into pending slot.
		if st.PendingSlot != proto.SlotUnknown && st.PendingSlot != "" {
			old := st.ActiveSlot
			st.ActiveSlot = st.PendingSlot
			st.InactiveSlot = old
			st.CurrentVersion = st.PendingVersion
			st.Marks[st.ActiveSlot] = proto.SlotStateActive
			st.Marks[old] = proto.SlotStateInactive
			st.PendingSlot = proto.SlotUnknown
			st.PendingVersion = ""
			st.PendingBundle = ""
		}
	}
	_ = m.saveState(st)
	m.mu.Unlock()
}

func (m *MockBackend) MarkGood(ctx context.Context, bundleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.loadState()
	if err != nil {
		return err
	}
	st.Marks[st.ActiveSlot] = proto.SlotStateGood
	return m.saveState(st)
}

func (m *MockBackend) MarkBad(ctx context.Context, bundleID, reason string) error {
	m.mu.Lock()
	st, err := m.loadState()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	bad := st.ActiveSlot
	good := st.InactiveSlot
	st.Marks[bad] = proto.SlotStateBad
	st.ActiveSlot = good
	st.InactiveSlot = bad
	st.Marks[good] = proto.SlotStateActive
	st.CurrentVersion = "0.0.0-dev" // we don't track per-slot versions in the mock
	if err := m.saveState(st); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()

	// Reboot back to the good slot. The slot model was already flipped
	// above, so there is nothing to do when the simulated node comes back.
	if _, err := requestReboot(m.rebooter, system.RebootRequest{
		Reason:       rebootReason("update.mark-bad", bundleID),
		Mode:         system.RebootPlain,
		DelaySeconds: 2,
	}); err != nil {
		log.Printf("rasputin-agent: updater mock: slot marked bad, but the reboot was refused: %v", err)
	}
	return nil
}
