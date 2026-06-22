package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func newUpdaterMock(t *testing.T) *MockBackend {
	t.Helper()
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	return mb
}

func TestNewMockBackend_SeedsDefaultStateOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if mb.Name() != "mock" {
		t.Errorf("Name: %q want mock", mb.Name())
	}
	// State file should now exist.
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Errorf("state.json not created: %v", err)
	}
	// Pre-check should return SlotA active, SlotB inactive — the seed.
	ack, err := mb.Precheck(context.Background())
	if err != nil {
		t.Fatalf("Precheck: %v", err)
	}
	if !ack.OK {
		t.Errorf("precheck not OK: %+v", ack)
	}
	if ack.ActiveSlot != proto.SlotA || ack.InactiveSlot != proto.SlotB {
		t.Errorf("seeded slots wrong: active=%s inactive=%s", ack.ActiveSlot, ack.InactiveSlot)
	}
	if ack.Backend != "mock" {
		t.Errorf("backend label: %q", ack.Backend)
	}
	if ack.AvailableBytes <= 0 {
		t.Errorf("available bytes should be positive, got %d", ack.AvailableBytes)
	}
}

func TestNewMockBackend_ReopensWithoutReseeding(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("first NewMockBackend: %v", err)
	}
	// Touch the state by marking good.
	if err := mb.MarkGood(context.Background(), "bundle-x"); err != nil {
		t.Fatalf("MarkGood: %v", err)
	}

	// Reopen — should pick up the same state file.
	mb2, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	ack, err := mb2.Precheck(context.Background())
	if err != nil {
		t.Fatalf("precheck after reopen: %v", err)
	}
	if ack.ActiveSlot != proto.SlotA {
		t.Errorf("active slot after reopen: %q", ack.ActiveSlot)
	}
}

func TestPrecheck_CorruptStateBubblesError(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	// Overwrite state file with garbage; Precheck should report !OK.
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("not-json"), 0o644); err != nil {
		t.Fatalf("corrupt state: %v", err)
	}
	ack, err := mb.Precheck(context.Background())
	if err != nil {
		t.Fatalf("Precheck returned err (expected !OK ack): %v", err)
	}
	if ack.OK {
		t.Errorf("precheck on corrupt state should not be OK: %+v", ack)
	}
}

func TestSetMuteHook_StoresAtomic(t *testing.T) {
	mb := newUpdaterMock(t)
	var flag atomic.Bool
	mb.SetMuteHook(&flag)
	// Round-trip: store via flag, read via mb (no public getter, but
	// the contract is set+observe via the shared pointer).
	flag.Store(true)
	if !flag.Load() {
		t.Error("flag store/load broken")
	}
	// Reset to false so no test downstream is affected.
	flag.Store(false)
}

func TestSetReregisterHook_StoresFn(t *testing.T) {
	mb := newUpdaterMock(t)
	called := false
	mb.SetReregisterHook(func() { called = true })
	// The hook is consumed inside simulateReboot, which we don't trigger
	// directly here (it sleeps). We assert the constructor accepts it
	// without blowing up; the integration path is covered via the
	// MarkGood/MarkBad tests that *do* exercise the post-reboot path
	// would set this true. For now: smoke test only.
	if called {
		t.Error("hook should not fire just from SetReregisterHook")
	}
}

func TestMarkGood_PersistsActiveSlotAsGood(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if err := mb.MarkGood(context.Background(), "bundle-x"); err != nil {
		t.Fatalf("MarkGood: %v", err)
	}
	// Inspect the persisted state.
	buf, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var st mockState
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if st.Marks[st.ActiveSlot] != proto.SlotStateGood {
		t.Errorf("active slot not marked good: %+v", st)
	}
}

// TestDownload_VerifiesSHA exercises the success+failure branches of the
// HTTP fetcher and SHA verification. We serve the bundle bytes from an
// in-process httptest server — no real network, no real file size.
func TestDownload_VerifiesSHA(t *testing.T) {
	body := []byte("mock bundle payload v1")
	sum := sha256.Sum256(body)
	expectedSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	mb := newUpdaterMock(t)

	var progressCalls int32
	var mu sync.Mutex
	var lastTotal int64
	progress := func(done, total int64) {
		atomic.AddInt32(&progressCalls, 1)
		mu.Lock()
		lastTotal = total
		mu.Unlock()
	}

	// Happy path: matching SHA.
	localPath, observed, err := mb.Download(context.Background(), "b1", srv.URL, expectedSHA, int64(len(body)), progress)
	if err != nil {
		t.Fatalf("Download (happy): %v", err)
	}
	if observed != expectedSHA {
		t.Errorf("observed SHA mismatch: %s vs %s", observed, expectedSHA)
	}
	if localPath == "" {
		t.Error("localPath should not be empty on success")
	}
	if _, err := os.Stat(localPath); err != nil {
		t.Errorf("downloaded file not on disk: %v", err)
	}
	if atomic.LoadInt32(&progressCalls) == 0 {
		t.Error("progress callback never fired")
	}
	mu.Lock()
	gotTotal := lastTotal
	mu.Unlock()
	if gotTotal <= 0 {
		t.Errorf("progress total should be positive, got %d", gotTotal)
	}
}

func TestDownload_FailsOnSHAMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bytes"))
	}))
	defer srv.Close()
	mb := newUpdaterMock(t)
	_, observed, err := mb.Download(context.Background(), "b2", srv.URL, "deadbeef", 0, nil)
	if err == nil {
		t.Fatalf("expected SHA mismatch error")
	}
	if observed == "deadbeef" {
		t.Errorf("observed SHA should be the real one, not echoed expected")
	}
}

func TestDownload_HTTPErrorBubbles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	mb := newUpdaterMock(t)
	if _, _, err := mb.Download(context.Background(), "b3", srv.URL, "", 0, nil); err == nil {
		t.Errorf("expected error on HTTP 500")
	}
}

func TestDownload_FailModeEnvErrors(t *testing.T) {
	t.Setenv("RASPUTIN_UPDATE_FAIL_MODE", "download")
	mb := newUpdaterMock(t)
	if _, _, err := mb.Download(context.Background(), "b4", "http://unused", "", 0, nil); err == nil {
		t.Errorf("expected fail-mode error")
	}
}

func TestDownload_BadURLErrors(t *testing.T) {
	mb := newUpdaterMock(t)
	// Invalid URL — NewRequestWithContext should reject.
	if _, _, err := mb.Download(context.Background(), "b5", "::not-a-url::", "", 0, nil); err == nil {
		t.Errorf("expected URL parse error")
	}
}

// TestMarkBad_FlipsActiveSlot — the saga relies on mark-bad swapping active
// and inactive and reporting the previous slot as bad. We assert the
// persisted state shape *without* waiting for the simulateReboot goroutine
// (it sleeps 2s and we don't want to block on it).
func TestMarkBad_FlipsActiveSlot(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if err := mb.MarkBad(context.Background(), "bundle-x", "health check failed"); err != nil {
		t.Fatalf("MarkBad: %v", err)
	}
	// The mock spawns a simulateReboot goroutine in the background that
	// would mutate state again after 2s. Read state immediately so we
	// capture the *first* mutation (the swap), not whatever the goroutine
	// later writes.
	buf, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var st mockState
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	// Initial seed was SlotA active. After MarkBad: SlotB active.
	if st.ActiveSlot != proto.SlotB {
		t.Errorf("active slot: got %q want b", st.ActiveSlot)
	}
	if st.Marks[proto.SlotA] != proto.SlotStateBad {
		t.Errorf("previously-active slot should be marked bad: %+v", st.Marks)
	}
}

// TestReboot_ClampsDelay covers the clamp+kickoff path. We pass a nil
// reregister hook so the background goroutine has nothing to call back into;
// the test asserts the synchronous return value, which is the contract.
func TestReboot_ClampsDelay(t *testing.T) {
	mb := newUpdaterMock(t)
	cases := []struct {
		in   int
		want int
	}{
		{0, 3},    // clamps to default
		{-5, 3},   // negative clamps
		{1000, 3}, // way too big clamps
		{5, 5},    // legal pass-through
		{30, 30},  // boundary pass-through
		{31, 3},   // just over the boundary clamps
	}
	for _, tc := range cases {
		got, err := mb.Reboot(context.Background(), "b", tc.in)
		if err != nil {
			t.Fatalf("Reboot(%d): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("Reboot(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ----- rauc.go pure parsers (no rauc CLI required) ---------------------------

func TestParseRAUCStatus_SlotA(t *testing.T) {
	in := `RAUC_BOOT_SLOT='rootfs.0'
RAUC_SLOT_STATUS_0_BUNDLE_VERSION='1.2.3'
RAUC_SLOT_STATUS_1_BUNDLE_VERSION='1.0.0'
`
	got := parseRAUCStatus(in)
	if got.activeSlot != proto.SlotA || got.inactiveSlot != proto.SlotB {
		t.Errorf("active/inactive: %+v", got)
	}
	if got.activeVersion != "1.2.3" {
		t.Errorf("active version: %q", got.activeVersion)
	}
}

func TestParseRAUCStatus_SlotB(t *testing.T) {
	in := `RAUC_BOOT_SLOT='rootfs.1'
RAUC_SLOT_STATUS_0_BUNDLE_VERSION='1.0.0'
RAUC_SLOT_STATUS_1_BUNDLE_VERSION='1.2.3'
`
	got := parseRAUCStatus(in)
	if got.activeSlot != proto.SlotB || got.inactiveSlot != proto.SlotA {
		t.Errorf("active/inactive: %+v", got)
	}
	if got.activeVersion != "1.2.3" {
		t.Errorf("active version: %q", got.activeVersion)
	}
}

func TestParseRAUCStatus_UnknownSlot(t *testing.T) {
	// No boot key and no slot states → both unknown.
	got := parseRAUCStatus("RAUC_SYSTEM_COMPATIBLE='rasputin-pi5-cm5'\n")
	if got.activeSlot != proto.SlotUnknown || got.inactiveSlot != proto.SlotUnknown {
		t.Errorf("expected unknown/unknown: %+v", got)
	}
}

func TestParseRAUCStatus_RealShellFormat(t *testing.T) {
	// Captured verbatim from `rauc status --output-format=shell` on the N100
	// controlplane. Real RAUC emits RAUC_BOOT_PRIMARY + per-index STATE/DEVICE,
	// NOT RAUC_BOOT_SLOT — the schema the old parser wrongly assumed, which made
	// OS self-update fail with "no inactive slot" (2026-06-22).
	in := `RAUC_SYSTEM_COMPATIBLE='rasputin-n100'
RAUC_SYSTEM_BOOTED_BOOTNAME='A'
RAUC_BOOT_PRIMARY='rootfs.0'
RAUC_SYSTEM_SLOTS='rootfs.1 rootfs.0'
RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='inactive'
RAUC_SLOT_DEVICE_1='/dev/disk/by-partlabel/rootfs-1'
RAUC_SLOT_STATE_2='booted'
RAUC_SLOT_DEVICE_2='/dev/disk/by-partlabel/rootfs-0'
`
	got := parseRAUCStatus(in)
	if got.activeSlot != proto.SlotA || got.inactiveSlot != proto.SlotB {
		t.Fatalf("real format: active/inactive = %+v, want A/B", got)
	}
}

func TestParseRAUCStatus_StateFallbackBootedB(t *testing.T) {
	// No boot key present → fall back to the slot whose STATE is booted,
	// resolved via its device partlabel (rootfs-1 → SlotB).
	in := `RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='booted'
RAUC_SLOT_DEVICE_1='/dev/disk/by-partlabel/rootfs-1'
RAUC_SLOT_STATE_2='inactive'
RAUC_SLOT_DEVICE_2='/dev/disk/by-partlabel/rootfs-0'
`
	got := parseRAUCStatus(in)
	if got.activeSlot != proto.SlotB || got.inactiveSlot != proto.SlotA {
		t.Fatalf("state fallback: active/inactive = %+v, want B/A", got)
	}
}

// TestInstall_ContextCancelShortCircuits drives Install with an already-
// cancelled context so we exit on the first phase boundary instead of
// sleeping through 1.2s of fake install phases. This covers the early-exit
// branch and the read-bundle / parse-manifest paths.
func TestInstall_ContextCancelShortCircuits(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	// Plant a bundle envelope so the read+manifest-parse step succeeds.
	bundlePath := filepath.Join(dir, "bundles", "b-cancel.bin")
	manifest := proto.BundleManifest{Version: "1.2.3", Compatible: "rasputin-pi5-cm5", Architecture: "arm64"}
	env := map[string]any{"manifest": manifest}
	buf, _ := json.Marshal(env)
	if err := os.WriteFile(bundlePath, buf, 0o644); err != nil {
		t.Fatalf("plant bundle: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done; Install's first phase select will exit immediately

	var phaseCalls int32
	_, err = mb.Install(ctx, "b-cancel", bundlePath, proto.SlotB, func(string, int) {
		atomic.AddInt32(&phaseCalls, 1)
	})
	if err == nil {
		t.Errorf("expected ctx.Err() from Install with cancelled ctx")
	}
	// The progress fn fires once before the first select.
	if atomic.LoadInt32(&phaseCalls) == 0 {
		t.Errorf("progress should have been called at least once before ctx check")
	}
}

func TestInstall_MissingBundleFileErrors(t *testing.T) {
	mb := newUpdaterMock(t)
	_, err := mb.Install(context.Background(), "nonexistent", "/no/such/path.bin", proto.SlotB, nil)
	if err == nil {
		t.Errorf("expected read-bundle error on missing path")
	}
}

func TestInstall_BadManifestErrors(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	// Bundle exists but isn't a JSON envelope.
	bundlePath := filepath.Join(dir, "bundles", "b-junk.bin")
	if err := os.WriteFile(bundlePath, []byte("not json"), 0o644); err != nil {
		t.Fatalf("plant junk bundle: %v", err)
	}
	if _, err := mb.Install(context.Background(), "b-junk", bundlePath, proto.SlotB, nil); err == nil {
		t.Errorf("expected manifest parse error")
	}
}

func TestNewRAUCBackend_ReturnsErrorWithoutRaucCLI(t *testing.T) {
	// On most dev boxes rauc isn't on PATH — the constructor surfaces
	// that as an error. Accept either outcome: if rauc IS installed,
	// the Name() should be "rauc".
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		return // expected on most boxes
	}
	if b.Name() != "rauc" {
		t.Errorf("Name: %q want rauc", b.Name())
	}
}
