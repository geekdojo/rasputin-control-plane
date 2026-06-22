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
	"runtime"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func writeFile644(path string, body []byte) error {
	return os.WriteFile(path, body, 0o644)
}

// startNATS spins up an in-process NATS server on a random port and returns a
// connected client. Both shut down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready in 2s")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func request[T any](t *testing.T, nc *nats.Conn, subj string, cmd any, out *T) {
	t.Helper()
	payload, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg, err := nc.Request(subj, payload, 5*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subj, err)
	}
	if err := json.Unmarshal(msg.Data, out); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
}

func newRegistered(t *testing.T) (*nats.Conn, *MockBackend) {
	t.Helper()
	nc := startNATS(t)
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	subs, err := RegisterHandlers(nc, "node-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	return nc, mb
}

func TestRegisterHandlers_PrecheckHappyPath(t *testing.T) {
	nc, _ := newRegistered(t)
	var ack proto.UpdatePrecheckAck
	request(t, nc, proto.UpdatePrecheckSubject("node-1"), proto.UpdatePrecheckCmd{}, &ack)
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	if ack.ActiveSlot != proto.SlotA {
		t.Errorf("active slot: %q", ack.ActiveSlot)
	}
	if ack.Backend != "mock" {
		t.Errorf("backend: %q", ack.Backend)
	}
}

func TestRegisterHandlers_DownloadHappyPath(t *testing.T) {
	body := []byte("mock bundle bytes for handler test")
	sum := sha256.Sum256(body)
	expectedSHA := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	nc, _ := newRegistered(t)
	// Subscribe to progress events so we cover the publish branch.
	progSub, err := nc.SubscribeSync(proto.UpdateDownloadProgressSubject("node-1"))
	if err != nil {
		t.Fatalf("subscribe progress: %v", err)
	}
	t.Cleanup(func() { _ = progSub.Unsubscribe() })

	var ack proto.UpdateDownloadAck
	request(t, nc, proto.UpdateDownloadSubject("node-1"), proto.UpdateDownloadCmd{
		BundleID:       "b1",
		URL:            srv.URL,
		ExpectedSHA256: expectedSHA,
		SizeBytes:      int64(len(body)),
	}, &ack)
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	if ack.SHA256 != expectedSHA {
		t.Errorf("sha: %q want %q", ack.SHA256, expectedSHA)
	}
	// Progress event(s) should have been published.
	if _, err := progSub.NextMsg(200 * time.Millisecond); err != nil {
		t.Errorf("no progress event published: %v", err)
	}
}

func TestRegisterHandlers_DownloadBadCmd(t *testing.T) {
	nc, _ := newRegistered(t)
	msg, err := nc.Request(proto.UpdateDownloadSubject("node-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.UpdateDownloadAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false")
	}
}

func TestRegisterHandlers_DownloadBackendError(t *testing.T) {
	t.Setenv("RASPUTIN_UPDATE_FAIL_MODE", "download")
	nc, _ := newRegistered(t)
	var ack proto.UpdateDownloadAck
	request(t, nc, proto.UpdateDownloadSubject("node-1"), proto.UpdateDownloadCmd{
		BundleID: "b", URL: "http://x",
	}, &ack)
	if ack.OK {
		t.Error("expected OK=false in download-fail mode")
	}
}

func TestRegisterHandlers_InstallHappyPath(t *testing.T) {
	nc, mb := newRegistered(t)
	// Plant a bundle so Install can read+parse it.
	dir := mb.stateDir
	bundlePath := filepath.Join(dir, "bundles", "b-install.bin")
	manifest := proto.BundleManifest{Version: "1.2.3", Compatible: "rasputin-pi5-cm5", Architecture: "arm64"}
	env := map[string]any{"manifest": manifest}
	buf, _ := json.Marshal(env)
	if err := writeBundle(bundlePath, buf); err != nil {
		t.Fatalf("plant bundle: %v", err)
	}

	progSub, err := nc.SubscribeSync(proto.UpdateInstallProgressSubject("node-1"))
	if err != nil {
		t.Fatalf("subscribe progress: %v", err)
	}
	t.Cleanup(func() { _ = progSub.Unsubscribe() })

	var ack proto.UpdateInstallAck
	request(t, nc, proto.UpdateInstallSubject("node-1"), proto.UpdateInstallCmd{
		BundleID: "b-install", LocalPath: bundlePath, TargetSlot: proto.SlotB,
	}, &ack)
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	if ack.NewVersion != "1.2.3" {
		t.Errorf("new version: %q", ack.NewVersion)
	}
	if ack.TargetSlot != proto.SlotB {
		t.Errorf("target slot: %q", ack.TargetSlot)
	}
	// At least one progress event published.
	if _, err := progSub.NextMsg(200 * time.Millisecond); err != nil {
		t.Errorf("no progress event published: %v", err)
	}
}

func TestRegisterHandlers_InstallBadCmd(t *testing.T) {
	nc, _ := newRegistered(t)
	msg, err := nc.Request(proto.UpdateInstallSubject("node-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.UpdateInstallAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false")
	}
}

func TestRegisterHandlers_InstallBackendError(t *testing.T) {
	nc, _ := newRegistered(t)
	// Nonexistent bundle path should bubble up from the mock's ReadFile.
	var ack proto.UpdateInstallAck
	request(t, nc, proto.UpdateInstallSubject("node-1"), proto.UpdateInstallCmd{
		BundleID: "missing", LocalPath: "/no/such/bundle.bin", TargetSlot: proto.SlotB,
	}, &ack)
	if ack.OK {
		t.Error("expected OK=false on backend error")
	}
}

func TestRegisterHandlers_RebootPublishesEvent(t *testing.T) {
	nc, _ := newRegistered(t)
	evSub, err := nc.SubscribeSync(proto.NodeEvtSubject("node-1", "rebooting"))
	if err != nil {
		t.Fatalf("subscribe ev: %v", err)
	}
	t.Cleanup(func() { _ = evSub.Unsubscribe() })

	var ack proto.UpdateRebootAck
	request(t, nc, proto.UpdateRebootSubject("node-1"), proto.UpdateRebootCmd{
		BundleID: "b", DelaySeconds: 3,
	}, &ack)
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	if ack.DelaySeconds != 3 {
		t.Errorf("delay: %d", ack.DelaySeconds)
	}
	if _, err := evSub.NextMsg(200 * time.Millisecond); err != nil {
		t.Errorf("rebooting event not published: %v", err)
	}
}

func TestRegisterHandlers_MarkGoodHappyPath(t *testing.T) {
	nc, _ := newRegistered(t)
	var ack proto.UpdateMarkGoodAck
	request(t, nc, proto.UpdateMarkGoodSubject("node-1"), proto.UpdateMarkGoodCmd{
		BundleID: "b",
	}, &ack)
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
}

func TestRegisterHandlers_MarkBadHappyPath(t *testing.T) {
	nc, _ := newRegistered(t)
	var ack proto.UpdateMarkBadAck
	request(t, nc, proto.UpdateMarkBadSubject("node-1"), proto.UpdateMarkBadCmd{
		BundleID: "b", Reason: "health check fail",
	}, &ack)
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
}

// errBackend implements Backend with every method returning an error.
type errBackend struct{}

func (errBackend) Name() string { return "errmock" }
func (errBackend) Precheck(_ context.Context) (*proto.UpdatePrecheckAck, error) {
	return nil, errStr("boom")
}
func (errBackend) Download(_ context.Context, _, _, _ string, _ int64, _ func(int64, int64)) (string, string, error) {
	return "", "", errStr("boom")
}
func (errBackend) Install(_ context.Context, _, _ string, _ proto.UpdateSlot, _ func(string, int)) (string, error) {
	return "", errStr("boom")
}
func (errBackend) Reboot(_ context.Context, _ string, _ int) (int, error) {
	return 0, errStr("boom")
}
func (errBackend) MarkGood(_ context.Context, _ string) error { return errStr("boom") }
func (errBackend) MarkBad(_ context.Context, _, _ string) error {
	return errStr("boom")
}

type errStr string

func (e errStr) Error() string { return string(e) }

func TestRegisterHandlers_AllBackendErrorPaths(t *testing.T) {
	nc := startNATS(t)
	subs, err := RegisterHandlers(nc, "node-1", errBackend{})
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var pack proto.UpdatePrecheckAck
	request(t, nc, proto.UpdatePrecheckSubject("node-1"), proto.UpdatePrecheckCmd{}, &pack)
	if pack.OK {
		t.Error("precheck OK on err backend")
	}

	var rack proto.UpdateRebootAck
	request(t, nc, proto.UpdateRebootSubject("node-1"), proto.UpdateRebootCmd{}, &rack)
	if rack.OK {
		t.Error("reboot OK on err backend")
	}

	var mg proto.UpdateMarkGoodAck
	request(t, nc, proto.UpdateMarkGoodSubject("node-1"), proto.UpdateMarkGoodCmd{}, &mg)
	if mg.OK {
		t.Error("mark-good OK on err backend")
	}

	var mb proto.UpdateMarkBadAck
	request(t, nc, proto.UpdateMarkBadSubject("node-1"), proto.UpdateMarkBadCmd{}, &mb)
	if mb.OK {
		t.Error("mark-bad OK on err backend")
	}
}

// writeBundle is a tiny helper that mirrors os.WriteFile but keeps the test
// file imports tight.
func writeBundle(path string, body []byte) error {
	return writeFile644(path, body)
}

// TestNewRAUCBackend_NoCLI exercises the LookPath-failure path so we cover
// the constructor without needing a real rauc binary.
func TestNewRAUCBackend_NoCLI(t *testing.T) {
	t.Setenv("PATH", "")
	_, err := NewRAUCBackend(t.TempDir())
	if err == nil {
		t.Error("expected NewRAUCBackend to fail with empty PATH")
	}
}

// TestRAUCBackend_NameAndSetMuteHook covers the trivial accessors so the
// production methods aren't entirely 0%-uncovered.
func TestRAUCBackend_NameAndSetMuteHook(t *testing.T) {
	b := &RAUCBackend{stateDir: t.TempDir()}
	if b.Name() != "rauc" {
		t.Errorf("Name: %q want rauc", b.Name())
	}
	// SetMuteHook is a single assignment — exercising it ensures someone
	// who breaks the field reference gets a compile-time failure here.
	b.SetMuteHook(nil)
}

// fakeRAUC writes a shim "rauc" binary into a temp dir and prepends that dir
// to PATH for the duration of the test. mode selects the shim's behavior:
//
//	"ok"     — status/install/info all succeed; info emits a valid RAUC_MF_VERSION.
//	"fail"   — every invocation exits non-zero.
//	"noversion" — status/install succeed but info emits no RAUC_MF_VERSION line.
//
// Skipped on Windows since the shim is /bin/sh.
func fakeRAUC(t *testing.T, mode string) {
	t.Helper()
	if runtimeIsWindows() {
		t.Skip("fake-rauc shim is /bin/sh; skipped on Windows")
	}
	dir := t.TempDir()
	var body string
	switch mode {
	case "ok":
		body = `#!/bin/sh
case "$1" in
  status)
    if [ "$2" = "mark-good" ] || [ "$2" = "mark-bad" ]; then
      exit 0
    fi
    cat <<EOF
RAUC_SYSTEM_COMPATIBLE='rasputin-n100'
RAUC_BOOT_PRIMARY='rootfs.0'
RAUC_SLOTS='1 2'
RAUC_SLOT_STATE_1='inactive'
RAUC_SLOT_DEVICE_1='/dev/disk/by-partlabel/rootfs-1'
RAUC_SLOT_STATE_2='booted'
RAUC_SLOT_DEVICE_2='/dev/disk/by-partlabel/rootfs-0'
RAUC_SLOT_STATUS_0_BUNDLE_VERSION='1.2.3'
RAUC_SLOT_STATUS_1_BUNDLE_VERSION='1.0.0'
EOF
    ;;
  install)
    exit 0
    ;;
  info)
    cat <<EOF
RAUC_MF_VERSION='4.5.6'
EOF
    ;;
  *)
    exit 0
    ;;
esac
`
	case "fail":
		body = `#!/bin/sh
exit 2
`
	case "noversion":
		body = `#!/bin/sh
case "$1" in
  install) exit 0 ;;
  info) echo "no version line here"; exit 0 ;;
  *) exit 0 ;;
esac
`
	}
	if err := writeFile755(dir+"/rauc", body); err != nil {
		t.Fatalf("write fake rauc: %v", err)
	}
	t.Setenv("PATH", dir+":"+osGetenvPath())
}

func writeFile755(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o755)
}

func osGetenvPath() string { return os.Getenv("PATH") }

func runtimeIsWindows() bool { return runtime.GOOS == "windows" }

func TestRAUCBackend_PrecheckHappy(t *testing.T) {
	fakeRAUC(t, "ok")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	ack, err := b.Precheck(context.Background())
	if err != nil {
		t.Fatalf("Precheck: %v", err)
	}
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	if ack.ActiveSlot != proto.SlotA {
		t.Errorf("active slot: %q", ack.ActiveSlot)
	}
	if ack.CurrentVersion != "1.2.3" {
		t.Errorf("version: %q", ack.CurrentVersion)
	}
}

func TestRAUCBackend_PrecheckFail(t *testing.T) {
	fakeRAUC(t, "fail")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	ack, err := b.Precheck(context.Background())
	if err != nil {
		t.Fatalf("Precheck: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false when rauc errors")
	}
}

func TestRAUCBackend_MarkGoodAndBad(t *testing.T) {
	fakeRAUC(t, "ok")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	if err := b.MarkGood(context.Background(), "x"); err != nil {
		t.Errorf("MarkGood: %v", err)
	}
	if err := b.MarkBad(context.Background(), "x", "r"); err != nil {
		t.Errorf("MarkBad: %v", err)
	}
}

func TestRAUCBackend_MarkGoodAndBadFail(t *testing.T) {
	fakeRAUC(t, "fail")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	if err := b.MarkGood(context.Background(), "x"); err == nil {
		t.Error("MarkGood should fail")
	}
	if err := b.MarkBad(context.Background(), "x", "r"); err == nil {
		t.Error("MarkBad should fail")
	}
}

func TestRAUCBackend_RebootReturnsDelay(t *testing.T) {
	fakeRAUC(t, "ok")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	got, err := b.Reboot(context.Background(), "x", 0)
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if got != 3 {
		t.Errorf("Reboot delay clamp: got %d want 3", got)
	}
	got, _ = b.Reboot(context.Background(), "x", 5)
	if got != 5 {
		t.Errorf("Reboot delay pass-through: got %d", got)
	}
}

func TestRAUCBackend_DownloadHappyPath(t *testing.T) {
	fakeRAUC(t, "ok")
	body := []byte("rauc bundle bytes")
	sum := sha256.Sum256(body)
	expectedSHA := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	path, observed, err := b.Download(context.Background(), "b1", srv.URL, expectedSHA, int64(len(body)), nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if path == "" {
		t.Error("empty path")
	}
	if observed != expectedSHA {
		t.Errorf("sha mismatch")
	}
}

func TestRAUCBackend_DownloadHTTPError(t *testing.T) {
	fakeRAUC(t, "ok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	if _, _, err := b.Download(context.Background(), "b", srv.URL, "", 0, nil); err == nil {
		t.Error("expected HTTP error")
	}
}

func TestRAUCBackend_DownloadBadURL(t *testing.T) {
	fakeRAUC(t, "ok")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	if _, _, err := b.Download(context.Background(), "b", "::not-a-url::", "", 0, nil); err == nil {
		t.Error("expected URL parse error")
	}
}

func TestRAUCBackend_InstallHappyPath(t *testing.T) {
	fakeRAUC(t, "ok")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	// Install reads the local bundle via `rauc install <path>` then queries
	// `rauc info`. Our fake binary ignores the actual file content, so we
	// can pass any path.
	tmp := filepath.Join(t.TempDir(), "bundle.raucb")
	if err := writeFile644(tmp, []byte("x")); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	ver, err := b.Install(context.Background(), "b1", tmp, proto.SlotB, nil)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if ver != "4.5.6" {
		t.Errorf("version: %q want 4.5.6", ver)
	}
}

func TestRAUCBackend_InstallFail(t *testing.T) {
	fakeRAUC(t, "fail")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	if _, err := b.Install(context.Background(), "b1", "/path/to/bundle", proto.SlotB, nil); err == nil {
		t.Error("expected install error")
	}
}

func TestRAUCBackend_InstallNoVersion(t *testing.T) {
	fakeRAUC(t, "noversion")
	b, err := NewRAUCBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	if _, err := b.Install(context.Background(), "b1", "/path/to/bundle", proto.SlotB, nil); err == nil {
		t.Error("expected error when RAUC_MF_VERSION missing")
	}
}

// TestRAUCBackend_ExplicitBinaryPath exercises the lower-level
// newRAUCBackend constructor that takes an explicit binary path. This is
// the test pattern adopted from tailscale/real.go — point at a shim
// directly instead of mutating PATH. Faster (no PATH lookup), cleaner
// (no env-var leak across parallel tests), and more honest (the field
// being exercised is the one production code uses).
func TestRAUCBackend_ExplicitBinaryPath(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("shim is /bin/sh")
	}
	shimDir := t.TempDir()
	shimPath := shimDir + "/rauc-shim"
	body := `#!/bin/sh
case "$1" in
  status)
    cat <<EOF
RAUC_BOOT_SLOT='rootfs.1'
RAUC_SLOT_STATUS_1_BUNDLE_VERSION='9.9.9'
EOF
    ;;
  *) exit 0 ;;
esac
`
	if err := writeFile755(shimPath, body); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	b, err := newRAUCBackend(t.TempDir(), shimPath)
	if err != nil {
		t.Fatalf("newRAUCBackend: %v", err)
	}
	ack, err := b.Precheck(context.Background())
	if err != nil {
		t.Fatalf("Precheck: %v", err)
	}
	if !ack.OK {
		t.Errorf("ack: %+v", ack)
	}
	if ack.ActiveSlot != proto.SlotB {
		t.Errorf("ActiveSlot: got %q want %q", ack.ActiveSlot, proto.SlotB)
	}
	if ack.CurrentVersion != "9.9.9" {
		t.Errorf("CurrentVersion: got %q want 9.9.9", ack.CurrentVersion)
	}
}

func TestRAUCBackend_NewRAUCBackend_RejectsEmptyBinary(t *testing.T) {
	if _, err := newRAUCBackend(t.TempDir(), ""); err == nil {
		t.Error("empty binary path should fail")
	}
}
