package bustls_test

// The TLS-only bus with the REAL rasputin-api binary: what only a running
// process shows.
//
//   - A controlplane upgraded from a release that had the ladder still carries
//     its recorded bus.tls_mode row, and may still carry RASPUTIN_BUS_TLS in
//     node.env. Neither changes anything: the bus refuses plaintext on the
//     wire, the row is left alone, and a set variable earns one WARN entry.
//   - A bus key, or a bus certificate, that will not load: the api keeps
//     running and answering, serves no bus listener at all, lists a crit alert
//     naming the file that failed, answers GET /api/bus/tls and mint with a
//     coded 503, mints nothing, and never claims a listener in its log.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls/bustlstest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// legacyModeSetting is the settings row the plaintext ladder recorded its rung
// in. Nothing reads it any more; an upgraded controlplane still carries it.
const legacyModeSetting = "bus.tls_mode"

var (
	apiBinOnce sync.Once
	apiBin     string
	apiBinErr  error
)

// buildAPI builds rasputin-api from this workspace — with the race detector
// when this test binary has it.
func buildAPI(t *testing.T) string {
	t.Helper()
	apiBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bustls-api-")
		if err != nil {
			apiBinErr = err
			return
		}
		apiBin = filepath.Join(dir, "rasputin-api")
		goBin, err := exec.LookPath("go")
		if err != nil {
			apiBinErr = fmt.Errorf("the api binary is built with the go command, and none is on PATH: %w", err)
			return
		}
		args := []string{"build", "-o", apiBin}
		if raceEnabled {
			args = append(args, "-race")
		}
		args = append(args, "github.com/geekdojo/rasputin-control-plane/api/cmd/rasputin-api")
		cmd := exec.Command(goBin, args...) // G204: fixed arguments, the test's own toolchain
		if out, err := cmd.CombinedOutput(); err != nil {
			apiBinErr = fmt.Errorf("go build rasputin-api: %v\n%s", err, out)
		}
	})
	if apiBinErr != nil {
		t.Fatal(apiBinErr)
	}
	return apiBin
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// apiProc is one running rasputin-api, with its log captured.
type apiProc struct {
	cmd      *exec.Cmd
	dataDir  string
	httpBase string
	natsPort int
	cookie   *http.Cookie

	mu      sync.Mutex
	lines   []string
	changed signal
	exited  chan struct{}
}

func (a *apiProc) log() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.lines, "\n")
}

// count is how many log lines contain every one of subs.
func (a *apiProc) count(subs ...string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, l := range a.lines {
		all := true
		for _, s := range subs {
			all = all && strings.Contains(l, s)
		}
		if all {
			n++
		}
	}
	return n
}

func (a *apiProc) waitLog(t *testing.T, what string, subs ...string) {
	t.Helper()
	waitFact(t, what+" in the api log", &a.changed, func() bool {
		if a.hasExited() {
			t.Fatalf("the api exited while waiting for %s\n%s", what, a.log())
		}
		return a.count(subs...) > 0
	}, a.log)
}

func (a *apiProc) hasExited() bool {
	select {
	case <-a.exited:
		return true
	default:
		return false
	}
}

// stop ends the api and waits for it.
func (a *apiProc) stop() {
	if !a.hasExited() {
		_ = a.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-a.exited:
		case <-time.After(30 * time.Second): // bounds the one wait for exit
			_ = a.cmd.Process.Kill()
			<-a.exited
		}
	}
}

type apiOpts struct {
	// recordMode writes the ladder's bus.tls_mode settings row, as a
	// controlplane upgraded from a ladder release carries it.
	recordMode string
	// env is extra environment for the api (RASPUTIN_BUS_TLS, say).
	env []string
	// corruptKey puts an unusable bus.key in place; badCert puts a directory
	// where bus.crt should be, beside a good key.
	corruptKey, badCert bool
	// bin runs another api binary (the compatibility tests' floor api); ""
	// builds this workspace's.
	bin string
	// dataDir and the two ports reuse a previous api's (the swap to a new
	// build); zero values are fresh.
	dataDir            string
	httpPort, natsPort int
	// noSeed leaves the data dir alone: no key, no settings, no session. An
	// older api then creates its own database rather than open one a newer
	// build's schema already migrated; with no key it generates one.
	noSeed bool
	// preseed is written as the matched-set token preseed (bus/preseed.json),
	// the one way to give an api a join token without touching its database.
	preseed []busauth.PreseedToken
	// noWait returns from runAPI as soon as the process has started, instead
	// of at its HTTP listener, so a test can act on a start-up log line that
	// comes before it (the auth-callout responder going active).
	noWait bool
}

// startAPI seeds a controlplane data dir the way firstboot and an operator
// would have — a bus key and a signed-in session (written to the database
// directly: auth is passkey-only) — and starts the api binary on it.
func startAPI(t *testing.T, o apiOpts) (a *apiProc, pin string) {
	t.Helper()
	ctx := context.Background()
	dataDir := o.dataDir
	if dataDir == "" {
		dataDir = t.TempDir()
	}
	dbPath := filepath.Join(dataDir, "rasputin.db")
	busDir := filepath.Join(dataDir, "bus")
	sessToken := "bustls-functional-session"

	if len(o.preseed) > 0 {
		if err := os.MkdirAll(busDir, 0o700); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(o.preseed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(busDir, "preseed.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	switch {
	case o.noSeed:
	case o.corruptKey:
		if err := os.MkdirAll(busDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(busDir, bustls.KeyFileName), []byte("not a key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	default:
		key, _, err := bustls.EnsureKey(busDir)
		if err != nil {
			t.Fatal(err)
		}
		pin = key.Pin()
	}
	if o.noSeed {
		return runAPI(t, o, dataDir, sessToken), pin
	}
	if o.badCert {
		if err := os.MkdirAll(filepath.Join(busDir, bustls.CertFileName), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if o.recordMode != "" {
		settings, err := setup.OpenStore(ctx, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := settings.Set(ctx, legacyModeSetting, o.recordMode); err != nil {
			t.Fatal(err)
		}
		_ = settings.Close()
	}
	authStore, err := auth.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := &auth.User{ID: []byte("bustls-functional-user"), Name: "operator", DisplayName: "Operator", CreatedAt: now}
	sess := &auth.Session{Token: sessToken, UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now}
	if err := authStore.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := authStore.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	_ = authStore.Close()
	return runAPI(t, o, dataDir, sessToken), pin
}

// runAPI starts the api binary on dataDir and waits for its HTTP listener,
// unless o.noWait.
func runAPI(t *testing.T, o apiOpts, dataDir, sessToken string) *apiProc {
	t.Helper()
	httpPort, natsPort := o.httpPort, o.natsPort
	if httpPort == 0 {
		httpPort = freePort(t)
	}
	if natsPort == 0 {
		natsPort = freePort(t)
	}
	ingestPort := freePort(t)
	a := &apiProc{
		dataDir:  dataDir,
		httpBase: fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		natsPort: natsPort,
		cookie:   &http.Cookie{Name: "rasputin-session", Value: sessToken},
		exited:   make(chan struct{}),
	}
	bin := o.bin
	if bin == "" {
		bin = buildAPI(t)
	}
	dead := "http://127.0.0.1:1" // no network: release and catalog checks fail fast
	cmd := exec.Command(bin)     // G204: a binary this test built
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dataDir,
		"RASPUTIN_DATA_DIR=" + dataDir,
		"RASPUTIN_HTTP_ADDR=" + fmt.Sprintf("127.0.0.1:%d", httpPort),
		"RASPUTIN_NATS_HOST=127.0.0.1",
		"RASPUTIN_NATS_PORT=" + fmt.Sprint(natsPort),
		"RASPUTIN_OBS_INGEST_ADDR=" + fmt.Sprintf("127.0.0.1:%d", ingestPort),
		"RASPUTIN_SELF_NODE_ID=cp1",
		"RASPUTIN_MESH_BACKEND=mock",
		"RASPUTIN_DNS=off",
		"RASPUTIN_SECURE_COOKIES=false",
		"RASPUTIN_UI_DIR=" + filepath.Join(dataDir, "no-ui"),
		"RASPUTIN_CP_AUTHORIZED_KEYS=" + filepath.Join(dataDir, "no-authorized-keys"),
		"RASPUTIN_RELEASE_API_BASE=" + dead,
		"RASPUTIN_RELEASE_DOWNLOAD_BASE=" + dead,
		"RASPUTIN_CATALOG_API_BASE=" + dead,
		// No scheduled job lands in the middle of the run.
		"RASPUTIN_FW_RECONCILE_INTERVAL=24h",
		"RASPUTIN_APPS_RECONCILE_INTERVAL=24h",
		"RASPUTIN_MESH_RECONCILE_INTERVAL=24h",
		"RASPUTIN_STORAGE_RECONCILE_INTERVAL=24h",
		"RASPUTIN_BACKUP_CHECK_INTERVAL=24h",
		"RASPUTIN_OBS_COLLECTOR_RECONCILE_INTERVAL=24h",
	}, o.env...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start api: %v", err)
	}
	a.cmd = cmd
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			a.mu.Lock()
			a.lines = append(a.lines, sc.Text())
			a.mu.Unlock()
			a.changed.fire()
		}
		_ = cmd.Wait()
		close(a.exited)
		a.changed.fire()
	}()
	t.Cleanup(func() {
		a.stop()
		if a.count("DATA RACE") != 0 {
			t.Errorf("the api binary (built with -race) reported a data race")
		}
		if t.Failed() {
			t.Logf("--- api log ---\n%s", a.log())
		}
	})
	if !o.noWait {
		a.waitLog(t, "the HTTP listener", "rasputin-api: http listening on")
	}
	return a
}

// do is one bounded HTTP round trip, signed in.
func (a *apiProc) do(method, path, body string) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, a.httpBase+path, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.AddCookie(a.cookie)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

// mint returns a join token bound to id from the api's own endpoint, as
// Add-node mints one.
func (a *apiProc) mint(t *testing.T, id string) string {
	t.Helper()
	resp, body, err := a.do(http.MethodPost, "/api/bus/tokens", fmt.Sprintf(`{"role":"compute","label":%q,"nodeId":%q}`, id, id))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/bus/tokens for %s = (%v, %s, %v)", id, resp, body, err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.Token == "" {
		t.Fatalf("mint body %s: %v", body, err)
	}
	return tok.Token
}

// tokenCount is how many join tokens GET /api/bus/tokens lists.
func (a *apiProc) tokenCount(t *testing.T) int {
	t.Helper()
	resp, body, err := a.do(http.MethodGet, "/api/bus/tokens", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/bus/tokens = (%v, %s, %v)", resp, body, err)
	}
	var list []json.RawMessage
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("token list %s: %v", body, err)
	}
	return len(list)
}

// TC-517-29: an upgraded controlplane's stale bus.tls_mode=offer row, and
// RASPUTIN_BUS_TLS set to a ladder mode or to garbage, change nothing: the bus
// refuses plaintext on the wire, the row is left in place, and the variable
// earns exactly one WARN entry naming it — none when it is unset.
func TestFunctional_RealAPIProcess_StaleModeChangesNothing(t *testing.T) {
	skipShort(t)
	for _, tc := range []struct {
		name      string
		node      string
		env       []string
		wantWarns int
	}{
		{"recorded offer, variable unset", "n-unset", nil, 0},
		{"RASPUTIN_BUS_TLS=offer", "n-offer", []string{"RASPUTIN_BUS_TLS=offer"}, 1},
		{"RASPUTIN_BUS_TLS=banana", "n-banana", []string{"RASPUTIN_BUS_TLS=banana"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, pin := startAPI(t, apiOpts{recordMode: "offer", env: tc.env})
			api.waitLog(t, "the bus listener", "rasputin-api: bus listening")
			bustlstest.AssertPlaintextRefused(t, fmt.Sprintf("127.0.0.1:%d", api.natsPort))

			// And the bus works: a node seeded with the pin joins.
			id := tc.node
			a := startAgent(t, agentOpts{id: id, url: fmt.Sprintf("nats://127.0.0.1:%d", api.natsPort), token: api.mint(t, id), pin: pin})
			a.waitLog(t, "the node on the bus", "agent/bus: connected")

			if got := api.count("level=WARN", "RASPUTIN_BUS_TLS is set but no longer read"); got != tc.wantWarns {
				t.Fatalf("%d WARN entries naming RASPUTIN_BUS_TLS, want %d", got, tc.wantWarns)
			}
			if tc.wantWarns == 1 {
				value := strings.SplitN(tc.env[0], "=", 2)[1]
				if api.count("RASPUTIN_BUS_TLS is set", "value="+value, "fix=") != 1 {
					t.Fatalf("the WARN does not carry value=%s and a fix", value)
				}
			}

			a.stop(t)
			api.stop()
			settings, err := setup.OpenStore(context.Background(), filepath.Join(api.dataDir, "rasputin.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = settings.Close() }()
			if v, err := settings.Get(context.Background(), legacyModeSetting); err != nil || v != "offer" {
				t.Fatalf("the %s row = (%q, %v) after the run, want it left at offer", legacyModeSetting, v, err)
			}
		})
	}
}

// busDown is the shared body of TC-517-30 and TC-517-44: the api keeps
// running with no bus listener, a crit alert naming failedFile, coded 503s on
// GET /api/bus/tls and mint, no token minted, and no listener claimed.
func busDown(t *testing.T, o apiOpts, failedFile, otherFile, logWhat string) {
	t.Helper()
	api, _ := startAPI(t, o)
	api.waitLog(t, logWhat, logWhat, "file=", failedFile)

	resp, _, err := api.do(http.MethodGet, "/healthz", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz = (%v, %v), want 200", resp, err)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", api.natsPort), 2*time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("something accepts on the bus port %d with the bus down", api.natsPort)
	}

	resp, body, err := api.do(http.MethodGet, "/api/alerts", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/alerts = (%v, %s, %v)", resp, body, err)
	}
	var alerts []proto.Alert
	if err := json.Unmarshal(body, &alerts); err != nil {
		t.Fatal(err)
	}
	var found *proto.Alert
	for i := range alerts {
		if alerts[i].ID == bustls.AlertID {
			found = &alerts[i]
		}
	}
	if found == nil || found.Severity != proto.AlertCrit {
		t.Fatalf("alerts = %+v, want a crit %s", alerts, bustls.AlertID)
	}
	if !strings.Contains(found.Detail, failedFile) || strings.Contains(found.Detail, otherFile) {
		t.Fatalf("alert detail %q, want it to name %s and not %s", found.Detail, failedFile, otherFile)
	}

	for _, path := range []string{"/api/bus/tls"} {
		resp, body, err := api.do(http.MethodGet, path, "")
		if err != nil || resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("GET %s = (%v, %s, %v), want 503", path, resp, body, err)
		}
		assertBusUnavailableBody(t, body)
	}
	before := api.tokenCount(t)
	resp, body, err = api.do(http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"n1","nodeId":"n1"}`)
	if err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("mint with the bus down = (%v, %s, %v), want 503", resp, body, err)
	}
	assertBusUnavailableBody(t, body)
	if after := api.tokenCount(t); after != before {
		t.Fatalf("a refused mint changed the token count %d → %d", before, after)
	}
	if api.count("bus listening") != 0 || api.count("nats listening") != 0 {
		t.Fatalf("the api claimed a bus listener with the bus down")
	}
	if api.hasExited() {
		t.Fatal("the api exited")
	}
}

func assertBusUnavailableBody(t *testing.T, body []byte) {
	t.Helper()
	var c struct {
		Error         string `json:"error"`
		Code          string `json:"code"`
		CorrelationID string `json:"correlationId"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatalf("503 body %s is not JSON: %v", body, err)
	}
	if c.Code != "bus_unavailable" || c.CorrelationID == "" || c.Error == "" {
		t.Fatalf("503 body = %s, want code bus_unavailable, a message and a correlation id", body)
	}
}

// TC-517-30: a corrupt bus.key.
func TestFunctional_RealAPIProcess_BusKeyDown(t *testing.T) {
	skipShort(t)
	busDown(t, apiOpts{corruptKey: true}, bustls.KeyFileName, bustls.CertFileName, "bus key did not load")
}

// TC-517-44: a good bus.key beside a bus.crt that cannot be read.
func TestFunctional_RealAPIProcess_BusCertDown(t *testing.T) {
	skipShort(t)
	busDown(t, apiOpts{badCert: true}, bustls.CertFileName, bustls.KeyFileName, "bus certificate unusable")
}
