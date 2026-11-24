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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
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

// freePorts returns n distinct free loopback ports, none of them in taken.
// Every listener stays open until all n are chosen, so the kernel cannot hand
// the same port out twice: on Linux, two back-to-back listen-and-close calls
// on 127.0.0.1:0 return the same port about once in 7,000 pairs. When the bus
// port and the obs ingest port came out equal, the api's node listener
// answered on the "bus" port and TestFunctional_RealAPIProcess_BusCertDown
// reported a bus listener that did not exist. A port in taken (one a stopped
// api used and the next one reuses) is held and skipped, never returned.
//
// Only the floor release's api (apiOpts.bin) is given ports chosen this way:
// it cannot report a port it picked itself. The api built from this workspace
// binds every listener on a port the OS picks and the test reads it back from
// the api's log, so no port is released for it to bind again.
func freePorts(t *testing.T, n int, taken ...int) []int {
	t.Helper()
	skip := make(map[int]bool, len(taken))
	for _, p := range taken {
		skip[p] = true
	}
	var held []net.Listener
	defer func() {
		for _, l := range held {
			_ = l.Close()
		}
	}()
	ports := make([]int, 0, n)
	for len(ports) < n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, l)
		if p := l.Addr().(*net.TCPAddr).Port; !skip[p] {
			skip[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}

// TestFreePortsDistinct pins the guarantee runAPI relies on for the floor
// api: every port freePorts returns is distinct and none is a port it was told is taken.
func TestFreePortsDistinct(t *testing.T) {
	taken := freePorts(t, 2)
	got := freePorts(t, 200, taken...)
	if len(got) != 200 {
		t.Fatalf("freePorts returned %d ports, want 200", len(got))
	}
	seen := map[int]bool{taken[0]: true, taken[1]: true}
	for _, p := range got {
		if p <= 0 || seen[p] {
			t.Fatalf("freePorts returned %d, a repeat, a taken port or not a port (taken %v, got %v)", p, taken, got)
		}
		seen[p] = true
	}
}

// apiProc is one running rasputin-api, with its log captured.
type apiProc struct {
	cmd     *exec.Cmd
	dataDir string
	// floor is the floor release's api, which logs its HTTP line as
	// "http listening on <addr>" and was given every port in advance.
	floor bool
	// httpBase is set by waitHTTP from the api's HTTP listening line.
	httpBase string
	// natsPort is the bus port given in advance; zero means the OS picks it
	// and busPort reads it from the log.
	natsPort int
	// cookies are the session cookies every request carries: the console
	// session the current api reads and the legacy one the floor api
	// reads; each ignores the other's.
	cookies []*http.Cookie

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
		if hasAll(l, subs) {
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

func hasAll(line string, subs []string) bool {
	for _, s := range subs {
		if !strings.Contains(line, s) {
			return false
		}
	}
	return true
}

// waitLine waits for a log line containing every one of subs and returns the
// first such line.
func (a *apiProc) waitLine(t *testing.T, what string, subs ...string) string {
	t.Helper()
	a.waitLog(t, what, subs...)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range a.lines {
		if hasAll(l, subs) {
			return l
		}
	}
	t.Fatalf("no log line holds %q after waiting for %s", subs, what)
	return ""
}

// logField is the value of key in a slog text line, unquoted when quoted, or
// "" when the line has no such key.
func logField(line, key string) string {
	i := strings.Index(" "+line, " "+key+"=")
	if i < 0 {
		return ""
	}
	v := line[i+len(key)+1:]
	if strings.HasPrefix(v, `"`) {
		q, err := strconv.QuotedPrefix(v)
		if err != nil {
			return ""
		}
		u, err := strconv.Unquote(q)
		if err != nil {
			return ""
		}
		return u
	}
	v, _, _ = strings.Cut(v, " ")
	return v
}

// listenAddr splits a host:port the api logged, failing the test when it
// does not parse or names port 0.
func listenAddr(t *testing.T, what, hostPort string) (host string, port int) {
	t.Helper()
	host, p, err := net.SplitHostPort(hostPort)
	if err == nil {
		port, err = strconv.Atoi(p)
	}
	if err != nil || port <= 0 {
		t.Fatalf("%s: the api logged %q, not a host:port with a port (%v)", what, hostPort, err)
	}
	return host, port
}

// httpAddr is the host and port the api's HTTP listening line names.
func (a *apiProc) httpAddr(t *testing.T) (host string, port int) {
	t.Helper()
	if a.floor {
		const floorLine = "rasputin-api: http listening on "
		l := a.waitLine(t, "the HTTP listener", floorLine)
		_, addr, _ := strings.Cut(l, floorLine)
		return listenAddr(t, "the HTTP listener", strings.TrimSpace(addr))
	}
	l := a.waitLine(t, "the HTTP listener", "rasputin-api: http listening")
	return listenAddr(t, "the HTTP listener", logField(l, "addr"))
}

// waitHTTP waits for the api's HTTP listener and points httpBase at it.
func (a *apiProc) waitHTTP(t *testing.T) {
	t.Helper()
	host, port := a.httpAddr(t)
	a.httpBase = "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// busPort is the bus port: the one given in advance, else the one the api's
// bus listening line names.
func (a *apiProc) busPort(t *testing.T) int {
	t.Helper()
	if a.natsPort != 0 {
		return a.natsPort
	}
	l := a.waitLine(t, "the bus listener", "rasputin-api: bus listening")
	u, err := url.Parse(logField(l, "url"))
	if err != nil {
		t.Fatalf("the bus listening line %q: %v", l, err)
	}
	_, port := listenAddr(t, "the bus listener", u.Host)
	return port
}

// nodePort is the port the api's node listener line names.
func (a *apiProc) nodePort(t *testing.T) int {
	t.Helper()
	l := a.waitLine(t, "the node listener", "rasputin-api: node listener up")
	_, port := listenAddr(t, "the node listener", logField(l, "addr"))
	return port
}

// assertOSChosenPorts checks that the test chose no port for a workspace api
// it gave none (TC-988-31), and that the HTTP line names the configured host
// and the port that answers (TC-988-33).
func assertOSChosenPorts(t *testing.T, a *apiProc) {
	t.Helper()
	// TC-988-31: every listener is left to the OS.
	for _, want := range []string{"RASPUTIN_HTTP_ADDR=127.0.0.1:0", "RASPUTIN_NATS_PORT=-1", "RASPUTIN_OBS_INGEST_ADDR=127.0.0.1:0"} {
		if !slices.Contains(a.cmd.Env, want) {
			t.Fatalf("the api's environment does not hold %s: %q", want, a.cmd.Env)
		}
	}
	host, httpPort := a.httpAddr(t)
	busPort, nodePort := a.busPort(t), a.nodePort(t)
	// TC-988-31: three nonzero ports (listenAddr refuses 0), all different,
	// and the -1 reached the bus rather than being mapped to 4222.
	if httpPort == busPort || httpPort == nodePort || busPort == nodePort {
		t.Fatalf("the api logged HTTP %d, bus %d and node %d: want three different ports", httpPort, busPort, nodePort)
	}
	if busPort == bus.DefaultPort {
		t.Fatalf("the bus listens on %d: RASPUTIN_NATS_PORT=-1 was mapped to the default", busPort)
	}
	// TC-988-33: the configured host is kept, and the logged port answers.
	if host != "127.0.0.1" {
		t.Fatalf("the HTTP line names host %q, want the configured 127.0.0.1", host)
	}
	resp, _, err := a.do(http.MethodGet, "/healthz", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz on the logged HTTP port %d = (%v, %v), want 200", httpPort, resp, err)
	}
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
	// dataDir and natsPort reuse a previous api's (the swap to a new build);
	// zero values are fresh.
	dataDir  string
	natsPort int
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
		return runAPI(t, o, dataDir, sessToken, ""), pin
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
	// The current api reads only a console session (geekdojo/geekdojo-brain#989).
	consoleSessions, err := auth.NewConsoleSessions(authStore, time.Now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	console, err := consoleSessions.Create(ctx, auth.Principal{Sub: "bustls-functional-sub", Name: "operator",
		Roles: []string{"admin"}, Session: auth.SessionRef{SID: "bustls-functional-sid"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(console.Destroy)
	_ = authStore.Close()
	return runAPI(t, o, dataDir, sessToken, string(console.Reveal())), pin
}

// runAPI starts the api binary on dataDir and waits for its HTTP listener,
// unless o.noWait.
//
// The api built from this workspace binds HTTP and the node listener on :0
// and the bus on -1 (any free port), or on o.natsPort when one is given; the
// test reads the ports back from its log. The floor api cannot report a port
// it picked, so it alone gets ports chosen in advance, in one draw.
func runAPI(t *testing.T, o apiOpts, dataDir, sessToken, consoleToken string) *apiProc {
	t.Helper()
	natsPort := o.natsPort
	httpAddr, ingestAddr := "127.0.0.1:0", "127.0.0.1:0"
	if o.bin != "" {
		fresh := freePorts(t, 3, natsPort)
		if natsPort == 0 {
			natsPort = fresh[2]
		}
		httpAddr, ingestAddr = fmt.Sprintf("127.0.0.1:%d", fresh[1]), fmt.Sprintf("127.0.0.1:%d", fresh[0])
	}
	natsPortEnv := strconv.Itoa(bus.AnyPort)
	if natsPort != 0 {
		natsPortEnv = strconv.Itoa(natsPort)
	}
	a := &apiProc{
		dataDir:  dataDir,
		floor:    o.bin != "",
		natsPort: natsPort,
		cookies:  []*http.Cookie{{Name: "rasputin-session", Value: sessToken}, {Name: auth.SessionCookieName, Value: consoleToken}},
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
		"RASPUTIN_HTTP_ADDR=" + httpAddr,
		"RASPUTIN_NATS_HOST=127.0.0.1",
		"RASPUTIN_NATS_PORT=" + natsPortEnv,
		"RASPUTIN_OBS_INGEST_ADDR=" + ingestAddr,
		"RASPUTIN_SELF_NODE_ID=cp1",
		"RASPUTIN_MESH_BACKEND=mock",
		"RASPUTIN_DNS=off",
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
		a.waitHTTP(t)
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
	for _, c := range a.cookies {
		req.AddCookie(c)
	}
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
			assertOSChosenPorts(t, api)
			// TC-988-32: plaintext is refused, and the pinned agent joins, on
			// the bus port the api's log names.
			busPort := api.busPort(t)
			bustlstest.AssertPlaintextRefused(t, fmt.Sprintf("127.0.0.1:%d", busPort))

			// And the bus works: a node seeded with the pin joins.
			id := tc.node
			a := startAgent(t, agentOpts{id: id, url: fmt.Sprintf("nats://127.0.0.1:%d", busPort), token: api.mint(t, id), pin: pin})
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
//
// TC-988-34: the test holds the bus port P from before the api starts until
// after it has stopped (the listener's Close is registered before the api's
// stop, and cleanups run last-in first-out). A bus that tried to bind P would
// fail to start and end the api before its HTTP listener, so an api that is
// up, answering and still running has no bus listener. P is never released,
// so no other socket can be mistaken for one.
func busDown(t *testing.T, o apiOpts, failedFile, otherFile, logWhat string) {
	t.Helper()
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	o.natsPort = held.Addr().(*net.TCPAddr).Port
	api, _ := startAPI(t, o)
	api.waitLog(t, logWhat, logWhat, "file=", failedFile)

	resp, _, err := api.do(http.MethodGet, "/healthz", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz = (%v, %v), want 200", resp, err)
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
