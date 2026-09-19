package bustls_test

// The bus TLS switch with the REAL rasputin-api binary: what only a running
// process can show. On a fresh controlplane the api reaches require by itself
// — offer → migrate → pin delivered to its own agent → require — and
// it does so WITHOUT ending: the same process (same PID, never exits, one
// "http listening" line) answers GET /healthz on every one of a tight,
// back-to-back series of polls from before the switch until after it. The
// dev-image QEMU smoke test's 70s uptime soak failed on exactly this when the
// switch restarted the api (rasputin-os run 35146258476).
//
// It also checks, from outside, what the in-process test checks from inside:
// plaintext refused on the wire; both agents (the controlplane's own agent, on
// the token the api minted for it, and a pinned compute node) back over TLS after the switch; an unpinned node
// refused; the recorded mode; and job submits across the switch — 503 with
// Retry-After or accepted, never anything else, and accepted on retry.
//
// Whether a submit lands inside the switch is timing: the switch lasts as long
// as one in-process server replacement, and this test cannot pause a real
// process. It fires one at the moment the api logs the decision (intake is
// already closed then) and reports whether it was refused; the deterministic
// proof that a submit during the switch is refused and then accepted is
// TestFunctional_AutomaticLadder, which runs inside the switch.

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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

var (
	apiBinOnce sync.Once
	apiBin     string
	apiBinErr  error
)

// buildAPI builds rasputin-api from this workspace — with the race detector
// when this test binary has it, so a race in the switch fails this test too.
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
	httpBase string
	natsPort int
	cookie   *http.Cookie
	// agentTokenFile is where the api mints its own agent's bus token.
	agentTokenFile string

	mu      sync.Mutex
	lines   []string
	changed signal
	exited  chan struct{}

	// onLine, when set, sees every line as it is read, before waiters do.
	onLine atomic.Pointer[func(string)]
}

func (a *apiProc) log() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.lines, "\n")
}

func (a *apiProc) count(sub string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, l := range a.lines {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

func (a *apiProc) waitLog(t *testing.T, what, sub string) {
	t.Helper()
	waitFact(t, what+" in the api log", &a.changed, func() bool {
		if a.hasExited() {
			t.Fatalf("the api exited while waiting for %s\n%s", what, a.log())
		}
		return a.count(sub) > 0
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

// startAPI seeds a fresh controlplane data dir the way firstboot and an
// operator would have — a provisioned bus key, a bound join token for n1, and
// a signed-in session (written to the database directly: auth is passkey-only)
// — and starts the api binary on it.
func startAPI(t *testing.T) (a *apiProc, pin, n1Token string) {
	t.Helper()
	ctx := context.Background()
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "rasputin.db")

	key, _, err := bustls.EnsureKey(filepath.Join(dataDir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := busauth.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	n1Token, _, err = tokens.MintBound(ctx, "n1", "n1", "compute")
	_ = tokens.Close()
	if err != nil {
		t.Fatal(err)
	}
	authStore, err := auth.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := &auth.User{ID: []byte("bustls-functional-user"), Name: "operator", DisplayName: "Operator", CreatedAt: now}
	sess := &auth.Session{Token: "bustls-functional-session", UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now}
	if err := authStore.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := authStore.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	_ = authStore.Close()

	httpPort, natsPort, ingestPort := freePort(t), freePort(t), freePort(t)
	a = &apiProc{
		httpBase:       fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		natsPort:       natsPort,
		cookie:         &http.Cookie{Name: "rasputin-session", Value: sess.Token},
		agentTokenFile: filepath.Join(dataDir, "bus", proto.BusAgentTokenFileName),
		exited:         make(chan struct{}),
	}
	dead := "http://127.0.0.1:1"     // no network: release and catalog checks fail fast
	cmd := exec.Command(buildAPI(t)) // G204: the binary this test just built
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dataDir,
		"RASPUTIN_DATA_DIR=" + dataDir,
		"RASPUTIN_HTTP_ADDR=" + fmt.Sprintf("127.0.0.1:%d", httpPort),
		"RASPUTIN_NATS_HOST=127.0.0.1",
		"RASPUTIN_NATS_PORT=" + fmt.Sprint(natsPort),
		"RASPUTIN_OBS_INGEST_ADDR=" + fmt.Sprintf("127.0.0.1:%d", ingestPort),
		"RASPUTIN_SELF_NODE_ID=cp1",
		"RASPUTIN_MESH_BACKEND=mock",
		"RASPUTIN_UPDATE_TRUST=dev-permissive",
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
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start api: %v", err)
	}
	a.cmd = cmd
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if f := a.onLine.Load(); f != nil {
				(*f)(line)
			}
			a.mu.Lock()
			a.lines = append(a.lines, line)
			a.mu.Unlock()
			a.changed.fire()
		}
	}()
	go func() {
		<-readDone
		_ = cmd.Wait()
		close(a.exited)
		a.changed.fire()
	}()
	t.Cleanup(func() {
		if !a.hasExited() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-a.exited:
			case <-time.After(30 * time.Second): // bounds the one wait for exit
				_ = cmd.Process.Kill()
				<-a.exited
			}
		}
		if a.count("DATA RACE") != 0 {
			t.Errorf("the api binary (built with -race) reported a data race")
		}
		if t.Failed() {
			t.Logf("--- api log ---\n%s", a.log())
		}
	})
	a.waitLog(t, "the HTTP listener", "rasputin-api: http listening on")
	return a, key.Pin(), n1Token
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

// healthPoller asks GET /healthz back to back, each request bounded, until
// stopped: any failure is recorded.
type healthPoller struct {
	ok       atomic.Int64
	mu       sync.Mutex
	failures []string
	stop     chan struct{}
	done     chan struct{}
}

func startHealthPoller(a *apiProc) *healthPoller {
	p := &healthPoller{stop: make(chan struct{}), done: make(chan struct{})}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
	go func() {
		defer close(p.done)
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			resp, err := client.Get(a.httpBase + "/healthz")
			switch {
			case err != nil:
				p.fail(err.Error())
			default:
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					p.fail(fmt.Sprintf("status %d", resp.StatusCode))
				} else {
					p.ok.Add(1)
				}
			}
		}
	}()
	return p
}

func (p *healthPoller) fail(why string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures = append(p.failures, why)
}

func (p *healthPoller) finish() (ok int64, failures []string) {
	close(p.stop)
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ok.Load(), p.failures
}

func (a *agentProc) lineCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.lines)
}

// waitLogSince is waitLog over the lines after the first `since`.
func (a *agentProc) waitLogSince(t *testing.T, since int, what string, subs ...string) {
	t.Helper()
	waitFact(t, what+" in agent "+a.id+"'s log", &a.changed, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, l := range a.lines[since:] {
			all := true
			for _, s := range subs {
				all = all && strings.Contains(l, s)
			}
			if all {
				return true
			}
		}
		return false
	}, a.log)
}

func TestFunctional_RealAPIProcess_RequireWithoutRestart(t *testing.T) {
	skipShort(t)
	api, pin, n1Token := startAPI(t)
	pid := api.cmd.Process.Pid
	url := fmt.Sprintf("nats://127.0.0.1:%d", api.natsPort)

	// The submit fired the moment the api logs the decision: intake is closed
	// by then, so it is refused unless the whole switch already finished.
	type submitResult struct {
		code       int
		retryAfter string
		body       string
		err        error
	}
	atDecision := make(chan submitResult, 1)
	var switchPolls [2]int64 // health polls answered when the replacement began and ended
	var poller atomic.Pointer[healthPoller]
	onLine := func(line string) {
		p := poller.Load()
		switch {
		case strings.Contains(line, "bustls: migrate → require"):
			resp, body, err := api.do(http.MethodPost, "/api/jobs", `{"kind":"diag.ping","spec":{"nodeId":"cp1"}}`)
			r := submitResult{err: err, body: string(body)}
			if resp != nil {
				r.code, r.retryAfter = resp.StatusCode, resp.Header.Get("Retry-After")
			}
			atDecision <- r
		case strings.Contains(line, "bus: replacing the embedded server") && p != nil:
			switchPolls[0] = p.ok.Load()
		case strings.Contains(line, "bus: the embedded server was replaced") && p != nil:
			switchPolls[1] = p.ok.Load()
		}
	}
	api.onLine.Store(&onLine)
	// Zero-touch: the api minted its own agent's token before it was ready.
	api.waitLog(t, "the api minting its own agent's bus token", `minted a bus token for this controlplane's agent "cp1"`)
	hp := startHealthPoller(api)
	poller.Store(hp)

	// The controlplane's own agent: the token the api minted into its data dir
	// at start, no pin yet (it is delivered). A compute node seeded with the
	// pin, as a matched set is.
	cpAgent := startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: url, tokenFile: api.agentTokenFile})
	n1 := startAgent(t, agentOpts{id: "n1", url: url, token: n1Token, pin: pin})

	api.waitLog(t, "the pin delivery to the controlplane's own agent", `bustls: "cp1" holds the pin`)
	cpSince, n1Since := cpAgent.lineCount(), n1.lineCount()
	api.waitLog(t, "the switch to TLS-only completing", "bustls: require: the bus refuses plaintext")

	// Both agents rejoin the replaced server over TLS on their own.
	cpAgent.waitLogSince(t, cpSince, "the controlplane agent reconnecting after the switch", "reconnected to", fmt.Sprint(api.natsPort))
	n1.waitLogSince(t, n1Since, "the compute node reconnecting after the switch", "reconnected to", fmt.Sprint(api.natsPort))

	// The job submitted at the decision: refused-and-retryable, or accepted
	// because the switch had already finished. Nothing else.
	var first submitResult
	select {
	case first = <-atDecision:
	case <-time.After(factDeadline):
		t.Fatal("the api logged the decision but the submit made then never returned")
	}
	switch {
	case first.err != nil:
		t.Fatalf("POST /api/jobs at the decision failed outright: %v", first.err)
	case first.code == http.StatusServiceUnavailable && first.retryAfter != "":
		t.Logf("a job submitted at the decision was refused during the switch: 503, Retry-After %s", first.retryAfter)
	case first.code == http.StatusCreated:
		t.Logf("a job submitted at the decision landed after the switch had finished (201); the in-switch refusal is proven by TestFunctional_AutomaticLadder")
	default:
		t.Fatalf("POST /api/jobs at the decision = %d (Retry-After %q) %s, want 503 with Retry-After or 201", first.code, first.retryAfter, first.body)
	}

	// Now jobs run, over the new bus, to both agents.
	for _, node := range []string{"cp1", "n1"} {
		resp, body, err := api.do(http.MethodPost, "/api/jobs", fmt.Sprintf(`{"kind":"diag.ping","spec":{"nodeId":%q}}`, node))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST /api/jobs diag.ping %s after the switch = (%v, %s, %v)", node, resp, body, err)
		}
		var j struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &j); err != nil || j.ID == "" {
			t.Fatalf("job body %s: %v", body, err)
		}
		waitJobSucceeded(t, api, j.ID)
	}

	ok, failures := hp.finish()
	if len(failures) != 0 {
		t.Fatalf("GET /healthz failed %d time(s) across the switch (answered %d): %q", len(failures), ok, failures)
	}
	if ok == 0 {
		t.Fatal("the health poller never got an answer")
	}
	t.Logf("GET /healthz answered %d times back to back with no failure; %d of them while the bus server was being replaced", ok, switchPolls[1]-switchPolls[0])

	// Same process, never exited, never restarted.
	if api.hasExited() || api.cmd.Process.Pid != pid {
		t.Fatalf("the api process exited or changed (pid %d → %d)", pid, api.cmd.Process.Pid)
	}
	if n := api.count("rasputin-api: http listening on"); n != 1 {
		t.Fatalf("the api started its HTTP server %d times, want once", n)
	}
	for _, never := range []string{"rasputin-api: shutting down", "exiting 75", "DATA RACE"} {
		if api.count(never) != 0 {
			t.Fatalf("the api log contains %q", never)
		}
	}

	// The recorded state, through the api.
	resp, body, err := api.do(http.MethodGet, "/api/bus/tls", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/bus/tls = (%v, %s, %v)", resp, body, err)
	}
	var st bustls.Status
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode != bustls.ModeRequire || st.PlaintextAllowed || st.Switching || st.SwitchFailed != "" || st.Pin != pin {
		t.Fatalf("GET /api/bus/tls = %+v, want require, plaintext refused, not switching, the provisioned pin", st)
	}
	for _, n := range st.Nodes {
		if !n.BusTLS {
			t.Fatalf("node %s is not on TLS after the switch: %+v", n.ID, st.Nodes)
		}
	}

	// Plaintext is refused on the wire, and an unpinned node cannot join.
	assertPlaintextRefused(t, api.natsPort)
	stray := startAgent(t, agentOpts{id: "n-unmigrated", url: url, token: api.mint(t, "n-unmigrated")})
	stray.waitLog(t, "the TLS-required refusal of an unpinned node", "NATS connect", "tls")
	stray.stop(t)
	if api.count("bus: replacing the embedded server") != 1 {
		t.Fatalf("the bus server was replaced %d times, want once", api.count("bus: replacing the embedded server"))
	}
}

// waitJobSucceeded asks for the job until it ends. Each ask is one bounded
// HTTP round trip, back to back, under the fact deadline.
func waitJobSucceeded(t *testing.T, a *apiProc, id string) {
	t.Helper()
	deadline := time.Now().Add(factDeadline)
	for time.Now().Before(deadline) {
		resp, body, err := a.do(http.MethodGet, "/api/jobs/"+id, "")
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/jobs/%s = (%v, %s, %v)", id, resp, body, err)
		}
		var j struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(body, &j); err != nil {
			t.Fatal(err)
		}
		switch j.Status {
		case "succeeded":
			return
		case "failed", "cancelled":
			t.Fatalf("job %s %s: %s", id, j.Status, j.Error)
		}
	}
	t.Fatalf("job %s did not end within %s", id, factDeadline)
}
