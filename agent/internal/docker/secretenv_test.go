package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The unit half of geekdojo/geekdojo-brain#776 on the agent: the order of the
// Compose calls a secret-bearing deploy makes, which of them get the values,
// the guard, the config-hash record and what Status reads. Compose itself is
// a fake here; secretenv_functional_test.go runs the real one.

const (
	envAppID   = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	envKey     = "RASPUTIN_SECRET_DB_PASSWORD"
	envHashA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	envHashB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	envHashC   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	refCompose = "services:\n  web:\n    image: busybox:1.36.1\n    environment:\n      DB_PASSWORD: ${RASPUTIN_SECRET_DB_PASSWORD}\n"
)

// guardJSON is what `config --no-interpolate --format json` prints for
// refCompose.
const guardJSON = `{"name":"x","services":{"web":{"environment":{"DB_PASSWORD":"${RASPUTIN_SECRET_DB_PASSWORD}"},"image":"busybox:1.36.1"}}}`

func canaryValue(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "S776-" + hex.EncodeToString(b)
}

// envCall is one docker CLI call the fake saw: its argv after the compose
// file and project, and the environment it was given (nil for none).
type envCall struct {
	sub    []string
	file   string
	env    []string
	stale  bool // the config-hash record existed when the call ran
	onDisk string
}

func (c envCall) is(sub ...string) bool {
	return len(c.sub) >= len(sub) && slices.Equal(c.sub[:len(sub)], sub)
}

// fakeCompose answers the compose subcommands Deploy, Status, quiesce, Stop,
// Pull and CheckVolumes run, and records every call with its environment.
type fakeCompose struct {
	t  *testing.T
	c  *ComposeBackend
	mu sync.Mutex

	calls []envCall
	guard string
	// hashWith is `config --hash` with values; hashWithout without them.
	hashWith, hashWithout string
	ps                    string
	upErr                 error
	upOut                 string
}

func newFakeCompose(t *testing.T) *fakeCompose {
	t.Helper()
	f := &fakeCompose{
		t:           t,
		guard:       guardJSON,
		hashWith:    "web " + envHashA + "\n",
		hashWithout: "level=warning msg=\"The \\\"RASPUTIN_SECRET_DB_PASSWORD\\\" variable is not set. Defaulting to a blank string.\"\nweb " + envHashB + "\n",
		ps:          `{"Name":"x-web-1","Service":"web","State":"running","ExitCode":0,"Labels":"com.docker.compose.config-hash=` + envHashA + `"}` + "\n",
	}
	f.c = &ComposeBackend{dir: t.TempDir()}
	f.c.exec = func(ctx context.Context, args ...string) ([]byte, error) { return f.handle(nil, args) }
	f.c.execEnv = func(ctx context.Context, env []string, args ...string) ([]byte, error) { return f.handle(env, args) }
	return f
}

func (f *fakeCompose) handle(env []string, args []string) ([]byte, error) {
	call := envCall{env: env}
	if len(args) >= 5 && args[0] == "compose" {
		call.file, call.sub = args[2], args[5:]
		b, _ := os.ReadFile(f.c.composePath(envAppID))
		call.onDisk = string(b)
	} else {
		call.sub = args
	}
	_, err := os.Stat(f.c.configHashRecordPath(envAppID))
	call.stale = err == nil
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	switch {
	case call.is("config", "--no-interpolate"):
		return []byte(f.guard), nil
	case call.is("config", "--hash"):
		if env != nil {
			return []byte(f.hashWith), nil
		}
		return []byte(f.hashWithout), nil
	case call.is("ps", "--format"):
		return []byte(f.ps), nil
	case call.is("up"):
		return []byte(f.upOut), f.upErr
	}
	return nil, nil
}

func (f *fakeCompose) composeCalls() []envCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []envCall
	for _, c := range f.calls {
		if c.file != "" {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeCompose) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

// scanForCanary fails if any file under root holds canary.
func scanForCanary(t *testing.T, root, canary string) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(canary)) {
			t.Errorf("%s holds the secret value", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TC-776-17: a deploy with values runs, in order: the guard on a staged file
// with no values; the stale record removed; the live compose written; `config
// --hash` with the values; `up` with the values. Status, quiesce, Stop, Pull
// and CheckVolumes afterwards run with no values.
//
// TC-776-18: afterwards no file under the state directory holds the value,
// and config-hash.json is 0600 and one of the files TightenAppState tightens.
func TestDeploySecrets_CallOrderAndEnvConfinement(t *testing.T) {
	ctx := context.Background()
	f := newFakeCompose(t)
	canary := canaryValue(t)
	env := proto.AppSecretEnv{envKey: canary}
	if err := atrest.EnsureSecretDir(f.c.appDir(envAppID)); err != nil {
		t.Fatal(err)
	}
	if err := atrest.WriteSecretFile(f.c.configHashRecordPath(envAppID), []byte(`{"web":"`+envHashC+`"}`)); err != nil {
		t.Fatal(err)
	}

	status, detail, err := f.c.Deploy(ctx, envAppID, "app", refCompose, env)
	if err != nil || status != proto.AppStatusRunning {
		t.Fatalf("Deploy = %s, %q, %v", status, detail, err)
	}
	calls := f.composeCalls()
	var order []string
	for _, c := range calls {
		switch {
		case c.is("config", "--no-interpolate"):
			order = append(order, "guard")
			if !strings.HasPrefix(filepath.Base(c.file), ".guard-") || c.env != nil {
				t.Errorf("guard ran on %s with env %v; want a staged file and no values", c.file, c.env != nil)
			}
			if !c.stale {
				t.Error("the stale record was already gone at the guard; it must outlive a refusal")
			}
		case c.is("config", "--hash"):
			order = append(order, "hash")
			if c.stale || c.onDisk != refCompose {
				t.Errorf("config --hash ran with the stale record present (%v) or before the live compose was written (%v)", c.stale, c.onDisk != refCompose)
			}
			if !slices.Equal(c.env, []string{envKey + "=" + canary}) {
				t.Error("config --hash did not get the values")
			}
		case c.is("up"):
			order = append(order, "up")
			if !slices.Equal(c.env, []string{envKey + "=" + canary}) {
				t.Error("up did not get the values")
			}
		default:
			if c.env != nil {
				t.Errorf("%v got the values", c.sub)
			}
		}
	}
	if want := []string{"guard", "hash", "up"}; !slices.Equal(order, want) {
		t.Fatalf("call order %v, want %v", order, want)
	}

	// Everything after the deploy runs without the values.
	f.reset()
	if _, _, err := f.c.Status(ctx, envAppID); err != nil {
		t.Fatal(err)
	}
	if err := f.c.StopApp(ctx, envAppID, 10); err != nil {
		t.Fatal(err)
	}
	if err := f.c.StartApp(ctx, envAppID); err != nil {
		t.Fatal(err)
	}
	_, _ = f.c.Pull(ctx, envAppID, "services: {}\n")
	_, _, _ = f.c.CheckVolumes(ctx, envAppID, "services: {}\n")
	_, _, _ = f.c.Stop(ctx, envAppID, false)
	seen := map[string]bool{}
	for _, c := range f.composeCalls() {
		seen[strings.Join(c.sub[:min(2, len(c.sub))], " ")] = true
		if c.env != nil {
			t.Errorf("%v ran with the values after the deploy", c.sub)
		}
	}
	// Status's own `config --hash` does not run here: the record answers it
	// (TC-776-21 covers the call where there is no record).
	if seen["config --hash"] {
		t.Error("Status ran config --hash although the deploy left a record")
	}
	for _, want := range []string{"ps --format", "stop --timeout", "start", "down", "pull --quiet", "config --volumes"} {
		if !seen[want] {
			t.Errorf("%q never ran, so its environment was not checked (saw %v)", want, seen)
		}
	}

	// TC-776-18.
	scanForCanary(t, f.c.dir, canary)
	st, err := os.Stat(f.c.configHashRecordPath(envAppID))
	if err != nil {
		t.Fatalf("config-hash.json: %v", err)
	}
	if st.Mode().Perm() != atrest.SecretFileMode {
		t.Errorf("config-hash.json mode %v, want %v", st.Mode().Perm(), atrest.SecretFileMode)
	}
	if !slices.Contains(agentWrittenFiles, configHashRecordFile) {
		t.Error("config-hash.json is not in agentWrittenFiles, so TightenAppState leaves it")
	}
}

// TC-776-19: the guard refuses a reference outside a service's environment,
// a reference the map does not cover, and output with no JSON model — before
// `up`, with the live compose of the previous deploy unchanged, and a detail
// naming the JSON path or variable and never the value.
func TestDeploySecrets_GuardRefusals(t *testing.T) {
	ctx := context.Background()
	canary := canaryValue(t)
	env := proto.AppSecretEnv{envKey: canary}
	const ref = `"${RASPUTIN_SECRET_DB_PASSWORD}"`
	for _, tc := range []struct {
		why, guard, want string
	}{
		{"user", `{"services":{"web":{"user":` + ref + `}}}`, "services.web.user"},
		{"command", `{"services":{"web":{"command":["sh","-c",` + ref + `]}}}`, "services.web.command.2"},
		{"image", `{"services":{"web":{"image":` + ref + `}}}`, "services.web.image"},
		{"labels", `{"services":{"web":{"labels":{"k":` + ref + `}}}}`, "services.web.labels.k"},
		{"inline config content", `{"configs":{"c":{"content":` + ref + `}},"services":{"web":{}}}`, "configs.c.content"},
		{"a config sourced from the variable", `{"configs":{"c":{"environment":"RASPUTIN_SECRET_DB_PASSWORD"}},"services":{"web":{}}}`, "configs.c.environment"},
		// F-776-12: an "x-" key is data, not an extension, below a definition.
		{"user on a service named x-", `{"services":{"x-web":{"user":` + ref + `}}}`, "services.x-web.user"},
		{"label key x-", `{"services":{"web":{"labels":{"x-leak":` + ref + `}}}}`, "services.web.labels.x-leak"},
		{"config named x-", `{"configs":{"x-cfg":{"content":` + ref + `}},"services":{"web":{}}}`, "configs.x-cfg.content"},
		{"build arg x-", `{"services":{"web":{"build":{"args":{"x-arg":` + ref + `}}}}}`, "services.web.build.args.x-arg"},
		{"a missing key", `{"services":{"web":{"environment":{"X":"${RASPUTIN_SECRET_OTHER}"}}}}`, "RASPUTIN_SECRET_OTHER"},
		{"no JSON", "level=warning msg=\"something\"\nnot json at all\n", "no JSON model"},
		{"broken JSON", "{\"services\": \n", "JSON model"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			f := newFakeCompose(t)
			const previous = "services:\n  web:\n    image: busybox:1.36.0\n"
			if err := f.c.writeCompose(envAppID, previous); err != nil {
				t.Fatal(err)
			}
			f.guard = tc.guard
			status, detail, err := f.c.Deploy(ctx, envAppID, "app", refCompose, env)
			if err == nil || status != proto.AppStatusFailed {
				t.Fatalf("Deploy = %s, %v; want a refusal", status, err)
			}
			if !strings.Contains(detail, tc.want) || strings.Contains(detail, canary) {
				t.Errorf("detail %q does not name %q, or holds the value", detail, tc.want)
			}
			for _, c := range f.composeCalls() {
				if c.is("up") || c.env != nil {
					t.Errorf("%v ran (env %v) after the guard refused", c.sub, c.env != nil)
				}
			}
			if b, _ := os.ReadFile(f.c.composePath(envAppID)); string(b) != previous {
				t.Errorf("the live compose changed: %q", b)
			}
		})
	}
}

// TC-776-20 (F-776-04): Compose's warnings ahead of the guard's JSON do not
// refuse a valid app; the deploy reaches `up`.
func TestDeploySecrets_GuardSkipsLeadingWarnings(t *testing.T) {
	f := newFakeCompose(t)
	f.guard = "time=\"2026-10-27T00:00:00Z\" level=warning msg=\"/x/docker-compose.yml: the attribute `version` is obsolete\"\n" + guardJSON + "\n"
	status, detail, err := f.c.Deploy(context.Background(), envAppID, "app", refCompose, proto.AppSecretEnv{envKey: canaryValue(t)})
	if err != nil || status != proto.AppStatusRunning {
		t.Fatalf("Deploy = %s, %q, %v", status, detail, err)
	}
	if !slices.ContainsFunc(f.composeCalls(), func(c envCall) bool { return c.is("up") }) {
		t.Fatal("the deploy never reached up")
	}
}

// The guard accepts list-form environment and ignores extension fields, at the
// top level and directly on a service: what `config --no-interpolate` prints
// for a compose that puts its environment in an anchor (measured on Compose
// 5.3.1).
func TestDeploySecrets_GuardAcceptsListFormAndExtensions(t *testing.T) {
	f := newFakeCompose(t)
	f.guard = `{"services":{"web":{"environment":["DB_PASSWORD=${RASPUTIN_SECRET_DB_PASSWORD}"],"x-note":"${RASPUTIN_SECRET_DB_PASSWORD}"}},"x-common":{"environment":["DB_PASSWORD=${RASPUTIN_SECRET_DB_PASSWORD}"]}}`
	if status, detail, err := f.c.Deploy(context.Background(), envAppID, "app", refCompose, proto.AppSecretEnv{envKey: "v"}); err != nil {
		t.Fatalf("Deploy = %s, %q, %v", status, detail, err)
	}
}

// TC-776-21: Status takes the wanted hashes from the record when there is
// one, and computes them live otherwise; an unreadable record leaves Outdated
// false.
func TestStatus_OutdatedUsesTheRecord(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		why    string
		record string // "" none; "dir" unreadable
		live   string // the hash `config --hash` without values prints
		want   bool
	}{
		{"the record matches the label; the value-less live hash does not", `{"web":"` + envHashA + `"}`, envHashB, false},
		{"the label differs from the record", `{"web":"` + envHashC + `"}`, envHashA, true},
		{"no record, the live hash matches", "", envHashA, false},
		{"no record, the live hash differs", "", envHashB, true},
		{"an unreadable record", "dir", envHashB, false},
	} {
		t.Run(tc.why, func(t *testing.T) {
			f := newFakeCompose(t)
			f.hashWithout = "web " + tc.live + "\n"
			if err := f.c.writeCompose(envAppID, refCompose); err != nil {
				t.Fatal(err)
			}
			switch tc.record {
			case "":
			case "dir":
				if err := os.Mkdir(f.c.configHashRecordPath(envAppID), 0o700); err != nil {
					t.Fatal(err)
				}
			default:
				if err := atrest.WriteSecretFile(f.c.configHashRecordPath(envAppID), []byte(tc.record)); err != nil {
					t.Fatal(err)
				}
			}
			log.SetOutput(&bytes.Buffer{})
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			status, services, err := f.c.Status(ctx, envAppID)
			if err != nil || status != proto.AppStatusRunning || len(services) != 1 {
				t.Fatalf("Status = %s, %v, %v", status, services, err)
			}
			if services[0].Outdated != tc.want {
				t.Errorf("Outdated = %v, want %v", services[0].Outdated, tc.want)
			}
			usedLive := slices.ContainsFunc(f.composeCalls(), func(c envCall) bool { return c.is("config", "--hash") })
			if wantLive := tc.record == ""; usedLive != wantLive {
				t.Errorf("live config --hash ran = %v, want %v", usedLive, wantLive)
			}
		})
	}
}

// TC-776-22: a deploy without values removes a record a previous secret
// deploy left, before `up`; no call carries values, and Status then computes
// the hash live.
func TestDeployWithoutSecrets_ClearsAStaleRecord(t *testing.T) {
	ctx := context.Background()
	f := newFakeCompose(t)
	if err := atrest.EnsureSecretDir(f.c.appDir(envAppID)); err != nil {
		t.Fatal(err)
	}
	if err := atrest.WriteSecretFile(f.c.configHashRecordPath(envAppID), []byte(`{"web":"`+envHashA+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, detail, err := f.c.Deploy(ctx, envAppID, "app", "services:\n  web:\n    image: busybox:1.36.1\n", nil); err != nil {
		t.Fatalf("Deploy: %q, %v", detail, err)
	}
	for _, c := range f.composeCalls() {
		if c.env != nil {
			t.Errorf("%v carried values", c.sub)
		}
		if c.is("up") && c.stale {
			t.Error("the stale record was still there at up")
		}
		if c.is("config", "--no-interpolate") {
			t.Error("the guard ran for a deploy without values")
		}
	}
	if _, err := os.Stat(f.c.configHashRecordPath(envAppID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the record is still there: %v", err)
	}
	f.reset()
	if _, _, err := f.c.Status(ctx, envAppID); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(f.composeCalls(), func(c envCall) bool { return c.is("config", "--hash") && c.env == nil }) {
		t.Error("Status did not compute the hash live")
	}
}

// A failed record write or `config --hash` fails the deploy before `up`.
func TestDeploySecrets_RecordFailureStopsBeforeUp(t *testing.T) {
	f := newFakeCompose(t)
	f.hashWith = "level=warning msg=\"nothing\"\n"
	_, detail, err := f.c.Deploy(context.Background(), envAppID, "app", refCompose, proto.AppSecretEnv{envKey: "v"})
	if err == nil || !strings.Contains(detail, "no service hash") {
		t.Fatalf("Deploy = %q, %v; want the record failure", detail, err)
	}
	if slices.ContainsFunc(f.composeCalls(), func(c envCall) bool { return c.is("up") }) {
		t.Error("up ran after the record failed")
	}
}

// TC-776-23: ps output with a Compose warning ahead of the NDJSON parses, and
// a line that opens with '{' and is not JSON is still an error.
func TestParsePsLines_SkipsWarnings(t *testing.T) {
	out := "time=\"x\" level=warning msg=\"The \\\"RASPUTIN_SECRET_DB_PASSWORD\\\" variable is not set. Defaulting to a blank string.\"\n" +
		`{"Name":"x-web-1","Service":"web","State":"running"}` + "\n" +
		`{"Name":"x-db-1","Service":"db","State":"running"}` + "\n"
	lines, err := parsePsLines([]byte(out))
	if err != nil || len(lines) != 2 || lines[0].Service != "web" || lines[1].Service != "db" {
		t.Fatalf("parsePsLines = %+v, %v", lines, err)
	}
	if _, err := parsePsLines([]byte("level=warning msg=x\n{not json\n")); err == nil {
		t.Fatal("a malformed JSON line parsed")
	}
}

// recordingBackend counts Deploy calls and keeps the last env.
type recordingBackend struct {
	*MockBackend
	mu      sync.Mutex
	deploys int
	env     proto.AppSecretEnv
	fail    bool
}

func (r *recordingBackend) Deploy(ctx context.Context, appID, name, composeYAML string, env proto.AppSecretEnv) (proto.AppStatus, string, error) {
	r.mu.Lock()
	r.deploys++
	r.env = env
	r.mu.Unlock()
	if r.fail {
		return proto.AppStatusFailed, "docker compose up: exit status 1", errOh
	}
	return proto.AppStatusRunning, "", nil
}

func (r *recordingBackend) state() (int, proto.AppSecretEnv) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deploys, r.env
}

// logSink is a log output that is safe to read while a handler writes, and
// signals the first line containing want.
type logSink struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	want string
	seen chan struct{}
	once sync.Once
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.buf.Write(p)
	if strings.Contains(l.buf.String(), l.want) {
		l.once.Do(func() { close(l.seen) })
	}
	return n, err
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newRecordingBackend(t *testing.T, fail bool) *recordingBackend {
	t.Helper()
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &recordingBackend{MockBackend: mb, fail: fail}
}

// TC-776-24: docker.deploy_secrets and docker.deploy both reach the deploy
// handler; a command with an invalid key is refused, naming the key, and
// Deploy is never called.
func TestHandlers_DeploySecretsRoutingAndKeyValidation(t *testing.T) {
	nc := startNATS(t)
	b := newRecordingBackend(t, false)
	subs, err := RegisterHandlers(nc, "node-1", b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	var ack proto.AppDeployAck
	request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{AppID: "a1"}, &ack)
	request(t, nc, proto.AppDeploySecretsSubject("node-1"), proto.AppDeployCmd{AppID: "a1", SecretEnv: proto.AppSecretEnv{envKey: "v"}}, &ack)
	if n, env := b.state(); !ack.OK || n != 2 || env[envKey] != "v" {
		t.Fatalf("ack %+v after %d deploy(s), env %d; want both subjects to reach Deploy with the map", ack, n, len(env))
	}

	canary := canaryValue(t)
	request(t, nc, proto.AppDeploySecretsSubject("node-1"), proto.AppDeployCmd{AppID: "a1", SecretEnv: proto.AppSecretEnv{"LD_PRELOAD": canary}}, &ack)
	if ack.OK || !strings.Contains(ack.Detail, "LD_PRELOAD") || strings.Contains(ack.Detail, canary) {
		t.Fatalf("ack %+v; want a refusal naming LD_PRELOAD without the value", ack)
	}
	if n, _ := b.state(); n != 2 {
		t.Fatalf("Deploy ran for an invalid key (%d calls)", n)
	}
}

// TC-776-16: a deploy that fails logs nothing and acks nothing holding the
// value.
func TestHandleDeploy_NeverLogsValues(t *testing.T) {
	logged := &logSink{want: "docker.deploy a1", seen: make(chan struct{})}
	log.SetOutput(logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	nc := startNATS(t)
	b := newRecordingBackend(t, true)
	subs, err := RegisterHandlers(nc, "node-1", b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	canary := canaryValue(t)
	var ack proto.AppDeployAck
	request(t, nc, proto.AppDeploySecretsSubject("node-1"), proto.AppDeployCmd{AppID: "a1", ComposeYAML: refCompose, SecretEnv: proto.AppSecretEnv{envKey: canary}}, &ack)
	if n, _ := b.state(); ack.OK || n != 1 {
		t.Fatalf("ack %+v after %d deploy(s); want the failure", ack, n)
	}
	// The handler answers and then logs: wait for the line, so the check
	// below reads the whole of what it wrote.
	<-logged.seen
	raw, _ := json.Marshal(ack)
	if strings.Contains(logged.String(), canary) || strings.Contains(string(raw), canary) {
		t.Fatalf("the value reached the log or the ack:\nlog: %s\nack: %s", logged.String(), raw)
	}
}

// TC-776-25: the mock backend accepts the map and never persists it.
func TestMockBackend_NeverPersistsSecretEnv(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	canary := canaryValue(t)
	if _, _, err := mb.Deploy(context.Background(), "a1", "x", refCompose, proto.AppSecretEnv{envKey: canary}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a1", mockStateFileName)); err != nil {
		t.Fatalf("state.json: %v", err)
	}
	scanForCanary(t, dir, canary)
}
