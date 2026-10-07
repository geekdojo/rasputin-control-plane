package secretstoretest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// These tests need no bao binary: the fakes are /bin/sh scripts. What they
// cannot show is that OpenBao accepts the rendered config; only
// TestSecretStore_SmokeWriteReadKV shows that.

func validConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		BinaryPath: "/nonexistent/bao",
		TempParent: t.TempDir(),
		Logger:     slog.New(slog.DiscardHandler),
		Now:        time.Now,
		Rand:       rand.Reader,
	}
}

// writeFake writes an executable /bin/sh script into its own temp dir, never
// TempParent, and returns its path.
func writeFake(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-bao")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// fifo makes a named pipe the fake writes its PID to. Reading it blocks until
// the fake has written, so the test waits on that fact and on no timer.
func fifo(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pid.fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("read pid: %v", err)
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Errorf("pid %q: %v", b, err)
	}
	return pid
}

func assertReaped(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		t.Fatalf("no pid to check (%d)", pid)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("kill -0 %d = %v, want ESRCH: the process is still there", pid, err)
	}
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("%s holds %v, want nothing", dir, names)
	}
}

// TC-753-01: New refuses a Config missing any one field, naming it, and does
// no I/O: a complete Config leaves TempParent empty.
func TestNew_RefusesIncompleteConfig(t *testing.T) {
	cases := []struct {
		field string
		mut   func(*Config)
	}{
		{"BinaryPath", func(c *Config) { c.BinaryPath = "" }},
		{"TempParent", func(c *Config) { c.TempParent = "" }},
		{"Logger", func(c *Config) { c.Logger = nil }},
		{"Now", func(c *Config) { c.Now = nil }},
		{"Rand", func(c *Config) { c.Rand = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			cfg := validConfig(t)
			tc.mut(&cfg)
			h, err := New(cfg)
			if h != nil {
				t.Errorf("New returned a Harness for a Config with no %s", tc.field)
			}
			if err == nil || !strings.HasPrefix(err.Error(), "secretstoretest:") ||
				!strings.Contains(err.Error(), "Config."+tc.field) {
				t.Errorf("err = %v, want a secretstoretest: error naming Config.%s", err, tc.field)
			}
		})
	}
	t.Run("complete", func(t *testing.T) {
		cfg := validConfig(t)
		h, err := New(cfg)
		if err != nil || h == nil {
			t.Fatalf("New(complete) = %v, %v", h, err)
		}
		assertEmpty(t, cfg.TempParent)
	})
}

// listenerBlock returns the body of the one listener "tcp" block, failing
// unless there is exactly one.
func listenerBlock(t *testing.T, hcl string) string {
	t.Helper()
	if n := strings.Count(hcl, `listener "tcp"`); n != 1 {
		t.Fatalf("%d listener \"tcp\" blocks, want 1:\n%s", n, hcl)
	}
	start := strings.Index(hcl, `listener "tcp" {`)
	if start < 0 {
		t.Fatalf("no listener \"tcp\" { in:\n%s", hcl)
	}
	body := hcl[start+len(`listener "tcp" {`):]
	end := strings.Index(body, "\n}")
	if end < 0 {
		t.Fatalf("listener block not closed:\n%s", hcl)
	}
	return body[:end]
}

// hasSetting reports whether text holds a line `key = value`, whitespace
// around the = ignored.
func hasSetting(text, key, value string) bool {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == key && strings.TrimSpace(v) == value {
			return true
		}
	}
	return false
}

// TC-753-02: the main config carries S8's transport, with the two
// disable_unauthed_* options INSIDE the listener block (F-753-01), S6's
// PebbleDB with clustering off, and a static seal reading a file:// key.
func TestRenderServerHCL(t *testing.T) {
	p := serverPaths{
		StoreCA:    "/t/ca/store-ca.pem",
		ServerCert: "/t/server/leaf.pem",
		ServerKey:  "/t/server/leaf.key",
		SealKey:    "/t/seal-key",
		Storage:    "/t/data",
	}
	hcl := renderServerHCL(p, 18299)
	listener := listenerBlock(t, hcl)

	for _, kv := range [][2]string{
		{"address", `"127.0.0.1:18299"`},
		{"tls_cert_file", `"/t/server/leaf.pem"`},
		{"tls_key_file", `"/t/server/leaf.key"`},
		{"tls_client_ca_file", `"/t/ca/store-ca.pem"`},
		{"tls_require_and_verify_client_cert", "true"},
		{"disable_unauthed_rekey_endpoints", "true"},
		{"disable_unauthed_generate_root_endpoints", "true"},
	} {
		if !hasSetting(listener, kv[0], kv[1]) {
			t.Errorf("listener block lacks %s = %s:\n%s", kv[0], kv[1], listener)
		}
	}
	// Placement: the disable_unauthed_* keys appear nowhere outside the
	// listener block.
	outside := strings.Replace(hcl, listener, "", 1)
	for _, k := range []string{"disable_unauthed_rekey_endpoints", "disable_unauthed_generate_root_endpoints"} {
		if strings.Contains(outside, k) {
			t.Errorf("%s appears outside the listener block", k)
		}
	}

	for _, want := range []string{
		`storage "pebbledb" {`,
		`seal "static" {`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("config lacks %s:\n%s", want, hcl)
		}
	}
	for _, kv := range [][2]string{
		{"path", `"/t/data"`},
		{"disable_clustering", "true"},
		{"current_key_id", `"secretstoretest"`},
		{"current_key", `"file:///t/seal-key"`},
		{"api_addr", `"https://127.0.0.1:18299"`},
	} {
		if !hasSetting(hcl, kv[0], kv[1]) {
			t.Errorf("config lacks %s = %s:\n%s", kv[0], kv[1], hcl)
		}
	}
	for _, banned := range []string{"unix", "raft", "cluster_addr", "0.0.0.0", "audit", "disable_mlock"} {
		if strings.Contains(hcl, banned) {
			t.Errorf("config contains %q:\n%s", banned, hcl)
		}
	}
}

// TC-753-03: the init config is self-init stanzas creating exactly the
// policy, the kv-v2 mount, cert auth and the role, and nothing else.
func TestRenderInitJSON(t *testing.T) {
	if KVMount != "harness-kv" || ClientRole != "harness-client" {
		t.Fatalf("KVMount, ClientRole = %q, %q", KVMount, ClientRole)
	}
	pem := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	b, err := renderInitJSON(pem)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Initialize []map[string]struct {
			Request []map[string]initRequest `json:"request"`
		} `json:"initialize"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	byPath := map[string]initRequest{}
	for _, block := range doc.Initialize {
		for _, stanza := range block {
			for _, named := range stanza.Request {
				for _, r := range named {
					if _, dup := byPath[r.Path]; dup {
						t.Errorf("two requests on %s", r.Path)
					}
					byPath[r.Path] = r
				}
			}
		}
	}
	wantPaths := []string{
		"sys/policies/acl/" + KVMount,
		"sys/mounts/" + KVMount,
		"sys/auth/cert",
		"auth/cert/certs/" + ClientRole,
	}
	if len(byPath) != len(wantPaths) {
		t.Errorf("requests on %d paths, want exactly %v: %v", len(byPath), wantPaths, byPath)
	}
	for p := range byPath {
		if strings.HasPrefix(p, "sys/audit") || strings.HasPrefix(p, "sys/init") {
			t.Errorf("request touches %s", p)
		}
	}

	pol := byPath["sys/policies/acl/"+KVMount]
	text, _ := pol.Data["policy"].(string)
	if text != `path "harness-kv/*" { capabilities = ["create", "read", "update"] }`+"\n" {
		t.Errorf("policy = %q, want create/read/update on harness-kv/* and nothing else", text)
	}
	if strings.Contains(text, "sudo") || strings.Count(text, "path ") != 1 {
		t.Errorf("policy grants more than one path or sudo: %q", text)
	}

	mount := byPath["sys/mounts/"+KVMount]
	opts, _ := mount.Data["options"].(map[string]any)
	if mount.Data["type"] != "kv" || opts["version"] != "2" {
		t.Errorf("mount data = %v, want type kv, options.version \"2\"", mount.Data)
	}
	if a := byPath["sys/auth/cert"]; a.Data["type"] != "cert" {
		t.Errorf("auth data = %v, want type cert", a.Data)
	}

	role := byPath["auth/cert/certs/"+ClientRole]
	if role.Data["certificate"] != string(pem) {
		t.Errorf("role certificate = %q, want the store CA PEM byte for byte", role.Data["certificate"])
	}
	if got := role.Data["allowed_common_names"]; !reflect.DeepEqual(got, []any{ClientRole}) {
		t.Errorf("allowed_common_names = %v, want [%s]", got, ClientRole)
	}
	if got := role.Data["token_policies"]; !reflect.DeepEqual(got, []any{KVMount}) {
		t.Errorf("token_policies = %v, want [%s]", got, KVMount)
	}
	for _, r := range byPath {
		if r.Operation != "update" {
			t.Errorf("%s operation = %q, want update", r.Path, r.Operation)
		}
	}
}

// TC-753-04: Start refuses a binary whose version is not exactly the pinned
// release, before it runs `server` or makes anything under TempParent.
func TestStart_RefusesAnUnpinnedRelease(t *testing.T) {
	if pinnedVersion() != "v2.7.0" {
		t.Fatalf("pinnedVersion() = %q, want the tag after the last ':' of %q", pinnedVersion(), OpenBaoRelease)
	}
	for _, got := range []string{"OpenBao v2.7.1 (fake)", "OpenBao v2.7.01 (fake)"} {
		t.Run(got, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "server-ran")
			cfg := validConfig(t)
			cfg.BinaryPath = writeFake(t, `case "$1" in
version) echo "`+got+`" ;;
server) touch "`+marker+`" ;;
esac
`)
			h, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			s, err := h.Start(t.Context())
			if s != nil || err == nil {
				t.Fatalf("Start = %v, %v; want a refusal", s, err)
			}
			if !strings.Contains(err.Error(), "want OpenBao v2.7.0") || !strings.Contains(err.Error(), got) {
				t.Errorf("err = %v, want it to name v2.7.0 and %q", err, got)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the fake's server subcommand ran (stat %v)", err)
			}
			assertEmpty(t, cfg.TempParent)
		})
	}
}

// TC-753-05: a store that exits before it is healthy fails Start with the
// exit status and its stderr (F-753-09), and leaves no process and no temp
// root behind.
func TestStart_StoreExitsEarly(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	cfg := validConfig(t)
	cfg.BinaryPath = writeFake(t, `case "$1" in
version) echo "OpenBao v2.7.0 (fake)" ;;
server) echo $$ > "`+pidFile+`"; echo "bind: address already in use" >&2; exit 3 ;;
esac
`)
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.Start(t.Context())
	if s != nil || err == nil {
		t.Fatalf("Start = %v, %v; want an error", s, err)
	}
	for _, want := range []string{"exit status 3", "bind: address already in use"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to carry %q", err, want)
		}
	}
	assertReaped(t, readPID(t, pidFile))
	assertEmpty(t, cfg.TempParent)
}

// TC-753-06: ctx ends before the store is healthy. Start names the last
// health answer, and its teardown waits on SIGTERM under a ctx that has not
// ended (F-753-03), so the store stops with no WARN.
func TestStart_CtxEndsBeforeHealthy(t *testing.T) {
	pidPipe := fifo(t)
	log, rec := logkittest.New()
	refused := make(chan struct{})
	cfg := validConfig(t)
	cfg.Logger = slog.New(&signalOn{inner: log.Handler(), msg: "secret store not healthy yet",
		attr: "connection refused", ch: refused})
	cfg.BinaryPath = writeFake(t, `case "$1" in
version) echo "OpenBao v2.7.0 (fake)" ;;
server) echo $$ > "`+pidPipe+`"; exec tail -f /dev/null ;;
esac
`)
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pid := make(chan int, 1)
	go func() {
		// Blocks until the fake has written its PID: the store is alive and
		// not listening. Then waits for the harness to have recorded a
		// refused health check. Only then is ctx cancelled.
		b, err := os.ReadFile(pidPipe)
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			n = -1
		}
		pid <- n
		<-refused
		cancel()
	}()
	s, err := h.Start(ctx)
	if s != nil || err == nil {
		t.Fatalf("Start = %v, %v; want an error", s, err)
	}
	if !strings.Contains(err.Error(), "not healthy when ctx ended") ||
		!strings.Contains(err.Error(), "connection refused") {
		t.Errorf("err = %v, want it to name the ended ctx and the last health answer (connection refused)", err)
	}
	p := <-pid
	assertReaped(t, p)
	assertEmpty(t, cfg.TempParent)

	stopped := rec.Matching(slog.LevelInfo, "secret store stopped")
	if len(stopped) != 1 {
		t.Fatalf("%d 'secret store stopped' records, want 1", len(stopped))
	}
	if got, _ := logkittest.Attr(stopped[0], "pid"); got != strconv.Itoa(p) {
		t.Errorf("stopped pid = %q, want %d", got, p)
	}
	if w := rec.Matching(slog.LevelWarn, "ignored SIGTERM"); len(w) != 0 {
		t.Errorf("teardown SIGKILLed a store that honours SIGTERM: %d WARN records", len(w))
	}
}

// signalOn passes every record to inner, and closes ch the first time a
// record with message msg carries attr in any field's value.
type signalOn struct {
	inner     slog.Handler
	msg, attr string
	ch        chan struct{}
	once      sync.Once
}

func (h *signalOn) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

func (h *signalOn) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == h.msg {
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), h.attr) {
				h.once.Do(func() { close(h.ch) })
				return false
			}
			return true
		})
	}
	return h.inner.Handle(ctx, r)
}

func (h *signalOn) WithAttrs(as []slog.Attr) slog.Handler { return h }
func (h *signalOn) WithGroup(string) slog.Handler         { return h }

// launched starts a store process under a fresh root that runs setup, then
// writes its PID, then runs body. It waits until the PID is written (a fact),
// so whatever setup does is in force before the test can signal the process.
// It returns the Store, the PID and the root.
func launched(t *testing.T, log *slog.Logger, setup, body string) (*Store, int, string) {
	t.Helper()
	pidPipe := fifo(t)
	bin := writeFake(t, setup+`echo $$ > "`+pidPipe+`"
`+body)
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Store{log: log, root: root}
	if err := s.launch(bin); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(pidPipe)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return s, pid, root
}

// TC-753-07: a store that ignores SIGTERM is SIGKILLed only because the ctx
// given to Close has ended, with one WARN naming its pid (F-753-03,
// F-753-10).
func TestClose_KillsAStoreThatIgnoresSIGTERM(t *testing.T) {
	log, rec := logkittest.New()
	s, pid, root := launched(t, log, "trap '' TERM\n", "exec tail -f /dev/null\n")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := s.Close(ctx); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
	assertReaped(t, pid)
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("root still there: stat %v", err)
	}
	warns := rec.Matching(slog.LevelWarn, "secret store ignored SIGTERM; killed")
	if len(warns) != 1 {
		t.Fatalf("%d WARN records, want 1", len(warns))
	}
	if got, _ := logkittest.Attr(warns[0], "pid"); got != strconv.Itoa(pid) {
		t.Errorf("WARN pid = %q, want %d", got, pid)
	}
}

// TC-753-08: a second Close returns the first one's result, signals nothing
// and logs nothing.
func TestClose_Idempotent(t *testing.T) {
	log, rec := logkittest.New()
	s, pid, _ := launched(t, log, "", "exec tail -f /dev/null\n")

	first := s.Close(context.Background())
	assertReaped(t, pid)
	n := len(rec.Records())
	second := s.Close(context.Background())

	if first != nil || second != first {
		t.Errorf("Close, Close = %v, %v; want the same nil result twice", first, second)
	}
	if got := len(rec.Records()); got != n {
		t.Errorf("second Close logged %d record(s)", got-n)
	}
	if st := rec.Matching(slog.LevelInfo, "secret store stopped"); len(st) != 1 {
		t.Errorf("%d 'secret store stopped' records, want 1", len(st))
	}
}

// TC-753-09: Close reports what it could not remove, joined with any other
// teardown error, after reaping the process (F-753-10).
func TestClose_ReportsResidue(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("this case needs a non-root user: root ignores directory modes, so the residue cannot be made")
	}
	s, pid, root := launched(t, slog.New(slog.DiscardHandler), "", "exec tail -f /dev/null\n")
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(locked, 0o700); err != nil {
			t.Errorf("unlock %s for cleanup: %v", locked, err)
		}
	})

	err := s.Close(context.Background())
	if err == nil {
		t.Fatal("Close = nil with an undeletable file under the root")
	}
	for _, want := range []string{filepath.Join(locked, "f"), "teardown left " + root + " behind"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %q", err, want)
		}
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != 2 {
		t.Errorf("err is not the errors.Join of both teardown failures: %#v", err)
	}
	assertReaped(t, pid)
}

// lineLog keeps only the last lines, an unterminated last line included, for
// the early-exit error.
func TestLineLogTail(t *testing.T) {
	l := newLineLog(slog.New(slog.DiscardHandler), "stderr", 3)
	if got := l.tail(); got != "(none)" {
		t.Errorf("empty tail = %q", got)
	}
	l.consume(strings.NewReader("a\nb\r\nc\npartial"))
	if got := l.tail(); got != "b | c | partial" {
		t.Errorf("tail = %q, want %q", got, "b | c | partial")
	}
}

// checkHealth calls the store healthy only on 200 with initialized=true and
// sealed=false. A sealed or uninitialized store, any other status, or an
// unreadable body is not healthy, and the status names what was seen.
func TestCheckHealth(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		body   string
		ok     bool
		status string
	}{
		{"healthy", 200, `{"initialized":true,"sealed":false}`, true, "200 initialized=true sealed=false"},
		{"sealed", 200, `{"initialized":true,"sealed":true}`, false, "200 initialized=true sealed=true"},
		{"uninitialized", 200, `{"initialized":false,"sealed":false}`, false, "200 initialized=false sealed=false"},
		{"sealed 503", 503, `{"initialized":true,"sealed":true}`, false, "503 initialized=true sealed=true"},
		{"standby 429", 429, `{"initialized":true,"sealed":false}`, false, "429 initialized=true sealed=false"},
		{"unreadable", 200, `not json`, false, "200, unreadable body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/sys/health" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(tc.code)
				if _, err := io.WriteString(w, tc.body); err != nil {
					t.Errorf("write the health body: %v", err)
				}
			}))
			defer srv.Close()
			s := &Store{url: srv.URL}
			ok, status, err := s.checkHealth(t.Context(), srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.ok || !strings.HasPrefix(status, tc.status) {
				t.Errorf("checkHealth = %t, %q; want %t, %q", ok, status, tc.ok, tc.status)
			}
		})
	}
}
