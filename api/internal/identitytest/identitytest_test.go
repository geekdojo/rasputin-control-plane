package identitytest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// These tests need no Keycloak, PostgreSQL, docker or Chrome: the runner is a
// fake, and kc.sh, java and Chrome are /bin/sh scripts. What they cannot show
// is what the real services do with the rendered input; the functional
// self-test (selftest_functional_test.go) shows that.

const goodVersion = "Keycloak 26.8.2\nJVM: 25.0.5 (Eclipse Adoptium OpenJDK 64-Bit Server VM 25.0.5+8-LTS)\nOS: Linux 6.8.0 amd64\n"

// fakeRunner records every call and answers from a table keyed on the
// command's first two words.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	answers map[string]func(args []string) ([]byte, error)
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	f.mu.Unlock()
	key := filepath.Base(name)
	if filepath.Base(name) == "env" {
		key = "env"
	} else if len(args) > 0 {
		key += " " + args[0]
	}
	if a, ok := f.answers[key]; ok {
		return a(args)
	}
	return nil, fmt.Errorf("fake runner: no answer for %s", key)
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func answer(out string) func([]string) ([]byte, error) {
	return func([]string) ([]byte, error) { return []byte(out), nil }
}

// goodRunner answers every docker call a clean start and teardown makes.
func goodRunner() *fakeRunner {
	return &fakeRunner{answers: map[string]func([]string) ([]byte, error){
		"env":         answer(goodVersion),
		"docker info": answer("29.0.0"),
		"docker run":  answer("pgcontainer1\n"),
		"docker port": answer("0.0.0.0:49001\n127.0.0.1:49002\n"),
		"docker exec": answer("127.0.0.1:5432 - accepting connections"),
		"docker rm":   answer("pgcontainer1"),
		"docker ps":   answer(""),
	}}
}

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
}

// installed lays out a fake install: keycloak/bin/kc.sh running kcBody,
// jre/bin/java, a docker CLI, chrome-linux64/chrome and a deny list.
func installed(t *testing.T, kcBody string) (Config, *fakeRunner) {
	t.Helper()
	home := t.TempDir()
	writeExec(t, filepath.Join(home, "keycloak", "bin", "kc.sh"), kcBody)
	if err := os.MkdirAll(filepath.Join(home, "keycloak", "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(home, "jre", "bin", "java"), "exit 0\n")
	writeExec(t, filepath.Join(home, "bin", "docker"), "exit 0\n")
	writeExec(t, filepath.Join(home, "chrome-linux64", "chrome"), "exit 0\n")
	if err := os.MkdirAll(filepath.Join(home, "password-blacklists"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "password-blacklists", flows.DenylistFile), []byte("correcthorsebatterystaple\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := goodRunner()
	return Config{
		KeycloakHome: filepath.Join(home, "keycloak"),
		JavaHome:     filepath.Join(home, "jre"),
		ChromePath:   filepath.Join(home, "chrome-linux64", "chrome"),
		DenylistDir:  filepath.Join(home, "password-blacklists"),
		DockerBin:    filepath.Join(home, "bin", "docker"),
		TempParent:   t.TempDir(),
		Logger:       slog.New(slog.DiscardHandler),
		Now:          time.Now,
		Rand:         rand.Reader,
		Run:          r.run,
		Procs:        func() ([]ProcInfo, error) { return nil, nil },
	}, r
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("%s holds %d entries, want none", dir, len(ents))
	}
}

// recTB records Fatalf and Skipf; its Fatalf returns, so the caller's
// return-after-report is exercised.
type recTB struct {
	ctx           context.Context
	fatals, skips []string
}

func (r *recTB) Helper()                  {}
func (r *recTB) Context() context.Context { return r.ctx }
func (r *recTB) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}
func (r *recTB) Skipf(format string, args ...any) {
	r.skips = append(r.skips, fmt.Sprintf(format, args...))
}

// TC-966-01: with the switch required, each missing dependency fails the
// caller once, never skips, names the dependency and what was looked for,
// and nothing starts: the runner sees no call after the failed preflight.
func TestPackage_MissingDependencyFails(t *testing.T) {
	t.Setenv(SwitchEnv, functest.Required)
	type call func(p *Package, tb TB)
	env := func(p *Package, tb TB) { p.Env(tb) }
	cases := []struct {
		name       string
		breakIt    func(t *testing.T, cfg *Config, r *fakeRunner)
		call       call
		want       []string
		wantCalls  int
		fromEnvVar bool
	}{
		{"no kc.sh", func(t *testing.T, c *Config, _ *fakeRunner) { c.KeycloakHome = t.TempDir() }, env,
			[]string{"Keycloak", "bin/kc.sh"}, 0, false},
		{"no java", func(t *testing.T, c *Config, _ *fakeRunner) { c.JavaHome = t.TempDir() }, env,
			[]string{"the JRE", "bin/java"}, 0, false},
		{"no docker CLI", func(t *testing.T, c *Config, _ *fakeRunner) { c.DockerBin = filepath.Join(t.TempDir(), "docker") }, env,
			[]string{"PostgreSQL needs docker", "no docker CLI"}, 0, false},
		{"no docker daemon", func(_ *testing.T, _ *Config, r *fakeRunner) {
			r.answers["docker info"] = func([]string) ([]byte, error) { return nil, errors.New("Cannot connect to the Docker daemon") }
		}, env, []string{"PostgreSQL needs docker", "found no daemon", "Cannot connect"}, 1, false},
		{"RASPUTIN_IDENTITY_HOME unset", nil, env, []string{HomeEnv + " is not set"}, 0, true},
		{"Headscale without docker", func(t *testing.T, c *Config, _ *fakeRunner) { c.DockerBin = filepath.Join(t.TempDir(), "docker") },
			func(p *Package, tb TB) { p.Headscale(tb) }, []string{"Headscale needs docker"}, 0, false},
		{"Browser without Chrome", func(t *testing.T, c *Config, _ *fakeRunner) { c.ChromePath = filepath.Join(t.TempDir(), "chrome") },
			func(p *Package, tb TB) { p.Browser(tb) }, []string{"the browser (Chrome for Testing)", "chrome"}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, r := installed(t, "exit 0\n")
			var p *Package
			if tc.fromEnvVar {
				t.Setenv(HomeEnv, "")
				p = NewPackage(ConfigFromEnv)
			} else {
				tc.breakIt(t, &cfg, r)
				p = NewPackage(func() (Config, error) { return cfg, nil })
			}
			tb := &recTB{ctx: t.Context()}
			tc.call(p, tb)
			if len(tb.fatals) != 1 || len(tb.skips) != 0 {
				t.Fatalf("Fatalf %d, Skipf %d; want exactly one Fatalf: %q %q", len(tb.fatals), len(tb.skips), tb.fatals, tb.skips)
			}
			for _, want := range append(tc.want, SwitchEnv+"="+functest.Required) {
				if !strings.Contains(tb.fatals[0], want) {
					t.Errorf("Fatalf %q does not name %q", tb.fatals[0], want)
				}
			}
			if got := r.count(); got != tc.wantCalls {
				t.Errorf("the runner saw %d calls (%v), want %d: nothing may run after a failed preflight", got, r.calls, tc.wantCalls)
			}
			if p.starts != 0 {
				t.Errorf("a start was attempted %d times", p.starts)
			}
			assertEmpty(t, cfg.TempParent)
		})
	}
}

// TC-966-05: a present but broken Keycloak (the wrong release, the wrong
// JVM, output that cannot be read) fails Start with no I/O beyond the
// version call.
func TestStart_RefusesAnUnpinnedRelease(t *testing.T) {
	cases := map[string]struct{ out, want string }{
		"keycloak 26.8.1": {strings.Replace(goodVersion, "26.8.2", "26.8.1", 1),
			"is not the pinned release: want Keycloak 26.8.2 (keycloak/keycloak:26.8.2), got Keycloak 26.8.1"},
		"jvm 21": {"Keycloak 26.8.2\nJVM: 21.0.9 (Red Hat OpenJDK 21.0.9+10-LTS)\n",
			"is not on the pinned runtime: want JVM 25.0.5+8"},
		"unreadable": {"Error: Could not find or load main class\n", "cannot read the Keycloak and JVM versions"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, r := installed(t, "exit 0\n")
			r.answers["env"] = answer(tc.out)
			h, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			env, err := h.Start(t.Context())
			if env != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Start = %v, %v; want %q", env, err, tc.want)
			}
			if r.count() != 1 {
				t.Errorf("runner calls = %v, want only the version call", r.calls)
			}
			assertEmpty(t, cfg.TempParent)
		})
	}
}

// TC-966-05: a start that failed once fails every later Package.Env with the
// same error, through Fatalf and never Skipf, whether the switch is set or
// not, and the start is attempted once.
func TestPackage_FailedStartFailsEveryCaller(t *testing.T) {
	for _, sw := range []string{"", functest.Required} {
		t.Run("switch="+sw, func(t *testing.T) {
			t.Setenv(SwitchEnv, sw)
			cfg, r := installed(t, "exit 0\n")
			r.answers["env"] = answer(strings.Replace(goodVersion, "26.8.2", "26.8.1", 1))
			p := NewPackage(func() (Config, error) { return cfg, nil })
			first, second := &recTB{ctx: t.Context()}, &recTB{ctx: t.Context()}
			if p.Env(first) != nil || p.Env(second) != nil {
				t.Fatal("Env returned an Env from a failed start")
			}
			if len(first.fatals) != 1 || len(second.fatals) != 1 || first.fatals[0] != second.fatals[0] {
				t.Errorf("fatals = %q, %q; want the same one error twice", first.fatals, second.fatals)
			}
			if len(first.skips)+len(second.skips) != 0 {
				t.Errorf("a broken dependency skipped: %q %q", first.skips, second.skips)
			}
			if !strings.Contains(first.fatals[0], "is not the pinned release") {
				t.Errorf("fatal = %q", first.fatals[0])
			}
			if p.starts != 1 {
				t.Errorf("starts = %d, want 1", p.starts)
			}
		})
	}
}

// TC-966-05: the browser's version comparator refuses anything but the
// pinned Chrome for Testing release.
func TestCheckChromeVersion(t *testing.T) {
	if v, err := checkChromeVersion("HeadlessChrome/157.0.8103.78"); err != nil || v != "157.0.8103.78" {
		t.Errorf("the pinned version = %q, %v", v, err)
	}
	for _, p := range []string{"HeadlessChrome/157.0.8103.79", "Chrome/158.0.0.0", "HeadlessChrome", ""} {
		if _, err := checkChromeVersion(p); err == nil {
			t.Errorf("checkChromeVersion(%q) = nil, want a refusal", p)
		}
	}
}

// TC-966-06: New refuses a Config missing any one field, naming it, and does
// no I/O: TempParent stays empty and the runner is never called.
func TestNew_RefusesIncompleteConfig(t *testing.T) {
	fields := map[string]func(*Config){
		"KeycloakHome": func(c *Config) { c.KeycloakHome = "" },
		"JavaHome":     func(c *Config) { c.JavaHome = "" },
		"ChromePath":   func(c *Config) { c.ChromePath = "" },
		"DockerBin":    func(c *Config) { c.DockerBin = "" },
		"TempParent":   func(c *Config) { c.TempParent = "" },
		"Logger":       func(c *Config) { c.Logger = nil },
		"Now":          func(c *Config) { c.Now = nil },
		"Rand":         func(c *Config) { c.Rand = nil },
		"Run":          func(c *Config) { c.Run = nil },
		"Procs":        func(c *Config) { c.Procs = nil },
		"DenylistDir":  func(c *Config) { c.DenylistDir = "" },
	}
	for field, clear := range fields {
		cfg, r := installed(t, "exit 0\n")
		parent := cfg.TempParent
		clear(&cfg)
		if h, err := New(cfg); h != nil || err == nil || !strings.Contains(err.Error(), "Config."+field) {
			t.Errorf("New without %s = %v, %v; want an error naming it", field, h, err)
		}
		if r.count() != 0 {
			t.Errorf("New without %s called the runner", field)
		}
		assertEmpty(t, parent)
	}
	cfg, _ := installed(t, "exit 0\n")
	if _, err := New(cfg); err != nil {
		t.Errorf("New with every field = %v", err)
	}
}

// TC-966-07: keycloak.conf carries the ports, TLS 1.3, the certificate and
// key, the test CA as the trust store, no plain HTTP, the local cache, the
// front's URL as hostname, and the database.
func TestRenderKeycloakConf(t *testing.T) {
	conf := string(renderKeycloakConf(kcPaths{
		CertFile: "/r/server/leaf.pem", KeyFile: "/r/server/leaf.key",
		TrustFile: "/r/ca/identitytest-ca.pem", VaultDir: "/r/vault",
	}, kcPorts{HTTPS: 18443, Mgmt: 18444, DB: 15432}, "https://127.0.0.1:19000", secret.New([]byte("db-pw-sentinel"))))
	for _, want := range []string{
		"https-port=18443", "http-management-port=18444", "https-protocols=TLSv1.3",
		"https-certificate-file=/r/server/leaf.pem", "https-certificate-key-file=/r/server/leaf.key",
		"https-trust-store-file=/r/ca/identitytest-ca.pem", "http-enabled=false", "http-host=127.0.0.1",
		"cache=local", "hostname=https://127.0.0.1:19000", "vault-dir=/r/vault",
		"db-url=jdbc:postgresql://127.0.0.1:15432/keycloak", "db-username=keycloak", "db-password=db-pw-sentinel",
	} {
		if !strings.Contains("\n"+conf, "\n"+want+"\n") {
			t.Errorf("keycloak.conf lacks the line %q:\n%s", want, conf)
		}
	}
}

// TC-966-07: the realm is valid JSON with realm harness, the public client
// with the standard flow, S256 PKCE and the one redirect URI, and one enabled
// user with the given password and no required actions. A password with
// JSON's special characters stays inside its field.
func TestRenderRealm(t *testing.T) {
	pw := `p"w\` + "\n" + `}`
	b, err := renderRealm(UserName, secret.New([]byte(pw)))
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Realm   string `json:"realm"`
		Enabled bool   `json:"enabled"`
		Clients []struct {
			ClientID            string            `json:"clientId"`
			PublicClient        bool              `json:"publicClient"`
			StandardFlowEnabled bool              `json:"standardFlowEnabled"`
			RedirectURIs        []string          `json:"redirectUris"`
			Attributes          map[string]string `json:"attributes"`
		} `json:"clients"`
		Users []struct {
			Username        string   `json:"username"`
			Enabled         bool     `json:"enabled"`
			RequiredActions []string `json:"requiredActions"`
			Credentials     []struct {
				Type, Value string
				Temporary   bool
			} `json:"credentials"`
		} `json:"users"`
	}
	if err := json.Unmarshal(b, &realm); err != nil {
		t.Fatalf("the realm is not JSON: %v\n%s", err, b)
	}
	if realm.Realm != Realm || !realm.Enabled || len(realm.Clients) != 1 || len(realm.Users) != 1 {
		t.Fatalf("realm = %+v", realm)
	}
	c := realm.Clients[0]
	if c.ClientID != ClientID || !c.PublicClient || !c.StandardFlowEnabled || len(c.RedirectURIs) != 1 ||
		c.RedirectURIs[0] != RedirectURI || c.Attributes["pkce.code.challenge.method"] != "S256" {
		t.Errorf("client = %+v", c)
	}
	u := realm.Users[0]
	if u.Username != UserName || !u.Enabled || len(u.RequiredActions) != 0 || len(u.Credentials) != 1 ||
		u.Credentials[0].Type != "password" || u.Credentials[0].Value != pw || u.Credentials[0].Temporary {
		t.Errorf("user = %+v", u)
	}
}

// TC-966-07 (the file modes) and the start path up to Keycloak's exit: the
// fake kc.sh runs from the Env's own home (bin/ copied, so the import
// directory it lists is the Env's), finds the realm and keycloak.conf at
// 0600, then exits 3. Start fails with its output, tears down, and leaves
// nothing behind.
func TestStart_WritesOwnerOnlyFilesAndTearsDownAnEarlyExit(t *testing.T) {
	modes := filepath.Join(t.TempDir(), "modes")
	cfg, r := installed(t, `home="$(cd "$(dirname "$0")/.." && pwd)"
ls -ln "$home/data/import/harness-realm.json" > "`+modes+`"
for a in "$@"; do case "$a" in --config-file=*) ls -ln "${a#--config-file=}" >> "`+modes+`" ;; esac; done
echo "ERROR: Failed to start server in (production) mode"
exit 3
`)
	log, rec := logkittest.New()
	cfg.Logger = log
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	env, err := h.Start(t.Context())
	if env != nil || err == nil {
		t.Fatalf("Start = %v, %v; want the early exit", env, err)
	}
	for _, want := range []string{"exited before it was ready", "exit status 3", "Failed to start server"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to carry %q", err, want)
		}
	}
	b, rerr := os.ReadFile(modes)
	if rerr != nil {
		t.Fatal(rerr)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("modes = %q, want the realm file and keycloak.conf", b)
	}
	for _, l := range lines {
		// The ten mode characters; macOS adds "@", SELinux ".", after them.
		if len(l) < 10 || l[:10] != "-rw-------" {
			t.Errorf("%q is not owner-only", l)
		}
	}
	assertEmpty(t, cfg.TempParent)
	if !strings.Contains(strings.Join(r.calls, "\n"), "docker rm -f -v pgcontainer1") {
		t.Errorf("the database container was not removed: %v", r.calls)
	}
	if got := rec.Matching(slog.LevelInfo, "identity database stopped"); len(got) != 1 {
		t.Errorf("%d 'identity database stopped' records, want 1", len(got))
	}
	// The password went to docker only through the env file, never argv.
	for _, c := range r.calls {
		if strings.Contains(c, "POSTGRES_PASSWORD") {
			t.Errorf("a docker call carries the password variable: %s", c)
		}
	}
}

// handEnv is an Env for the teardown proof's cases, built by hand.
func handEnv(t *testing.T, log *slog.Logger, r *fakeRunner, procs ProcLister) *Env {
	t.Helper()
	cfg, _ := installed(t, "exit 0\n")
	cfg.Logger, cfg.Run, cfg.Procs = log, r.run, procs
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return &Env{h: h, log: log, docker: docker{bin: "docker", run: r.run}, root: root, ports: &reportedPorts{}}
}

// TC-966-15: the teardown proof in its five states.
func TestClose_TeardownProof(t *testing.T) {
	none := func() ([]ProcInfo, error) { return nil, nil }

	t.Run("clean", func(t *testing.T) {
		e := handEnv(t, slog.New(slog.DiscardHandler), goodRunner(), none)
		e.pgID = "pgcontainer1"
		if err := e.Close(context.Background()); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		if _, err := os.Stat(e.root); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("root still there: %v", err)
		}
	})

	t.Run("container still listed and a process naming the root, joined", func(t *testing.T) {
		r := goodRunner()
		r.answers["docker ps"] = answer("pgcontainer1\n")
		var e *Env
		e = handEnv(t, slog.New(slog.DiscardHandler), r, func() ([]ProcInfo, error) {
			return []ProcInfo{
				{Pid: 1, Cmdline: "/sbin/init"},
				{Pid: 4242, Cmdline: "/opt/jre/bin/java -Dkc.home.dir=" + e.root + "/kc"},
				{Pid: 4343, Cmdline: "chrome_crashpad_handler", Cwd: e.root + "/chrome"},
			}, nil
		})
		e.pgID = "pgcontainer1"
		err := e.Close(context.Background())
		for _, want := range []string{"teardown left container pgcontainer1 behind", "teardown left pid 4242 behind", "teardown left pid 4343 behind"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Close = %v, want it to name %q", err, want)
			}
		}
		if err != nil && strings.Contains(err.Error(), "pid 1 ") {
			t.Errorf("Close named a process that does not name the root: %v", err)
		}
		var joined interface{ Unwrap() []error }
		if !errors.As(err, &joined) {
			t.Errorf("Close = %#v, want an errors.Join", err)
		}
	})

	t.Run("root cannot be removed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Fatal("this case needs a non-root user: root ignores directory modes")
		}
		e := handEnv(t, slog.New(slog.DiscardHandler), goodRunner(), none)
		locked := filepath.Join(e.root, "locked")
		if err := os.Mkdir(locked, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(locked, "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		err := e.Close(context.Background())
		for _, want := range []string{"remove " + e.root, "teardown left " + e.root + " behind"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Close = %v, want it to name %q", err, want)
			}
		}
	})

	t.Run("Keycloak ignores SIGTERM until ctx ends", func(t *testing.T) {
		log, rec := logkittest.New()
		e := handEnv(t, log, goodRunner(), none)
		ready := filepath.Join(t.TempDir(), "ready")
		if err := syscall.Mkfifo(ready, 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := proctest.Start(proctest.Spec{
			Bin: "/bin/sh", Args: []string{"-c", `trap '' TERM; echo $$ > "` + ready + `"; exec tail -f /dev/null`},
			Logger: log, Name: "identity service", Source: "keycloak", Group: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		pidText, err := os.ReadFile(ready)
		if err != nil {
			t.Fatal(err)
		}
		e.kc = p
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := e.Close(ctx); err != nil {
			t.Errorf("Close = %v, want nil: the kill is the ended ctx's, and the proof holds", err)
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(pidText)))
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Errorf("kill -0 %d = %v, want ESRCH", pid, err)
		}
		warns := rec.Matching(slog.LevelWarn, "identity service ignored SIGTERM; killed")
		if len(warns) != 1 {
			t.Fatalf("%d WARN records, want 1", len(warns))
		}
		if got, _ := logkittest.Attr(warns[0], "pid"); got != strconv.Itoa(pid) {
			t.Errorf("WARN pid = %q, want %d", got, pid)
		}
	})

	t.Run("cannot list processes", func(t *testing.T) {
		e := handEnv(t, slog.New(slog.DiscardHandler), goodRunner(), func() ([]ProcInfo, error) {
			return nil, errors.New("list /proc: no such file")
		})
		if err := e.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot show no process is left") {
			t.Errorf("Close = %v, want the proof to say it cannot show it", err)
		}
	})
}

// fakeM is a *testing.M stand-in.
type fakeM struct{ code int }

func (m fakeM) Run() int { return m.code }

// TC-966-15: Package.Run returns 1 and writes the joined error to stderr when
// the proof fails, and m.Run()'s code when it passes or nothing started.
func TestPackage_RunTurnsAFailedProofRed(t *testing.T) {
	r := goodRunner()
	r.answers["docker ps"] = answer("pgcontainer1\n")
	e := handEnv(t, slog.New(slog.DiscardHandler), r, func() ([]ProcInfo, error) { return nil, nil })
	e.pgID = "pgcontainer1"
	var stderr bytes.Buffer
	p := &Package{stderr: &stderr, env: e}
	if got := p.Run(fakeM{code: 0}); got != 1 {
		t.Errorf("Run = %d with a failed proof, want 1", got)
	}
	if !strings.Contains(stderr.String(), "teardown proof failed") || !strings.Contains(stderr.String(), "pgcontainer1") {
		t.Errorf("stderr = %q, want the proof's error", stderr.String())
	}

	clean := handEnv(t, slog.New(slog.DiscardHandler), goodRunner(), func() ([]ProcInfo, error) { return nil, nil })
	stderr.Reset()
	p = &Package{stderr: &stderr, env: clean}
	if got := p.Run(fakeM{code: 3}); got != 3 || stderr.Len() != 0 {
		t.Errorf("Run = %d, stderr %q; want m.Run's 3 and nothing written", got, stderr.String())
	}
	if got := (&Package{stderr: &stderr}).Run(fakeM{code: 0}); got != 0 {
		t.Errorf("Run with nothing started = %d", got)
	}
}

// ScanProc sees this test's own process on Linux, with its working
// directory; elsewhere there is no /proc and it says so.
func TestScanProc(t *testing.T) {
	procs, err := ScanProc()
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Errorf("ScanProc on %s = nil error, want one: there is no /proc", runtime.GOOS)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	for _, p := range procs {
		if p.Pid == os.Getpid() {
			if p.Cwd != wd || p.Cmdline == "" {
				t.Errorf("own process = %+v, want cwd %s and a command line", p, wd)
			}
			return
		}
	}
	t.Errorf("ScanProc did not list pid %d", os.Getpid())
}

// The ports watcher reads Keycloak 26.8.2's start line, and nothing else.
func TestReportedPorts(t *testing.T) {
	var r reportedPorts
	r.watch("2026-11-12 12:13:33,326 INFO  [io.quarkus] (main) Keycloak 26.8.2 on JVM started in 1.956s.")
	if h, m := r.get(); h != 0 || m != 0 {
		t.Errorf("ports from a line without them = %d, %d", h, m)
	}
	r.watch("2026-11-12 12:14:59,008 INFO  [io.quarkus] (main) Keycloak 26.8.2 on JVM (powered by Quarkus 3.40.1.1) started in 1.850s. " +
		"Listening on: https://127.0.0.1:55679. Management interface listening on https://127.0.0.1:55678.")
	if h, m := r.get(); h != 55679 || m != 55678 {
		t.Errorf("ports = %d, %d; want 55679, 55678", h, m)
	}
}

// parseKeycloakVersion accepts the measured 26.8.2 output on the pinned JRE.
func TestParseKeycloakVersion(t *testing.T) {
	jvm, err := parseKeycloakVersion(goodVersion)
	if err != nil || jvm != "25.0.5 (Eclipse Adoptium OpenJDK 64-Bit Server VM 25.0.5+8-LTS)" {
		t.Errorf("the pinned output = %q, %v", jvm, err)
	}
}

// TC-972-17: the readiness wait startPostgres and TestPostgresTLSOnly share.
// Its ctx has no deadline, so only the container's own answers or a cancel
// can end it.
func TestAwaitPostgres(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	isready := []string{"-h", "127.0.0.1"}

	t.Run("a container that is not running fails at once", func(t *testing.T) {
		r := &fakeRunner{answers: map[string]func([]string) ([]byte, error){
			"docker exec": func([]string) ([]byte, error) {
				return []byte("Error response from daemon: container pgcontainer1 is not running"), errors.New("exit status 1")
			},
		}}
		err := docker{bin: "docker", run: r.run}.awaitPostgres(context.Background(), log, "pgcontainer1", isready...)
		if err == nil || !strings.Contains(err.Error(), "pgcontainer1") || !strings.Contains(err.Error(), "is not running") {
			t.Fatalf("awaitPostgres = %v, want an error naming pgcontainer1 and \"is not running\"", err)
		}
		if n := r.count(); n != 1 {
			t.Errorf("docker calls = %d (%q), want exactly one docker exec", n, r.calls)
		}
		if want := "docker exec pgcontainer1 pg_isready -h 127.0.0.1"; len(r.calls) > 0 && r.calls[0] != want {
			t.Errorf("call = %q, want %q", r.calls[0], want)
		}
	})

	t.Run("a cancelled wait names the last status", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var mu sync.Mutex
		calls := 0
		r := &fakeRunner{answers: map[string]func([]string) ([]byte, error){
			"docker exec": func([]string) ([]byte, error) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				if calls > 1 {
					cancel() // after the first answer has been taken as the last status
				}
				return []byte("127.0.0.1:5432 - no response"), errors.New("exit status 2")
			},
		}}
		err := docker{bin: "docker", run: r.run}.awaitPostgres(ctx, log, "pgcontainer1", isready...)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("awaitPostgres = %v, want it to unwrap to context.Canceled", err)
		}
		for _, want := range []string{"pgcontainer1", "127.0.0.1:5432 - no response"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("awaitPostgres = %q, want it to name %q", err, want)
			}
		}
	})

	t.Run("an accepting server is ready", func(t *testing.T) {
		r := goodRunner()
		if err := (docker{bin: "docker", run: r.run}).awaitPostgres(context.Background(), log, "pgcontainer1", isready...); err != nil {
			t.Fatalf("awaitPostgres = %v, want nil", err)
		}
	})
}

// builtTheme lays out a theme tree holding login/theme.properties.
func builtTheme(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "login"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "login", "theme.properties"), []byte("parent=base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TC-988-16: with a ThemeDir, the Env's Keycloak home has a themes/ of its
// own: each entry of the dist's themes/ is linked in it and themes/rasputin
// links to ThemeDir. Without one, themes/ is the dist's, linked whole.
func TestThemeDir_LinkedIntoTheKeycloakHome(t *testing.T) {
	cfg, _ := installed(t, "exit 0\n")
	distThemes := filepath.Join(cfg.KeycloakHome, "themes")
	if err := os.MkdirAll(filepath.Join(distThemes, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distThemes, "README.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.ThemeDir = builtTheme(t)
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{h: h, root: t.TempDir()}
	home, err := e.makeKeycloakHome()
	if err != nil {
		t.Fatal(err)
	}
	themes := filepath.Join(home, "themes")
	info, err := os.Lstat(themes)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("themes/ = %v, %v; want a real directory", info, err)
	}
	for name, want := range map[string]string{
		"other":     filepath.Join(distThemes, "other"),
		"README.md": filepath.Join(distThemes, "README.md"),
		"rasputin":  cfg.ThemeDir,
	} {
		got, err := os.Readlink(filepath.Join(themes, name))
		if err != nil || got != want {
			t.Errorf("readlink themes/%s = %q, %v; want %q", name, got, err, want)
		}
	}

	cfg.ThemeDir = ""
	h, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e = &Env{h: h, root: t.TempDir()}
	home, err = e.makeKeycloakHome()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(filepath.Join(home, "themes")); err != nil || got != distThemes {
		t.Errorf("without a ThemeDir, readlink themes = %q, %v; want the dist's %q", got, err, distThemes)
	}
}

// TC-988-16: a ThemeDir that is missing, a file, or lacks
// login/theme.properties is refused by New, naming it, before anything runs.
func TestThemeDir_RefusesABrokenTheme(t *testing.T) {
	file := filepath.Join(t.TempDir(), "theme")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{
		"missing":                   filepath.Join(t.TempDir(), "nothing-here"),
		"a file":                    file,
		"no login/theme.properties": t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, r := installed(t, "exit 0\n")
			cfg.ThemeDir = dir
			h, err := New(cfg)
			if h != nil || err == nil || !strings.Contains(err.Error(), dir) {
				t.Fatalf("New = %v, %v; want an error naming %s", h, err, dir)
			}
			if r.count() != 0 {
				t.Errorf("New called the runner")
			}
		})
	}
}

// TC-988-28: a walk with RASPUTIN_IDENTITY_THEME unset fails under
// required, naming the variable, and skips otherwise; a theme that lacks
// login/theme.properties fails whether or not required is set.
func TestThemeDir_DependencyHandling(t *testing.T) {
	cfg, _ := installed(t, "exit 0\n")
	t.Run("unset, required", func(t *testing.T) {
		t.Setenv(SwitchEnv, functest.Required)
		p := NewPackage(func() (Config, error) { return cfg, nil })
		tb := &recTB{ctx: t.Context()}
		if p.RequireTheme(tb) || len(tb.fatals) != 1 || !strings.Contains(tb.fatals[0], ThemeEnv) {
			t.Errorf("fatals %q skips %q; want one failure naming %s", tb.fatals, tb.skips, ThemeEnv)
		}
	})
	t.Run("unset, not required", func(t *testing.T) {
		t.Setenv(SwitchEnv, "")
		p := NewPackage(func() (Config, error) { return cfg, nil })
		tb := &recTB{ctx: t.Context()}
		if p.RequireTheme(tb) || len(tb.skips) != 1 || len(tb.fatals) != 0 || !strings.Contains(tb.skips[0], ThemeEnv) {
			t.Errorf("fatals %q skips %q; want one skip naming %s", tb.fatals, tb.skips, ThemeEnv)
		}
	})
	for _, sw := range []string{functest.Required, ""} {
		t.Run("broken, switch="+sw, func(t *testing.T) {
			t.Setenv(SwitchEnv, sw)
			broken := cfg
			broken.ThemeDir = t.TempDir()
			p := NewPackage(func() (Config, error) { return broken, nil })
			tb := &recTB{ctx: t.Context()}
			if !p.RequireTheme(tb) {
				t.Fatal("RequireTheme refused a configured theme; New is what checks it")
			}
			p.Env(tb)
			if len(tb.fatals) != 1 || len(tb.skips) != 0 || !strings.Contains(tb.fatals[0], "login/theme.properties") {
				t.Errorf("fatals %q skips %q; want one failure naming login/theme.properties", tb.fatals, tb.skips)
			}
		})
	}
}

// TC-1145-21: an identity home without a usable deny list is refused by New,
// naming the list, and through Package.Env it fails the caller with or
// without the switch, never skipping: the realm's password policy names the
// list, so converge cannot apply it without one. With the list, the Env's
// Keycloak home holds a byte-equal copy at data/password-blacklists/, 0600
// in a 0700 directory.
func TestDenylist_MissingListFailsAndIsStaged(t *testing.T) {
	for name, breakIt := range map[string]func(t *testing.T, dir string){
		"no list":      func(t *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, flows.DenylistFile)) },
		"no directory": func(t *testing.T, dir string) { _ = os.RemoveAll(dir) },
		"an empty list": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, flows.DenylistFile), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a directory in its place": func(t *testing.T, dir string) {
			p := filepath.Join(dir, flows.DenylistFile)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, r := installed(t, "exit 0\n")
			breakIt(t, cfg.DenylistDir)
			list := filepath.Join(cfg.DenylistDir, flows.DenylistFile)
			if h, err := New(cfg); h != nil || err == nil || !strings.Contains(err.Error(), list) {
				t.Fatalf("New = %v, %v; want an error naming %s", h, err, list)
			}
			if r.count() != 0 {
				t.Errorf("New called the runner: %v", r.calls)
			}
			for _, sw := range []string{functest.Required, ""} {
				t.Setenv(SwitchEnv, sw)
				p := NewPackage(func() (Config, error) { return cfg, nil })
				tb := &recTB{ctx: t.Context()}
				if p.Env(tb) != nil || len(tb.fatals) != 1 || len(tb.skips) != 0 || !strings.Contains(tb.fatals[0], "password deny list") {
					t.Errorf("switch=%q: fatals %q skips %q; want one failure naming the deny list", sw, tb.fatals, tb.skips)
				}
			}
			assertEmpty(t, cfg.TempParent)
		})
	}
	t.Run("staged into the Keycloak home", func(t *testing.T) {
		cfg, _ := installed(t, "exit 0\n")
		h, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		e := &Env{h: h, root: t.TempDir()}
		home, err := e.makeKeycloakHome()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(filepath.Join(cfg.DenylistDir, flows.DenylistFile))
		got, err := os.ReadFile(denylistPath(home))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("the staged list = %q, %v; want %q", got, err, want)
		}
		for path, mode := range map[string]os.FileMode{filepath.Dir(denylistPath(home)): 0o700, denylistPath(home): 0o600} {
			if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != mode {
				t.Errorf("%s: %v, %v; want mode %o", path, info, err, mode)
			}
		}
	})
}
