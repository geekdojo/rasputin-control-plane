package identitytest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/execrun"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
)

// SwitchEnv set to functest.Required turns every missing dependency's skip
// into a failure, which is how CI makes the identity tests an enforced gate.
const SwitchEnv = "RASPUTIN_IDENTITY_FUNCTIONAL"

// HomeEnv is the install directory scripts/install-identity.sh fills:
// keycloak/, jre/ and chrome-linux64/chrome.
const HomeEnv = "RASPUTIN_IDENTITY_HOME"

// TB is the slice of testing.TB the Package uses, declared by its consumer so
// a unit test can pass a recorder. *testing.T satisfies it.
type TB interface {
	functest.TB
	Context() context.Context
}

// M is the slice of *testing.M Package.Run uses.
type M interface{ Run() int }

// Package holds one Env per test package: the first test that asks for it
// starts it, every later test shares it, and TestMain's Run tears it down
// with proof.
type Package struct {
	config func() (Config, error)
	stderr io.Writer

	cfgOnce sync.Once
	cfg     Config
	cfgErr  error

	once     sync.Once
	env      *Env
	startErr error
	starts   int // how many times a start was attempted; for tests
}

// NewPackage returns a Package whose Config comes from config, called once,
// on first use. A test package passes ConfigFromEnv, or a function that
// wraps it.
func NewPackage(config func() (Config, error)) *Package {
	return &Package{config: config, stderr: os.Stderr}
}

func (p *Package) loadConfig() (Config, error) {
	p.cfgOnce.Do(func() { p.cfg, p.cfgErr = p.config() })
	return p.cfg, p.cfgErr
}

// Env returns the package's running Env, starting it on first call. A
// missing dependency skips tb, or fails it when SwitchEnv is required. A
// dependency that is present but broken always fails it, and so does every
// later call: the start is attempted once. With a recorder tb whose Fatalf
// returns, Env returns nil.
func (p *Package) Env(tb TB) *Env {
	tb.Helper()
	cfg, err := p.loadConfig()
	if err != nil {
		functest.SkipOrFail(tb, SwitchEnv, "%v", err)
		return nil
	}
	if !p.preflight(tb, cfg) {
		return nil
	}
	p.once.Do(func() {
		p.starts++
		h, err := New(cfg)
		if err != nil {
			p.startErr = err
			return
		}
		p.env, p.startErr = h.Start(tb.Context())
	})
	if p.startErr != nil {
		tb.Fatalf("identitytest: the identity environment did not start: %v", p.startErr)
		return nil
	}
	return p.env
}

// Headscale starts the package's mesh coordinator on first call and returns
// its URL and a pool holding only its CA. docker is checked first, as for
// Env.
func (p *Package) Headscale(tb TB) (string, *Env) {
	tb.Helper()
	cfg, err := p.loadConfig()
	if err != nil {
		functest.SkipOrFail(tb, SwitchEnv, "%v", err)
		return "", nil
	}
	if !p.preflightDocker(tb, cfg, "Headscale") {
		return "", nil
	}
	env := p.Env(tb)
	if env == nil {
		return "", nil
	}
	url, _, err := env.Headscale(tb.Context())
	if err != nil {
		tb.Fatalf("%v", err)
		return "", nil
	}
	return url, env
}

// Browser starts the package's browser on first call and returns a chromedp
// context for it. The pinned Chrome is checked first.
func (p *Package) Browser(tb TB) (context.Context, *Env) {
	tb.Helper()
	cfg, err := p.loadConfig()
	if err != nil {
		functest.SkipOrFail(tb, SwitchEnv, "%v", err)
		return nil, nil
	}
	if !executable(cfg.ChromePath) {
		functest.SkipOrFail(tb, SwitchEnv, "the browser (Chrome for Testing) is not installed: no executable %s (scripts/install-identity.sh)", cfg.ChromePath)
		return nil, nil
	}
	env := p.Env(tb)
	if env == nil {
		return nil, nil
	}
	ctx, _, err := env.Browser(tb.Context())
	if err != nil {
		tb.Fatalf("%v", err)
		return nil, nil
	}
	return ctx, env
}

// preflight checks Keycloak, the JRE and docker before anything starts, and
// reports the first one missing through SkipOrFail, naming it and the path
// or command it looked for.
func (p *Package) preflight(tb TB, cfg Config) bool {
	tb.Helper()
	if kcsh := filepath.Join(cfg.KeycloakHome, "bin", "kc.sh"); !executable(kcsh) {
		functest.SkipOrFail(tb, SwitchEnv, "the identity service (Keycloak) is not installed: no executable %s (scripts/install-identity.sh)", kcsh)
		return false
	}
	if java := filepath.Join(cfg.JavaHome, "bin", "java"); !executable(java) {
		functest.SkipOrFail(tb, SwitchEnv, "the JRE is not installed: no executable %s (scripts/install-identity.sh)", java)
		return false
	}
	return p.preflightDocker(tb, cfg, "PostgreSQL")
}

// preflightDocker checks for the docker CLI and a daemon that answers.
func (p *Package) preflightDocker(tb TB, cfg Config, forWhat string) bool {
	tb.Helper()
	if _, err := exec.LookPath(cfg.DockerBin); err != nil {
		functest.SkipOrFail(tb, SwitchEnv, "%s needs docker, and there is no docker CLI: %q: %v", forWhat, cfg.DockerBin, err)
		return false
	}
	d := docker{bin: cfg.DockerBin, run: cfg.Run}
	if err := d.info(tb.Context()); err != nil {
		functest.SkipOrFail(tb, SwitchEnv, "%s needs docker, and %s info found no daemon: %v", forWhat, cfg.DockerBin, err)
		return false
	}
	return true
}

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0
}

// Run runs the package's tests, then closes the Env, if one started, with
// proof. A failed proof is written to stderr and turns the package red: Run
// returns 1. Otherwise it returns m.Run()'s code.
//
// Close gets a ctx that never ends, so Keycloak is SIGKILLed only if it never
// honours SIGTERM, and that hangs the job until its own bound (F-966-03, an
// accepted gap).
func (p *Package) Run(m M) int {
	code := m.Run()
	if p.env == nil {
		return code
	}
	if err := p.env.Close(context.Background()); err != nil {
		_, _ = fmt.Fprintf(p.stderr, "identitytest: teardown proof failed: %v\n", err)
		return 1
	}
	return code
}

// ConfigFromEnv is the identity tests' composition root: the only place the
// environment is read. It reads HomeEnv (layout keycloak/, jre/,
// chrome-linux64/chrome) and builds the logger (text to stderr, at the level
// -test.v would want: INFO), the clock, crypto/rand, execrun's runner and the
// /proc scan. An unset HomeEnv is a missing dependency.
func ConfigFromEnv() (Config, error) {
	home := os.Getenv(HomeEnv)
	if home == "" {
		return Config{}, errors.New(HomeEnv + " is not set, so there is no installed identity service, JRE or browser (scripts/install-identity.sh)")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		docker = "docker" // the preflight names it
	}
	return Config{
		KeycloakHome: filepath.Join(home, "keycloak"),
		JavaHome:     filepath.Join(home, "jre"),
		ChromePath:   filepath.Join(home, "chrome-linux64", "chrome"),
		DockerBin:    docker,
		TempParent:   os.TempDir(), // each Env makes, and removes, its own root here
		Logger:       slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Now:          time.Now,
		Rand:         rand.Reader,
		Run:          CmdRunner(execrun.CombinedOutput),
		Procs:        ScanProc,
	}, nil
}
