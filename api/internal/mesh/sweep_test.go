package mesh

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ledgertest"
)

func sweepTestCA(t *testing.T) *MeshCA {
	t.Helper()
	ca, err := EnsureMeshCA(t.TempDir(), "sweep")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	return ca
}

// mintWithLifetime puts a leaf on disk whose NotAfter is `lifetime` away, so a
// test can put a leaf inside or outside the renew window deliberately.
func mintWithLifetime(t *testing.T, ca *MeshCA, dir, cn string, lifetime time.Duration) {
	t.Helper()
	if _, err := MintLeafToDisk(ca, dir, LeafSpec{CommonName: cn, DNSNames: []string{cn}, Lifetime: lifetime}); err != nil {
		t.Fatalf("MintLeafToDisk: %v", err)
	}
}

func notAfter(t *testing.T, dir string) time.Time {
	t.Helper()
	paths := LeafPathsIn(dir)
	pemBytes, err := os.ReadFile(paths.CertPath)
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("leaf at %s is not PEM", paths.CertPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert.NotAfter
}

// TestLeafSweep_RenewsOnTheFactAndReloadsOnlyThen is the core contract: the
// sweep renews when the leaf's NotAfter is inside the renew window, leaves a
// healthy leaf alone, and calls the reload hook ONLY when it minted.
func TestLeafSweep_RenewsOnTheFactAndReloadsOnlyThen(t *testing.T) {
	ca := sweepTestCA(t)
	expiring := t.TempDir()
	healthy := t.TempDir()
	// 30 days left: inside the 60-day renew window.
	mintWithLifetime(t, ca, expiring, "expiring.local", 30*24*time.Hour)
	// 200 days left: outside it.
	mintWithLifetime(t, ca, healthy, "healthy.local", 200*24*time.Hour)
	before := notAfter(t, expiring)
	healthyBefore := notAfter(t, healthy)

	var reloaded []string
	s := NewLeafSweeper(ca)
	for _, c := range []struct{ name, dir, cn string }{
		{"expiring", expiring, "expiring.local"},
		{"healthy", healthy, "healthy.local"},
	} {
		if err := s.Register(LeafConsumer{
			Name: c.name, Dir: c.dir,
			Spec: func() (LeafSpec, error) {
				return LeafSpec{CommonName: c.cn, DNSNames: []string{c.cn}}, nil
			},
			Reload: func(context.Context, LeafPaths) error {
				reloaded = append(reloaded, c.name)
				return nil
			},
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	rep := s.Sweep(context.Background(), nil)
	if rep.Checked != 2 {
		t.Errorf("checked = %d, want 2", rep.Checked)
	}
	if !slices.Equal(rep.Renewed, []string{"expiring"}) {
		t.Errorf("renewed = %v, want [expiring]", rep.Renewed)
	}
	if !slices.Equal(reloaded, []string{"expiring"}) {
		t.Errorf("reloaded = %v — the hook must fire only on a real renewal", reloaded)
	}
	if !slices.Equal(rep.Reloaded, []string{"expiring"}) {
		t.Errorf("report reloaded = %v, want [expiring]", rep.Reloaded)
	}
	if len(rep.Failed) != 0 {
		t.Errorf("failed = %v, want none", rep.Failed)
	}
	if !notAfter(t, expiring).After(before) {
		t.Errorf("the expiring leaf was not replaced (NotAfter still %s)", before)
	}
	if got := notAfter(t, healthy); !got.Equal(healthyBefore) {
		t.Errorf("the healthy leaf was re-minted: %s → %s", healthyBefore, got)
	}

	// A second sweep is a no-op: the fact has changed, so there is nothing
	// left to do. This is what makes the tick a safety net rather than a
	// schedule.
	reloaded = nil
	rep = s.Sweep(context.Background(), nil)
	if len(rep.Renewed) != 0 || len(reloaded) != 0 {
		t.Errorf("second sweep renewed %v / reloaded %v, want nothing", rep.Renewed, reloaded)
	}
}

// A leaf whose SANs no longer describe the service is renewed by the same
// check, so a moved hostname does not wait for the expiry window.
func TestLeafSweep_RenewsOnSpecDrift(t *testing.T) {
	ca := sweepTestCA(t)
	dir := t.TempDir()
	mintWithLifetime(t, ca, dir, "old.local", 300*24*time.Hour)

	name := "old.local"
	s := NewLeafSweeper(ca)
	if err := s.Register(LeafConsumer{
		Name: "api", Dir: dir,
		Spec: func() (LeafSpec, error) {
			return LeafSpec{CommonName: name, DNSNames: []string{name}}, nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if rep := s.Sweep(context.Background(), nil); len(rep.Renewed) != 0 {
		t.Fatalf("sweep renewed %v before any drift", rep.Renewed)
	}
	name = "new.local"
	rep := s.Sweep(context.Background(), nil)
	if !slices.Equal(rep.Renewed, []string{"api"}) {
		t.Errorf("renewed = %v, want [api] after the name moved", rep.Renewed)
	}
}

// One broken consumer must not stop the others: a sweep that gave up at the
// first error would leave every leaf after it unrenewed.
func TestLeafSweep_OneFailureDoesNotStopTheRest(t *testing.T) {
	ca := sweepTestCA(t)
	good := t.TempDir()
	reloadFails := t.TempDir()
	mintWithLifetime(t, ca, good, "good.local", time.Hour)
	mintWithLifetime(t, ca, reloadFails, "reload.local", time.Hour)

	s := NewLeafSweeper(ca)
	mustRegister := func(c LeafConsumer) {
		t.Helper()
		if err := s.Register(c); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	mustRegister(LeafConsumer{
		Name: "a-spec-error", Dir: t.TempDir(),
		Spec: func() (LeafSpec, error) { return LeafSpec{}, errors.New("boom") },
	})
	mustRegister(LeafConsumer{
		Name: "b-reload-error", Dir: reloadFails,
		Spec: func() (LeafSpec, error) {
			return LeafSpec{CommonName: "reload.local", DNSNames: []string{"reload.local"}}, nil
		},
		Reload: func(context.Context, LeafPaths) error { return errors.New("restart failed") },
	})
	mustRegister(LeafConsumer{
		Name: "c-good", Dir: good,
		Spec: func() (LeafSpec, error) {
			return LeafSpec{CommonName: "good.local", DNSNames: []string{"good.local"}}, nil
		},
	})

	rep := s.Sweep(context.Background(), nil)
	if rep.Checked != 3 {
		t.Errorf("checked = %d, want 3", rep.Checked)
	}
	if !slices.Contains(rep.Renewed, "c-good") {
		t.Errorf("renewed = %v, want the good consumer renewed despite the earlier failures", rep.Renewed)
	}
	if !slices.Equal(rep.Failed, []string{"a-spec-error", "b-reload-error"}) {
		t.Errorf("failed = %v, want both failures recorded", rep.Failed)
	}
	// A reload that failed still leaves the fresh leaf on disk — the next
	// sweep finds it usable and does not mint a third one.
	if !slices.Contains(rep.Renewed, "b-reload-error") {
		t.Errorf("renewed = %v, want the leaf minted even though its reload failed", rep.Renewed)
	}
}

// Sources are re-read on every sweep, so a consumer that stops being listed
// simply stops being renewed.
func TestLeafSweep_SourcesAreReReadEachSweep(t *testing.T) {
	ca := sweepTestCA(t)
	dir := t.TempDir()
	mintWithLifetime(t, ca, dir, "node-a", time.Hour)

	listed := true
	s := NewLeafSweeper(ca)
	s.RegisterSource(func(context.Context) ([]LeafConsumer, error) {
		if !listed {
			return nil, nil
		}
		return []LeafConsumer{{
			Name: "collector/node-a", Dir: dir,
			Spec: func() (LeafSpec, error) { return LeafSpec{CommonName: "node-a", DNSNames: []string{"node-a"}}, nil },
		}}, nil
	})
	if rep := s.Sweep(context.Background(), nil); !slices.Equal(rep.Renewed, []string{"collector/node-a"}) {
		t.Fatalf("renewed = %v, want the listed consumer", rep.Renewed)
	}
	// Put it back inside the window and stop listing it.
	mintWithLifetime(t, ca, dir, "node-a", time.Hour)
	listed = false
	rep := s.Sweep(context.Background(), nil)
	if rep.Checked != 0 || len(rep.Renewed) != 0 {
		t.Errorf("checked=%d renewed=%v, want an unlisted consumer to be left alone", rep.Checked, rep.Renewed)
	}
}

// A source that cannot answer is logged and skipped, not fatal: the leaves it
// would have named keep the certificates they have, which is where a missed
// tick leaves them anyway.
func TestLeafSweep_SourceErrorIsNotFatal(t *testing.T) {
	ca := sweepTestCA(t)
	dir := t.TempDir()
	mintWithLifetime(t, ca, dir, "fixed.local", time.Hour)
	s := NewLeafSweeper(ca)
	s.RegisterSource(func(context.Context) ([]LeafConsumer, error) { return nil, errors.New("db down") })
	if err := s.Register(LeafConsumer{
		Name: "fixed", Dir: dir,
		Spec: func() (LeafSpec, error) {
			return LeafSpec{CommonName: "fixed.local", DNSNames: []string{"fixed.local"}}, nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	var warned int
	rep := s.Sweep(context.Background(), func(level, _ string) {
		if level == "warn" {
			warned++
		}
	})
	if !slices.Equal(rep.Renewed, []string{"fixed"}) {
		t.Errorf("renewed = %v, want the registered consumer still swept", rep.Renewed)
	}
	if warned == 0 {
		t.Error("a source error must be logged")
	}
}

func TestLeafSweep_RegisterRejectsDuplicatesAndIncompleteConsumers(t *testing.T) {
	s := NewLeafSweeper(sweepTestCA(t))
	ok := LeafConsumer{Name: "api", Dir: t.TempDir(), Spec: func() (LeafSpec, error) { return LeafSpec{}, nil }}
	if err := s.Register(ok); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.Register(ok); err == nil {
		t.Error("a duplicate name must be refused — two registrations of one leaf is the sprawl this replaces")
	}
	for _, bad := range []LeafConsumer{
		{Dir: "d", Spec: func() (LeafSpec, error) { return LeafSpec{}, nil }},
		{Name: "n", Spec: func() (LeafSpec, error) { return LeafSpec{}, nil }},
		{Name: "n", Dir: "d"},
	} {
		if err := s.Register(bad); err == nil {
			t.Errorf("Register(%+v) = nil, want an error", bad)
		}
	}
}

// No CA (a dev run with no mesh) means no leaves, and the sweep says so
// rather than erroring.
func TestLeafSweep_NoCAIsANoOp(t *testing.T) {
	s := NewLeafSweeper(nil)
	if err := s.Register(LeafConsumer{
		Name: "api", Dir: t.TempDir(),
		Spec: func() (LeafSpec, error) { return LeafSpec{}, errors.New("must not be called") },
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if rep := s.Sweep(context.Background(), nil); rep.Checked != 0 || len(rep.Failed) != 0 {
		t.Errorf("report = %+v, want an empty sweep", rep)
	}
}

func TestLeafPathsIn(t *testing.T) {
	got := LeafPathsIn("/data/tls/api")
	if got.CertPath != filepath.Join("/data/tls/api", "leaf.pem") || got.KeyPath != filepath.Join("/data/tls/api", "leaf.key") {
		t.Errorf("LeafPathsIn = %+v", got)
	}
}

// Headscale reads its certificate at container start, so its reload hook
// restarts the container — and only when it is actually running.
func TestHeadscaleLeafConsumer_RestartsOnlyARunningContainer(t *testing.T) {
	ca := sweepTestCA(t)
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.MeshCA = ca
		c.ListenAddr = "127.0.0.1:18080"
	})
	c := s.LeafConsumer()
	if c.Name != headscaleLeafName || c.Spec == nil || c.Reload == nil {
		t.Fatalf("LeafConsumer = %+v, want a named consumer with a spec and a reload hook", c)
	}
	if want := filepath.Join(s.cfg.StateDir, "certs"); c.Dir != want {
		t.Errorf("Dir = %q, want %q", c.Dir, want)
	}

	// No container yet: nothing to restart, and that is not an error — the
	// next Start creates it and reads the leaf then.
	if err := c.Reload(context.Background(), LeafPathsIn(c.Dir)); err != nil {
		t.Fatalf("reload with no container: %v", err)
	}
	if slices.Contains(fd.cmdNames(), "restart") {
		t.Error("restarted a container that does not exist")
	}

	fd.containerExists, fd.containerState = true, "running"
	if err := c.Reload(context.Background(), LeafPathsIn(c.Dir)); err != nil {
		t.Fatalf("reload with a running container: %v", err)
	}
	if !slices.Contains(fd.cmdNames(), "restart") {
		t.Errorf("a running container was not restarted; calls = %v", fd.cmdNames())
	}
}

// The spec the sweep checks against is the one Start mints with, so a leaf
// Start is happy with is not re-minted on every sweep.
func TestHeadscaleLeafConsumer_SpecMatchesWhatStartMints(t *testing.T) {
	ca := sweepTestCA(t)
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.MeshCA = ca
		c.ListenAddr = "127.0.0.1:18080"
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sweeper := NewLeafSweeper(ca)
	if err := sweeper.Register(s.LeafConsumer()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	rep := sweeper.Sweep(context.Background(), nil)
	if rep.Checked != 1 || len(rep.Renewed) != 0 {
		t.Errorf("report = %+v, want the freshly-minted leaf left alone", rep)
	}
}

// The workflow is the one driver: it sweeps the leaves the controlplane holds
// AND runs the delegated lifecycles, recording both in one result.
func TestLeafSweepWorkflow(t *testing.T) {
	ca := sweepTestCA(t)
	dir := t.TempDir()
	mintWithLifetime(t, ca, dir, "api.local", time.Hour)
	s := NewLeafSweeper(ca)
	if err := s.Register(LeafConsumer{
		Name: "api-https", Dir: dir,
		Spec: func() (LeafSpec, error) {
			return LeafSpec{CommonName: "api.local", DNSNames: []string{"api.local"}}, nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	var ran, failedRan int
	wf := LeafSweepWorkflow(LeafSweepDeps{
		Sweeper: s,
		FanOut: []LeafFanOut{
			{Name: "apps.leaf_rotate", Run: func(*jobs.StepCtx) error { ran++; return nil }},
			{Name: "broken", Run: func(*jobs.StepCtx) error { failedRan++; return errors.New("submit failed") }},
		},
	})
	if wf.Kind != LeafSweepKind || len(wf.Steps) != 1 {
		t.Fatalf("workflow = %+v", wf)
	}
	sc := &jobs.StepCtx{Ctx: context.Background(), Log: func(string, string) {}}
	raw, err := wf.Steps[0].Do(sc)
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	var rep LeafSweepReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("result: %v", err)
	}
	if !slices.Equal(rep.Renewed, []string{"api-https"}) {
		t.Errorf("renewed = %v", rep.Renewed)
	}
	if ran != 1 || failedRan != 1 {
		t.Errorf("fan-outs ran %d/%d, want both", ran, failedRan)
	}
	if !slices.Equal(rep.Failed, []string{"broken"}) {
		t.Errorf("failed = %v, want the fan-out that errored recorded", rep.Failed)
	}
}

// Gate 6 (geekdojo/geekdojo-brain#493): the sweep mints private keys, so its
// ledger is a place one could land. Run the real workflow on the real Runner
// and jobs store, with a reload that fails so the warning path is exercised
// too, and scan all four surfaces.
func TestLeafSweep_KeyMaterialNeverReachesTheLedger(t *testing.T) {
	capturedLog := ledgertest.CaptureLog(t)
	ctx := context.Background()
	ca := sweepTestCA(t)
	renewed := t.TempDir()
	reloadFails := t.TempDir()
	mintWithLifetime(t, ca, renewed, "api.local", time.Hour)
	mintWithLifetime(t, ca, reloadFails, "hs.local", time.Hour)

	s := NewLeafSweeper(ca)
	for _, c := range []struct {
		name, dir, cn string
		reload        func(context.Context, LeafPaths) error
	}{
		{name: "api-https", dir: renewed, cn: "api.local"},
		{
			name: "headscale", dir: reloadFails, cn: "hs.local",
			reload: func(context.Context, LeafPaths) error { return errors.New("docker restart: exit status 1") },
		},
	} {
		if err := s.Register(LeafConsumer{
			Name: c.name, Dir: c.dir,
			Spec:   func() (LeafSpec, error) { return LeafSpec{CommonName: c.cn, DNSNames: []string{c.cn}}, nil },
			Reload: c.reload,
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	store, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runner := jobs.NewRunner(store, nil)
	runner.Register(LeafSweepWorkflow(LeafSweepDeps{Sweeper: s}))
	job, err := runner.Submit(ctx, LeafSweepKind, nil, "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	runner.Wait()

	// The secrets: the private keys the sweep just minted. Read from where
	// they belong, so the scan below cannot pass by looking for nothing.
	var secrets []ledgertest.Secret
	var onDisk string
	for _, d := range []struct{ name, dir string }{{"the api leaf key", renewed}, {"the Headscale leaf key", reloadFails}} {
		raw, err := os.ReadFile(LeafPathsIn(d.dir).KeyPath)
		if err != nil {
			t.Fatalf("read %s: %v", d.name, err)
		}
		secrets = append(secrets, ledgertest.Secret{Name: d.name, Value: strings.TrimSpace(string(raw))})
		onDisk += string(raw)
	}

	got, err := store.GetJob(ctx, job.ID)
	if err != nil || got == nil {
		t.Fatalf("GetJob: %v", err)
	}
	steps, err := store.ListSteps(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	events, err := store.ListEvents(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	stepJSON, _ := json.Marshal(steps)
	eventJSON, _ := json.Marshal(events)
	jobJSON, _ := json.Marshal(got)

	// The reload failure must be in the ledger — otherwise the scan below is
	// checking a job that never did anything.
	if !strings.Contains(string(stepJSON), "headscale") {
		t.Fatalf("the sweep's step result does not mention the consumer it failed to reload")
	}
	surfaces := ledgertest.Surfaces{
		Spec:   string(jobJSON),
		Steps:  string(stepJSON),
		Events: string(eventJSON),
		Log:    capturedLog.String(),
	}
	surfaces.AssertPresent(t, "the leaf key files on disk", onDisk, secrets)
	surfaces.AssertAbsent(t, secrets)
}
