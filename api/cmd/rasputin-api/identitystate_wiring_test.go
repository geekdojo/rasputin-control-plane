package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// identityCounts counts every call the identity state's collaborators get.
type identityCounts struct {
	mu                                             sync.Mutex
	run, fsOpen, health, ledger, settings, outcome int
	runCalls                                       []string
}

func (c *identityCounts) inc(p *int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*p++
}

func (c *identityCounts) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.run + c.fsOpen + c.health + c.ledger + c.settings + c.outcome
}

type countedFS struct {
	c     *identityCounts
	inner fs.FS
}

func (f countedFS) Open(name string) (fs.File, error) {
	f.c.inc(&f.c.fsOpen)
	return f.inner.Open(name)
}

type countedHealth struct {
	c   *identityCounts
	err error
}

func (h countedHealth) Health(context.Context) (idclient.HealthReport, error) {
	h.c.inc(&h.c.health)
	return idclient.HealthReport{}, h.err
}

type countedLedger struct {
	c     *identityCounts
	inner *jobs.Store
}

func (l countedLedger) RecordFinishedJob(ctx context.Context, j *jobs.Job) (bool, error) {
	l.c.inc(&l.c.ledger)
	return l.inner.RecordFinishedJob(ctx, j)
}

func (l countedLedger) ListJobsByKind(ctx context.Context, kind string, limit int) ([]*jobs.Job, error) {
	l.c.inc(&l.c.ledger)
	return l.inner.ListJobsByKind(ctx, kind, limit)
}

type countedSettings struct{ c *identityCounts }

func (s countedSettings) Get(context.Context, string) (string, error) {
	s.c.inc(&s.c.settings)
	return "", nil
}

func (s countedSettings) Set(context.Context, string, string) error {
	s.c.inc(&s.c.settings)
	return nil
}

type countedOutcomes struct{ c *identityCounts }

func (o countedOutcomes) ReadKind(context.Context, string) error {
	o.c.inc(&o.c.outcome)
	return nil
}

// identityDeps are the wiring's deps over counting fakes: systemctl fails,
// the file system holds no exits directory, and every health call is
// ErrUnreachable.
func identityDeps(t *testing.T, mode string, c *identityCounts) identityStateDeps {
	t.Helper()
	log, _ := logkittest.New()
	return identityStateDeps{
		mode:     mode,
		client:   countedHealth{c: c, err: &idclient.Error{Op: "health", Kind: idclient.ErrUnreachable}},
		ledger:   countedLedger{c: c, inner: openLedgerAt(t, filepath.Join(t.TempDir(), "jobs.db"))},
		settings: countedSettings{c: c}, outcomes: countedOutcomes{c: c},
		jobRunning: func(context.Context, string) (bool, error) { return false, nil },
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			c.mu.Lock()
			c.run++
			c.runCalls = append(c.runCalls, name+" "+strings.Join(args, " "))
			c.mu.Unlock()
			return nil, errors.New("systemctl: not found")
		},
		fsys:     countedFS{c: c, inner: fstest.MapFS{}},
		remove:   func(string) error { return errors.New("nothing to remove") },
		free:     func(string) (uint64, error) { return 1 << 40, nil },
		dataDir:  t.TempDir(),
		restores: noRestores{},
		features: func(context.Context, string) (bool, error) { return false, nil },
		now:      time.Now,
		log:      log,
	}
}

// fakeRegistry records the workflows registered.
type fakeRegistry struct{ wfs []jobs.Workflow }

func (r *fakeRegistry) Register(w jobs.Workflow) { r.wfs = append(r.wfs, w) }

// alertsHook records SetIdentityAlerts.
type alertsHook struct {
	fn func(context.Context, time.Time) []proto.Alert
}

func (h *alertsHook) SetIdentityAlerts(fn func(context.Context, time.Time) []proto.Alert) { h.fn = fn }

// TC-979-23: the composition root's identity state. Under keycloak, building
// makes no call at all; identity.recover is registered System, with a
// scheduler entry and an Arm; and the alerts list, read with systemctl
// failing, no exits directory and the service unreachable, returns one
// identity: alert and no error. Under off and mock there is no monitor, no
// SetIdentityAlerts and no entry.
func TestIdentityStateWiring(t *testing.T) {
	c := &identityCounts{}
	w, err := identityStateWiring(identityDeps(t, identityModeKeycloak, c))
	if err != nil {
		t.Fatal(err)
	}
	if n := c.total(); n != 0 {
		t.Fatalf("building made %d calls, want 0", n)
	}
	reg := &fakeRegistry{}
	w.register(reg)
	if len(reg.wfs) != 1 || reg.wfs[0].Kind != "identity.recover" || !reg.wfs[0].System {
		t.Fatalf("registered %+v, want identity.recover as a System job", reg.wfs)
	}
	if e := w.entries(); len(e) != 1 || e[0].Kind != "identity.recover" || e[0].Interval != storeAuditCheckEvery || e[0].Due == nil {
		t.Fatalf("entries = %+v", e)
	}
	if w.arm == nil || w.monitor == nil {
		t.Fatal("no Arm or monitor under keycloak")
	}

	svc := newOutcomeEnv(t).alertsService(t, mustReader(t))
	w.wireAlerts(svc, nil)
	all, err := svc.List(t.Context())
	if err != nil {
		t.Fatalf("List with the identity service down: %v", err)
	}
	var ids []string
	for _, a := range all {
		if strings.HasPrefix(a.ID, "identity:") {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) != 1 {
		t.Fatalf("identity alerts = %v, want one", ids)
	}
	if c.run == 0 || c.health != 1 {
		t.Fatalf("the reading made %d systemctl and %d health calls", c.run, c.health)
	}
	if want := "systemctl show --property=ActiveState,SubState,InvocationID keycloak.service keycloak-db.service"; c.runCalls[0] != want {
		t.Fatalf("first command = %q, want %q", c.runCalls[0], want)
	}

	for _, mode := range []string{identityModeOff, identityModeMock} {
		c := &identityCounts{}
		w, err := identityStateWiring(identityDeps(t, mode, c))
		if err != nil {
			t.Fatal(err)
		}
		reg := &fakeRegistry{}
		w.register(reg)
		hook := &alertsHook{}
		w.wireAlerts(hook, nil)
		w.start(t.Context())
		if w.monitor != nil || len(reg.wfs) != 0 || w.entries() != nil || hook.fn != nil || c.total() != 0 {
			t.Fatalf("%s: monitor %v, %d workflows, entries %v, alerts wired %t, %d calls; want none",
				mode, w.monitor, len(reg.wfs), w.entries(), hook.fn != nil, c.total())
		}
	}

	d := identityDeps(t, identityModeKeycloak, &identityCounts{})
	d.client = nil
	if _, err := identityStateWiring(d); err == nil {
		t.Fatal("a nil collaborator under keycloak was accepted")
	}
}

// mustReader is an outcome reader over an empty run directory.
func mustReader(t *testing.T) *osoutcome.Reader {
	t.Helper()
	e := newOutcomeEnv(t)
	return e.reader(t, func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
}

// TC-979-15 (the declarations): os.identity_db_init takes created and
// untouched as OK and alerts on refused; os.identity_rollback takes current as
// OK and alerts on restored, refused and failed; an unknown word records
// unreadable and alerts. Both are read by ReadKind.
func TestOutcomeSources_Identity(t *testing.T) {
	e := newOutcomeEnv(t)
	for _, d := range []string{"rasputin-identity-db-init", "rasputin-identity-rollback"} {
		if err := os.MkdirAll(filepath.Join(e.runDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r := e.reader(t, func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	svc := e.alertsService(t, r)
	for i, c := range []struct {
		kind, dir, word string
		alert           bool
	}{
		{"os.identity_db_init", "rasputin-identity-db-init", "created", false},
		{"os.identity_db_init", "rasputin-identity-db-init", "untouched", false},
		{"os.identity_db_init", "rasputin-identity-db-init", "refused", true},
		{"os.identity_rollback", "rasputin-identity-rollback", "current", false},
		{"os.identity_rollback", "rasputin-identity-rollback", "restored", true},
		{"os.identity_rollback", "rasputin-identity-rollback", "refused", true},
		{"os.identity_rollback", "rasputin-identity-rollback", "failed", true},
		{"os.identity_rollback", "rasputin-identity-rollback", "maybe", true},
	} {
		// A new boot per case, so each record is a new job.
		boot := fmt.Sprintf("0f3c5b2a-1d4e-4f6a-9b8c-%012x", i)
		e.write(t, c.dir, "outcome="+c.word+"\nboot_id="+boot+"\nreason=The gate said "+c.word+".\n")
		if err := r.ReadKind(t.Context(), c.kind); err != nil {
			t.Fatal(err)
		}
		all, err := svc.List(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		alerted := false
		for _, a := range all {
			alerted = alerted || a.ID == osoutcome.AlertIDPrefix+c.kind
		}
		if alerted != c.alert {
			t.Errorf("%s %s: alert %t, want %t", c.kind, c.word, alerted, c.alert)
		}
	}
}
