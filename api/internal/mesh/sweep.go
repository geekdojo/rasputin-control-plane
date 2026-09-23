package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// One renewal driver for every Mesh-CA leaf the controlplane holds.
//
// Renewal is decided by a fact — the leaf's NotAfter is within renewWindow, or
// the spec it was minted for no longer describes the service — and the sweep
// that re-checks that fact is a safety net, not a schedule
// (design/principles.md). Nothing here decides anything from elapsed time; the
// tick only says how long a lapse can go unnoticed.
//
// Before this there were four drivers on four cadences, and the two leaves the
// controlplane serves itself were the two that were not actually covered:
//
//   - the api's own HTTPS leaf was minted at start and re-minted only when the
//     primary LAN address changed, so on a controlplane that neither restarted
//     nor moved, nothing renewed it;
//   - Headscale's leaf was ensured inside DockerSupervisor.Start, which is a
//     no-op while the container is running — and Headscale reads its
//     certificate at container start, so even a re-mint would not have reached
//     a client;
//   - per-app leaves had their own scheduler entry (apps.leaf_rotate);
//   - per-node collector leaves renewed as a side effect of the collector
//     reconcile's redeploy window.
//
// Now one entry fires LeafSweepKind. It renews every leaf the controlplane
// keeps on its own disk and calls that consumer's reload hook — because a
// renewed file is not a renewed service: each consumer picks its certificate
// up differently, and a mint nobody reloads is the same outage as no mint.
// The fan-outs that own a delivery contract of their own (the per-app leaves,
// which must reach a node before the on-disk copy advances) keep that contract
// and are driven from this one sweep.

// LeafSweepKind is the job kind of the sweep.
const LeafSweepKind = "mesh.leaf_sweep"

// DefaultLeafSweepInterval is the safety-net cadence. Leaves live a year and
// renew with renewWindow (60 days) left, so a daily re-check is ample and
// cheap: in a steady state it reads each leaf's NotAfter and does nothing.
const DefaultLeafSweepInterval = 24 * time.Hour

// LeafConsumer is one holder of a Mesh-CA leaf the controlplane keeps in a
// directory of its own. Registered once; swept forever.
type LeafConsumer struct {
	// Name identifies the consumer in logs and in the job result. Unique.
	Name string
	// Dir is the directory MintLeafToDisk keeps the leaf in.
	Dir string
	// Spec is re-derived on every sweep rather than captured once, so a
	// service whose names moved (a new hostname, a new LAN address) is
	// re-minted by the same check that catches near-expiry.
	Spec func() (LeafSpec, error)
	// Reload makes the consumer serve the leaf that is now on disk. Called
	// ONLY after a fresh leaf was minted — never on a sweep that found the
	// existing one still good, so a consumer that reloads by restarting
	// (Headscale) restarts on real drift and not on a tick. Optional: a
	// consumer that reads its leaf per use needs none.
	Reload func(ctx context.Context, paths LeafPaths) error
}

// LeafSource yields consumers whose set changes while the api runs — the
// per-node collector leaves. Re-read on every sweep, so a node that has left
// inventory simply stops being renewed (§5.2 revocation: the node's leaves are
// no longer renewed). Deleting what it leaves behind is a separate matter and
// is not done here.
type LeafSource func(ctx context.Context) ([]LeafConsumer, error)

// LeafSweeper renews the Mesh-CA leaves the controlplane holds.
type LeafSweeper struct {
	ca *MeshCA

	mu      sync.Mutex
	fixed   []LeafConsumer
	sources []LeafSource
}

// NewLeafSweeper returns a sweeper for ca. A nil CA is allowed and makes every
// sweep a no-op — dev runs with no mesh CA have no leaves to renew.
func NewLeafSweeper(ca *MeshCA) *LeafSweeper { return &LeafSweeper{ca: ca} }

// Register adds a consumer whose leaf exists for the api's whole life.
func (s *LeafSweeper) Register(c LeafConsumer) error {
	if c.Name == "" || c.Dir == "" || c.Spec == nil {
		return errors.New("mesh: LeafConsumer needs a Name, a Dir and a Spec")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.fixed {
		if existing.Name == c.Name {
			return fmt.Errorf("mesh: leaf consumer %q is already registered", c.Name)
		}
	}
	s.fixed = append(s.fixed, c)
	return nil
}

// RegisteredNames returns the names of the fixed consumers registered so far,
// sorted. It exists so startup can CHECK its own wiring: every Register call
// sits inline in main(), where deleting one is invisible — the build passes,
// the tests pass, and that leaf simply stops being renewed until it expires.
// A name the caller expected and does not find here is that mistake, caught at
// boot instead of at NotAfter.
//
// Sources are deliberately not included: their membership follows inventory
// and is empty on a cluster with no collectors, so absence proves nothing.
func (s *LeafSweeper) RegisteredNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.fixed))
	for _, c := range s.fixed {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}

// RegisterSource adds a source of consumers re-read on every sweep.
func (s *LeafSweeper) RegisterSource(fn LeafSource) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, fn)
}

// LeafSweepReport is what one sweep did. It is the job's recorded result, so
// in a steady state it reads checked=N renewed=0 — the sweep working, not the
// sweep being idle.
type LeafSweepReport struct {
	Checked  int      `json:"checked"`
	Renewed  []string `json:"renewed,omitempty"`
	Reloaded []string `json:"reloaded,omitempty"`
	Failed   []string `json:"failed,omitempty"`
}

// Sweep re-checks every registered leaf and renews the ones whose fact has
// changed. It never fails as a whole: one consumer's error is recorded against
// that consumer and the rest are still swept, because a sweep that stops at
// the first problem leaves every later leaf unrenewed.
//
// logf receives one line per renewal and one per failure; it may be nil.
func (s *LeafSweeper) Sweep(ctx context.Context, logf func(level, msg string)) LeafSweepReport {
	if logf == nil {
		logf = func(string, string) {}
	}
	var report LeafSweepReport
	if s.ca == nil {
		return report
	}
	for _, c := range s.consumers(ctx, logf) {
		if err := ctx.Err(); err != nil {
			return report
		}
		report.Checked++
		spec, err := c.Spec()
		if err != nil {
			report.Failed = append(report.Failed, c.Name)
			logf("warn", fmt.Sprintf("leaf sweep: %s: spec: %v", c.Name, err))
			continue
		}
		paths := LeafPathsIn(c.Dir)
		// THE fact. loadLeafIfUsable returns nil when the leaf is missing,
		// unparseable, signed by another CA, minted for a different purpose,
		// no longer covers the spec's names, or has less than renewWindow
		// left. Anything else is a leaf that does not need touching.
		if loadLeafIfUsable(paths, s.ca, spec) != nil {
			continue
		}
		if _, err := MintLeafToDisk(s.ca, c.Dir, spec); err != nil {
			report.Failed = append(report.Failed, c.Name)
			logf("warn", fmt.Sprintf("leaf sweep: %s: mint: %v", c.Name, err))
			continue
		}
		report.Renewed = append(report.Renewed, c.Name)
		logf("info", fmt.Sprintf("leaf sweep: %s: minted a fresh leaf", c.Name))
		if c.Reload == nil {
			continue
		}
		if err := c.Reload(ctx, paths); err != nil {
			report.Failed = append(report.Failed, c.Name)
			logf("warn", fmt.Sprintf("leaf sweep: %s: reload: %v (the fresh leaf is on disk and reloads on the next sweep or restart)", c.Name, err))
			continue
		}
		report.Reloaded = append(report.Reloaded, c.Name)
	}
	return report
}

// consumers is the registered set plus whatever the sources yield this sweep,
// in a stable order. A source that errors is logged and skipped: the leaves it
// would have named keep their current certificates, which is the same position
// a missed tick leaves them in.
func (s *LeafSweeper) consumers(ctx context.Context, logf func(level, msg string)) []LeafConsumer {
	s.mu.Lock()
	fixed := append([]LeafConsumer(nil), s.fixed...)
	sources := append([]LeafSource(nil), s.sources...)
	s.mu.Unlock()

	var dynamic []LeafConsumer
	for _, fn := range sources {
		got, err := fn(ctx)
		if err != nil {
			logf("warn", fmt.Sprintf("leaf sweep: listing leaves: %v", err))
			continue
		}
		dynamic = append(dynamic, got...)
	}
	sort.Slice(dynamic, func(i, j int) bool { return dynamic[i].Name < dynamic[j].Name })
	return append(fixed, dynamic...)
}

// LeafPathsIn names the leaf files inside dir. One place, so a sweep asking
// "does this need renewing?" and MintLeafToDisk writing the answer can never
// look at different files.
func LeafPathsIn(dir string) LeafPaths {
	return LeafPaths{
		CertPath: filepath.Join(dir, "leaf.pem"),
		KeyPath:  filepath.Join(dir, "leaf.key"),
	}
}

// LeafSweepDeps is what the workflow needs.
type LeafSweepDeps struct {
	// Sweeper renews the leaves the controlplane holds directly.
	Sweeper *LeafSweeper
	// FanOut are the leaf lifecycles that own a delivery contract of their
	// own — the per-app leaves, which must be accepted by a node before the
	// on-disk copy advances past what that node holds. They keep that
	// contract; this sweep is what drives them, so there is one driver.
	// Each runs after the direct sweep and reports its own outcome.
	FanOut []LeafFanOut
}

// LeafFanOut is one delegated leaf lifecycle.
type LeafFanOut struct {
	Name string
	Run  func(sc *jobs.StepCtx) error
}

// LeafSweepWorkflow is the one renewal driver (§7.1). Its single step is the
// sweep; per-consumer problems are recorded, not fatal, so one broken consumer
// cannot stop the others from renewing.
func LeafSweepWorkflow(deps LeafSweepDeps) jobs.Workflow {
	return jobs.Workflow{
		Kind: LeafSweepKind,
		Steps: []jobs.WorkflowStep{
			{Name: "sweep", Timeout: 5 * time.Minute, Do: leafSweepStep(deps)},
		},
	}
}

func leafSweepStep(deps LeafSweepDeps) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		report := LeafSweepReport{}
		if deps.Sweeper != nil {
			report = deps.Sweeper.Sweep(sc.Ctx, sc.Log)
		}
		for _, f := range deps.FanOut {
			if f.Run == nil {
				continue
			}
			if err := f.Run(sc); err != nil {
				report.Failed = append(report.Failed, f.Name)
				sc.Log("warn", fmt.Sprintf("leaf sweep: %s: %v", f.Name, err))
			}
		}
		sc.Log("info", fmt.Sprintf("leaf sweep: checked=%d renewed=%d reloaded=%d failed=%d",
			report.Checked, len(report.Renewed), len(report.Reloaded), len(report.Failed)))
		return json.Marshal(report)
	}
}
