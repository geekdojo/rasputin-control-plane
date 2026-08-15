package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// A SIMULATED FLEET — the CI regression net for the fan-out orchestration
// layer (geekdojo/geekdojo-brain#99).
//
// ⚠️ READ THIS FIRST: THIS IS NOT THE TEST ADR-0005 DECISION 10 REQUIRES.
// That one is a written plan run against a dedicated bench cluster — real
// nodes, real RAUC, real bootloaders (#80). This is the cheap net underneath
// it, and the distinction is not pedantry:
//
//	"I never trust a test harness that isn't orchestrating the actual stack
//	 from top to bottom. We've seen that in Rasputin with almost every mock
//	 we've made. They will miss something critical that only shows up in real
//	 world testing."   — Bryce, 2026-08-15
//
// He has the receipts. The die-after-reboot injector armed a marker where
// startup did not look, silently never fired, and returned a clean `committed`
// in 63 seconds. `bootedSlotFromCmdline` matched PARTLABEL= and rasputin.slot=
// while the Pi emits rauc.slot=, which would have no-opped the whole #88 fix on
// arm64 — caught only because one fixture came off real hardware. c08 sat
// "reasoned about, not run" for a month and then produced the campaign's most
// consequential finding.
//
// So: what follows catches REGRESSIONS in orchestration. Every scenario here
// exists because hardware found the bug first. It is a ratchet, not a discovery
// tool, and it does not earn the confidence a bench run earns.
//
// WHAT THIS IS. A fleet of nodes that speak the real agent side of the update
// protocol over a real NATS bus, driven by the real `system.update` and
// `node.update` sagas on a real jobs.Runner against real SQLite stores. Nothing
// about the orchestration is stubbed: the canary gate, the bounded fan-out, the
// failure budget, the verify contract, the per-node grid and every wire event
// are the shipping code paths. Only the thing on the other end of the bus is
// simulated.
//
// WHY IT HAS TO EXIST, and why the unit suite is not it. canary_test.go
// exercises the ordering logic through an injected childDriver — no runner, no
// child jobs, no bus, no clock. That is the right shape for the decisions the
// cascade makes, and it is blind to everything BETWEEN those decisions: the
// child saga's seven steps, the boot-identity handshake, RPC timeouts, the
// registration wake-up, the store writes. All three bugs ADR-0005 is built on
// (#58/#57/#53) lived exactly there, and all three were invisible to the unit
// suite and found by a 24-node run. So did the two found while splitting #69.
//
// WHERE IT SITS RELATIVE TO HARDWARE. `bitscope` is 24 nodes that will run real
// apps, so Decision 10 rations it to one or two release-gate runs. The #80
// bench cluster is the venue you can break freely and the one that discharges
// the decision. This runs on every PR in seconds, with nothing powered on, and
// its job is to make sure a known failure cannot come back between bench runs.
// TestFleetSweep additionally makes the knobs cheap to explore — but a sweep
// against simulated nodes measures containment, never throughput (see #97/#81).
//
// ⚠️ WHAT IT DOES NOT PROVE, stated up front so no one reads a green run as
// more than it is:
//
//   - Nothing about RAUC, GRUB, the Pi bootloader, `/proc/cmdline` parsing or
//     any other agent-side backend behaviour. A simulated node reports what it
//     is told to report — one coherent, honest notion of its slot and version.
//     It cannot lie in the ways real hardware has: #88 (ActiveSlot following
//     the bootloader's intent rather than the booted slot), #92 / #86 (an agent
//     echoing a sha256 as its version), #82 (no CurrentVersion at all). Every
//     one of those is invisible from here, and every one of them shipped.
//   - Nothing about wall-clock realism. Installs and reboots are milliseconds
//     and the saga's step timeouts are compressed (see cappedTimeouts) so a
//     deadline-dependent path can be exercised in seconds. What is asserted is
//     BEHAVIOUR at a deadline, never the deadline's value.
//   - Nothing about the HTTP surface. The cascade is submitted through the
//     runner, not through POST /api/updates/system. That is deliberate — a
//     harness driven through the UI hangs on the native confirm() the UPDATE
//     ALL button raises — but it means auth, handler validation and the UI are
//     out of scope here.

// ----- node behaviour -----------------------------------------------------

// simBehaviour is what a simulated node does when it is updated. Each value is
// a shape observed on hardware or reasoned about in ADR-0005, named after the
// bench node that produced it where one did.
type simBehaviour string

const (
	// simHealthy takes the update and comes back on the new slot and version.
	simHealthy simBehaviour = "healthy"
	// simFailDownload rejects the download RPC — the saga fails at step 3 with
	// no slot mutation.
	simFailDownload simBehaviour = "fail-download"
	// simFailInstall rejects the install RPC — step 4, still before any reboot.
	simFailInstall simBehaviour = "fail-install"
	// simNoReboot acks the reboot and does not reboot, answering prechecks on
	// the SAME boot id throughout. Bench node c13: the false-rollback class the
	// whole verify contract exists to kill. Expected: the job FAILS at step 6
	// naming the boot, and NO rolled_back row is written.
	simNoReboot simBehaviour = "no-reboot"
	// simNeverReturns goes quiet at the reboot and never answers again. Bench
	// node c08. Expected: failed with "stopped answering and never came back",
	// again not a rollback, and inventory's version left UNCONFIRMED (#90).
	simNeverReturns simBehaviour = "never-returns"
	// simFailHealth reboots cleanly onto the new slot and then answers
	// diag.health red. Expected: mark-bad, a rolled_back row, inventory
	// unconfirmed — the node is on the new slot but about to revert, so both
	// available versions are wrong.
	simFailHealth simBehaviour = "fail-health"
	// simBootloaderRollback comes back on a NEW boot but on the OLD slot: the
	// watchdog reverted it. Conjunct (b) fails. This is the one shape that IS a
	// genuine rolled_back.
	simBootloaderRollback simBehaviour = "bootloader-rollback"
	// simNoBootID is a pre-bootId agent: it updates correctly but never reports
	// a boot identity, so verify has to degrade (Decision 3). It must still
	// commit, and it must be marked unverified_boot rather than passing
	// silently — a mixed-version fleet is the NORMAL case for this feature.
	simNoBootID simBehaviour = "no-boot-id"
)

// simNodeSpec describes one node of a simulated fleet.
type simNodeSpec struct {
	ID   string
	Role proto.NodeRole
	// Arch is "amd64" | "arm64", or "" to model an agent that never reported
	// one (which the plan must treat as stranded, never as amd64 — #67).
	Arch      string
	Behaviour simBehaviour
	// Version is what the node is running before the update.
	Version string
	// InstallFor / RebootFor let one node be slower than its neighbours, which
	// is what makes a bounded fan-out's overlap observable at all. Zero takes
	// the fleet default.
	InstallFor time.Duration
	RebootFor  time.Duration
	// RebootDelay is how long the node keeps answering ON THE OLD BOOT after
	// acking the reboot — the real UpdateRebootCmd carries a delay, so every
	// healthy update has this window.
	//
	// Zero means the node goes quiet before it even answers the ack, which
	// makes the reboot handshake deterministic and is what the ordinary
	// scenarios want. A NON-zero value is how the #90 shape is reproduced: the
	// pre-reboot agent answers a poll or two on the old boot, and a run that
	// then vanishes must be reported as "stopped answering", not as "still
	// answering". That distinction was a latch bug, and a harness with no
	// window cannot catch it coming back.
	RebootDelay time.Duration
}

// simNode is a live simulated agent: a set of NATS responders over a slot
// model, an image version and a boot identity.
type simNode struct {
	spec simNodeSpec
	nc   *nats.Conn
	// versionOf resolves a bundle sha to the version its manifest declares —
	// the harness's stand-in for reading the manifest out of the bundle.
	versionOf func(sha string) string

	mu             sync.Mutex
	bootID         string
	active         proto.UpdateSlot
	inactive       proto.UpdateSlot
	version        string
	pendingSlot    proto.UpdateSlot
	pendingVersion string
	// subs is non-nil exactly while the node is answering. A rebooting node
	// unsubscribes rather than staying silent on a live subscription: the api
	// must see ErrNoResponders, which is what a real box that is down looks
	// like, and a silent subscriber would instead burn the RPC's full timeout.
	subs []*nats.Subscription
	// prechecks counts every precheck this node answered. A node the cascade
	// never touched has zero, which is how "untouched" is asserted rather than
	// inferred from a grid row the cascade wrote about it.
	prechecks int
	// installs is the same for installs, and is what the sim-side concurrency
	// observation is built from.
	installs int
	// inFlight / peakInFlight track how many installs are running on THIS node
	// at once (always ≤ 1) — the fleet aggregates them.
	fleetEnter func()
	fleetExit  func()
}

func (n *simNode) lock() func() {
	n.mu.Lock()
	return n.mu.Unlock
}

// respond publishes a reply, ignoring the error: a request whose requester has
// already given up is not the simulated agent's problem, exactly as on a real
// one.
func (n *simNode) respond(m *nats.Msg, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = m.Respond(b)
}

// listen attaches every responder. Called at fleet start and again each time a
// node comes back from a simulated reboot.
func (n *simNode) listen() error {
	handlers := map[string]nats.MsgHandler{
		proto.UpdatePrecheckSubject(n.spec.ID):         n.onPrecheck,
		proto.UpdateDownloadSubject(n.spec.ID):         n.onDownload,
		proto.UpdateInstallSubject(n.spec.ID):          n.onInstall,
		proto.UpdateRebootSubject(n.spec.ID):           n.onReboot,
		proto.UpdateMarkGoodSubject(n.spec.ID):         n.onMarkGood,
		proto.UpdateMarkBadSubject(n.spec.ID):          n.onMarkBad,
		proto.NodeCmdSubject(n.spec.ID, "diag.health"): n.onHealth,
		proto.NodeCmdSubject(n.spec.ID, "diag.ping"):   n.onPing,
	}
	subjects := make([]string, 0, len(handlers))
	for s := range handlers {
		subjects = append(subjects, s)
	}
	sort.Strings(subjects) // deterministic attach order; makes failures reproducible
	var subs []*nats.Subscription
	for _, s := range subjects {
		sub, err := n.nc.Subscribe(s, handlers[s])
		if err != nil {
			return err
		}
		subs = append(subs, sub)
	}
	// Flush so the server has acked every SUB before we claim to be up. Without
	// it a node can miss the first RPC of its own update.
	if err := n.nc.Flush(); err != nil {
		return err
	}
	defer n.lock()()
	n.subs = subs
	return nil
}

// silence detaches every responder — the simulated node is down. Requests to it
// now fail with ErrNoResponders immediately, as they do against a box that is
// rebooting.
func (n *simNode) silence() {
	n.mu.Lock()
	subs := n.subs
	n.subs = nil
	n.mu.Unlock()
	for _, s := range subs {
		_ = s.Unsubscribe()
	}
	_ = n.nc.Flush()
}

func (n *simNode) onPrecheck(m *nats.Msg) {
	defer n.lock()()
	n.prechecks++
	ack := proto.UpdatePrecheckAck{
		OK:             true,
		ActiveSlot:     n.active,
		InactiveSlot:   n.inactive,
		CurrentVersion: n.version,
		AvailableBytes: 16 << 30,
		Backend:        "sim",
		BootID:         n.bootID,
	}
	n.respond(m, ack)
}

func (n *simNode) onDownload(m *nats.Msg) {
	var cmd proto.UpdateDownloadCmd
	_ = json.Unmarshal(m.Data, &cmd)
	if n.spec.Behaviour == simFailDownload {
		n.respond(m, proto.UpdateDownloadAck{OK: false, Detail: "simulated download failure"})
		return
	}
	n.respond(m, proto.UpdateDownloadAck{
		OK:        true,
		LocalPath: "/var/lib/rasputin/bundles/" + cmd.BundleID,
		SizeBytes: cmd.SizeBytes,
		SHA256:    cmd.ExpectedSHA256,
	})
}

func (n *simNode) onInstall(m *nats.Msg) {
	var cmd proto.UpdateInstallCmd
	_ = json.Unmarshal(m.Data, &cmd)
	if n.spec.Behaviour == simFailInstall {
		n.respond(m, proto.UpdateInstallAck{OK: false, Detail: "simulated install failure"})
		return
	}
	if n.fleetEnter != nil {
		n.fleetEnter()
	}
	time.Sleep(n.spec.InstallFor)
	if n.fleetExit != nil {
		n.fleetExit()
	}

	newVersion := n.versionOf(cmd.BundleID)
	unlock := n.lock()
	n.installs++
	n.pendingSlot = cmd.TargetSlot
	n.pendingVersion = newVersion
	unlock()

	n.respond(m, proto.UpdateInstallAck{
		OK:         true,
		TargetSlot: cmd.TargetSlot, // a truthful echo; the api refuses a divergent one
		NewVersion: newVersion,
	})
}

func (n *simNode) onReboot(m *nats.Msg) {
	// Go quiet BEFORE acking unless the spec asks for a delay window. Replying
	// does not need a subscription, so the ack still lands; what it removes is
	// the race between "the api's first post-reboot poll" and "the node going
	// away", which would otherwise make two scenarios flaky in opposite
	// directions. RebootDelay > 0 puts the window back deliberately.
	if n.spec.Behaviour != simNoReboot && n.spec.RebootDelay == 0 {
		n.silence()
	}
	n.respond(m, proto.UpdateRebootAck{OK: true, DelaySeconds: 0})
	// The rebooting event is what step 5 blocks on. Published even by a node
	// that is lying about rebooting (c13) — that is the whole shape of c13: it
	// ACKS, it announces, and then it stays exactly where it was.
	_ = n.nc.Publish(proto.NodeEvtSubject(n.spec.ID, "rebooting"), []byte(`{"delaySeconds":0}`))
	if n.spec.Behaviour == simNoReboot {
		return
	}
	go n.reboot()
}

// reboot models the window a real node is unreachable for, then comes back with
// whatever identity its behaviour dictates.
func (n *simNode) reboot() {
	if n.spec.RebootDelay > 0 {
		// Still answering, still on the old boot: the reboot has been ordered
		// and has not happened yet.
		time.Sleep(n.spec.RebootDelay)
	}
	n.silence()
	time.Sleep(n.spec.RebootFor)
	if n.spec.Behaviour == simNeverReturns {
		return // c08: it is gone, and nothing later says otherwise
	}

	unlock := n.lock()
	switch n.spec.Behaviour {
	case simBootloaderRollback:
		// A NEW boot — it really did reboot — onto the OLD slot. Conjunct (a)
		// passes and (b) fails, which is the only combination that means the
		// bootloader reverted rather than the node never having gone.
		n.bootID = newBootID()
	case simNoBootID:
		// A pre-bootId agent has no identity to report, before or after.
		n.bootID = ""
		n.commitPending()
	default:
		n.bootID = newBootID()
		n.commitPending()
	}
	unlock()

	if err := n.listen(); err != nil {
		return
	}
	// Registration is how a real agent announces it is back, and step 6 uses it
	// as a latency hint — it shortcuts the poll interval rather than proving
	// anything. Publishing it keeps the harness honest about pacing: without it
	// every node would pay the full 2s poll tick.
	evt, _ := json.Marshal(proto.NodeRegisteredEvt{
		NodeID:       n.spec.ID,
		Role:         n.spec.Role,
		Hostname:     n.spec.ID,
		Architecture: n.spec.Arch,
		ImageVersion: n.currentVersion(),
		BootID:       n.bootIDNow(),
	})
	_ = n.nc.Publish(proto.NodeRegisteredSubject(n.spec.ID), evt)
}

// commitPending swaps the slots. Caller holds the lock.
func (n *simNode) commitPending() {
	if n.pendingSlot == "" || n.pendingSlot == proto.SlotUnknown {
		return
	}
	old := n.active
	n.active, n.inactive = n.pendingSlot, old
	n.version = n.pendingVersion
	n.pendingSlot, n.pendingVersion = "", ""
}

func (n *simNode) onHealth(m *nats.Msg) {
	healthy := n.spec.Behaviour != simFailHealth
	detail := "healthy"
	if !healthy {
		detail = "simulated health-battery failure"
	}
	n.respond(m, proto.DiagHealthAck{
		NodeID: n.spec.ID,
		Role:   string(n.spec.Role),
		OK:     healthy,
		Detail: detail,
		Ts:     time.Now().UTC(),
	})
}

func (n *simNode) onPing(m *nats.Msg) { n.respond(m, map[string]any{"ok": true}) }

func (n *simNode) onMarkGood(m *nats.Msg) {
	n.respond(m, proto.UpdateMarkGoodAck{OK: true})
}

// onMarkBad accepts the mark-bad and reverts, which is what a real agent does:
// the slot is flagged and the node reboots back to the one it came from.
func (n *simNode) onMarkBad(m *nats.Msg) {
	unlock := n.lock()
	n.active, n.inactive = n.inactive, n.active
	unlock()
	n.respond(m, proto.UpdateMarkBadAck{OK: true})
}

func (n *simNode) currentVersion() string {
	defer n.lock()()
	return n.version
}

func (n *simNode) bootIDNow() string {
	defer n.lock()()
	return n.bootID
}

func (n *simNode) activeSlot() proto.UpdateSlot {
	defer n.lock()()
	return n.active
}

func (n *simNode) precheckCount() int {
	defer n.lock()()
	return n.prechecks
}

var bootSeq struct {
	mu sync.Mutex
	n  int
}

// newBootID mints a fresh boot identity. Sequential rather than random: the
// only operation the contract performs on it is equality, and a readable value
// makes a failed assertion legible.
func newBootID() string {
	bootSeq.mu.Lock()
	defer bootSeq.mu.Unlock()
	bootSeq.n++
	return fmt.Sprintf("boot-%08d", bootSeq.n)
}

// ----- the fleet ----------------------------------------------------------

// fleetDefaults are the pacing knobs. They are small on purpose — the harness
// is a state-machine venue, not a stopwatch — but non-zero, because a fan-out
// whose work takes no time cannot be observed to overlap.
const (
	defaultInstallFor = 25 * time.Millisecond
	defaultRebootFor  = 25 * time.Millisecond
	// nodeStepCap compresses the node.update saga's step timeouts. Step 6's
	// real timeout is five minutes, and the two deadline-dependent shapes (c13,
	// c08) are defined by reaching it. waitForNewBoot polls every 2s, so the cap
	// has to leave room for at least two polls.
	nodeStepCap = 5 * time.Second
	// systemStepCap bounds the whole cascade. Generous: it is a backstop against
	// a wedged harness, not a behaviour under test.
	systemStepCap = 3 * time.Minute
)

// fleet is a running simulated cluster plus the real control-plane machinery
// driving it.
type fleet struct {
	t        *testing.T
	nc       *nats.Conn
	store    *Store
	inv      *inventory.Store
	jobStore *jobs.Store
	runner   *jobs.Runner
	nodes    map[string]*simNode
	order    []string // node ids in the order they were declared

	versionsMu sync.Mutex
	versions   map[string]string // bundle sha → version

	// installGauge is the sim-side concurrency observation: how many nodes were
	// inside their install at once. Independent of the event-stream measurement
	// in fleetRun, and the two agreeing is itself worth something.
	gaugeMu     sync.Mutex
	inFlight    int
	peakSeen    int
	evMu        sync.Mutex
	events      []proto.SystemUpdateChangeEvt
	liveCount   int
	livePeakAll int
	livePeak    map[proto.NodeRole]int
	liveNow     map[proto.NodeRole]int
}

// bundleSpec is one artifact staged on the control plane.
type bundleSpec struct {
	SHA        string
	Version    string
	Compatible string
	Arch       string
}

// osBundles is the pair of OS artifacts a mixed-arch cluster needs. Written out
// rather than derived so a reader can see that "one release, two artifacts" is
// the thing under test (Decision 11).
func osBundles(version string) []bundleSpec {
	return []bundleSpec{
		{SHA: "sha-amd64-" + version, Version: version, Compatible: "rasputin-n100", Arch: "amd64"},
		{SHA: "sha-arm64-" + version, Version: version, Compatible: "rasputin-rpi-arm64", Arch: "arm64"},
	}
}

// newFleet boots NATS, the three stores, the real runner with the real
// workflows, and the simulated nodes. Everything is torn down on test cleanup.
func newFleet(t *testing.T, nodes []simNodeSpec, bundles []bundleSpec) *fleet {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	nc := startNATS(t)

	store, err := OpenStore(ctx, filepath.Join(dir, "updater.db"))
	if err != nil {
		t.Fatalf("updater OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	inv, err := inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	jobStore, err := jobs.OpenStore(ctx, filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatalf("jobs OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })

	f := &fleet{
		t: t, nc: nc, store: store, inv: inv, jobStore: jobStore,
		nodes:    map[string]*simNode{},
		versions: map[string]string{},
		livePeak: map[proto.NodeRole]int{},
		liveNow:  map[proto.NodeRole]int{},
	}

	for _, b := range bundles {
		f.versions[b.SHA] = b.Version
		if err := store.CreateBundle(ctx, &Bundle{
			SHA256: b.SHA, Version: b.Version, Compatible: b.Compatible,
			Architecture: b.Arch, SizeBytes: 4096,
			UploadedAt: time.Now().UTC(), UploadedBy: "fleetsim",
		}); err != nil {
			t.Fatalf("create bundle %s: %v", b.SHA, err)
		}
	}

	now := time.Now().UTC()
	for _, spec := range nodes {
		if spec.Behaviour == "" {
			spec.Behaviour = simHealthy
		}
		if spec.InstallFor == 0 {
			spec.InstallFor = defaultInstallFor
		}
		if spec.RebootFor == 0 {
			spec.RebootFor = defaultRebootFor
		}
		if spec.Version == "" {
			spec.Version = "2026.08.0"
		}
		if err := inv.Insert(ctx, &proto.Node{
			ID:           spec.ID,
			Role:         spec.Role,
			Hostname:     spec.ID,
			Architecture: spec.Arch,
			ImageVersion: spec.Version,
			FirstSeen:    now,
			LastSeen:     now, // online: planTargets recomputes status from this
		}); err != nil {
			t.Fatalf("inv insert %s: %v", spec.ID, err)
		}
		n := &simNode{
			spec: spec, nc: nc,
			versionOf: f.versionFor,
			bootID:    newBootID(),
			active:    proto.SlotA,
			inactive:  proto.SlotB,
			version:   spec.Version,
			fleetEnter: func() {
				f.gaugeMu.Lock()
				f.inFlight++
				if f.inFlight > f.peakSeen {
					f.peakSeen = f.inFlight
				}
				f.gaugeMu.Unlock()
			},
			fleetExit: func() {
				f.gaugeMu.Lock()
				f.inFlight--
				f.gaugeMu.Unlock()
			},
		}
		if spec.Behaviour == simNoBootID {
			n.bootID = ""
		}
		if err := n.listen(); err != nil {
			t.Fatalf("node %s listen: %v", spec.ID, err)
		}
		t.Cleanup(n.silence)
		f.nodes[spec.ID] = n
		f.order = append(f.order, spec.ID)
	}

	runner := jobs.NewRunner(jobStore, nc)
	// Retries exist in the saga for genuinely transient RPC failures; a
	// second-long backoff in a harness is just dead time.
	runner.SetBackoff(func(int) time.Duration { return 10 * time.Millisecond })
	runner.Register(cappedTimeouts(UpdateWorkflow(store, inv, nc, Config{
		PublicBaseURL: "http://localhost:8080",
	}), nodeStepCap))
	runner.Register(cappedTimeouts(SystemUpdateWorkflow(store, inv, jobStore, runner, nc,
		SystemUpdateConfig{}), systemStepCap))
	f.runner = runner
	t.Cleanup(runner.Wait)

	return f
}

func (f *fleet) versionFor(sha string) string {
	f.versionsMu.Lock()
	defer f.versionsMu.Unlock()
	return f.versions[sha]
}

// cappedTimeouts lowers every step timeout to at most cap, leaving the DoFns —
// the code actually under test — untouched.
//
// ⚠️ It is a pacing device, never an assertion. Two of the shapes this harness
// exists to reach (c13, c08) are DEFINED by a step reaching its deadline, and a
// five-minute deadline turns each of them into a five-minute test, which is a
// test nobody runs. What the harness asserts is what the code does when a
// deadline fires; the production values are what they are, and this does not
// claim otherwise.
func cappedTimeouts(wf jobs.Workflow, cap time.Duration) jobs.Workflow {
	steps := make([]jobs.WorkflowStep, len(wf.Steps))
	copy(steps, wf.Steps)
	for i := range steps {
		if steps[i].Timeout > cap {
			steps[i].Timeout = cap
		}
	}
	wf.Steps = steps
	return wf
}

// ----- running a rollout --------------------------------------------------

// fleetRun is everything one system.update produced: the parent job's verdict,
// the wire events in the order they were published, and the report grid.
type fleetRun struct {
	t        *testing.T
	JobID    string
	Status   jobs.Status
	Error    string
	Events   []proto.SystemUpdateChangeEvt
	Results  []proto.NodeResult
	Skipped  []proto.SkippedNode
	Counts   proto.SystemUpdateCounts
	Duration time.Duration
	// PeakInFlight is the highest number of nodes simultaneously between
	// node_started and their terminal node_* event, measured from the api's OWN
	// wire events rather than from the simulator — the fan-out width as an
	// operator watching the bus would see it.
	PeakInFlight     int
	PeakInFlightTier map[proto.NodeRole]int
	// PeakInstalling is the simulator's independent view: nodes inside their
	// install RPC at the same moment.
	PeakInstalling int
}

// run submits a system.update and waits for it to reach a terminal state.
func (f *fleet) run(spec proto.SystemUpdateSpec) fleetRun {
	f.t.Helper()
	ctx := context.Background()

	f.evMu.Lock()
	f.events = nil
	f.liveCount, f.livePeakAll = 0, 0
	f.livePeak = map[proto.NodeRole]int{}
	f.liveNow = map[proto.NodeRole]int{}
	f.evMu.Unlock()
	f.gaugeMu.Lock()
	f.peakSeen, f.inFlight = 0, 0
	f.gaugeMu.Unlock()

	run := fleetRun{t: f.t, PeakInFlightTier: map[proto.NodeRole]int{}}

	// Subscribe BEFORE submitting: the planned event fires inside the first
	// step, which starts as soon as Submit returns.
	sub, err := f.nc.Subscribe(proto.AllSystemUpdatesFilter, func(m *nats.Msg) {
		var ev proto.SystemUpdateChangeEvt
		if json.Unmarshal(m.Data, &ev) != nil {
			return
		}
		// Everything the callback touches lives on the fleet under evMu and is
		// copied out once the job is terminal. Writing into `run` from here
		// instead would be a data race with the goroutine assembling it — the
		// subscription outlives the last event only by a hair.
		f.evMu.Lock()
		defer f.evMu.Unlock()
		f.events = append(f.events, ev)
		switch ev.Change {
		case proto.SystemUpdateNodeStarted:
			f.liveCount++
			f.liveNow[ev.Tier]++
			if f.liveNow[ev.Tier] > f.livePeak[ev.Tier] {
				f.livePeak[ev.Tier] = f.liveNow[ev.Tier]
			}
			if f.liveCount > f.livePeakAll {
				f.livePeakAll = f.liveCount
			}
		case proto.SystemUpdateNodeSucceeded, proto.SystemUpdateNodeFailed:
			f.liveCount--
			f.liveNow[ev.Tier]--
		}
	})
	if err != nil {
		f.t.Fatalf("subscribe system updates: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := f.nc.Flush(); err != nil {
		f.t.Fatalf("flush: %v", err)
	}

	body, err := json.Marshal(spec)
	if err != nil {
		f.t.Fatalf("marshal spec: %v", err)
	}
	started := time.Now()
	job, err := f.runner.Submit(ctx, "system.update", body, "fleetsim")
	if err != nil {
		f.t.Fatalf("submit system.update: %v", err)
	}
	run.JobID = job.ID

	// A hard deadline, not an open-ended poll: a harness that hangs forever on a
	// wedged cascade tells you nothing and costs an afternoon.
	deadline := time.Now().Add(systemStepCap + 30*time.Second)
	for {
		if time.Now().After(deadline) {
			f.t.Fatalf("system.update %s never reached a terminal state within %s", job.ID, time.Since(started))
		}
		j, err := f.jobStore.GetJob(ctx, job.ID)
		if err != nil {
			f.t.Fatalf("get job: %v", err)
		}
		if j != nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed || j.Status == jobs.StatusCancelled) {
			run.Status, run.Error = j.Status, j.Error
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	run.Duration = time.Since(started)

	f.evMu.Lock()
	run.Events = append([]proto.SystemUpdateChangeEvt(nil), f.events...)
	run.PeakInFlight = f.livePeakAll
	for tier, peak := range f.livePeak {
		run.PeakInFlightTier[tier] = peak
	}
	f.evMu.Unlock()
	f.gaugeMu.Lock()
	run.PeakInstalling = f.peakSeen
	f.gaugeMu.Unlock()

	// The completed event is the report. It fires on every outcome — that is the
	// point of it (#76) — so its absence is itself a finding.
	for _, ev := range run.Events {
		if ev.Change == proto.SystemUpdateCompleted {
			run.Results, run.Skipped = ev.Results, ev.Skipped
			if ev.Counts != nil {
				run.Counts = *ev.Counts
			}
		}
	}
	return run
}

// ----- reading a run ------------------------------------------------------

// outcome returns one node's grid row.
func (r fleetRun) outcome(nodeID string) (proto.NodeResult, bool) {
	for _, row := range r.Results {
		if row.NodeID == nodeID {
			return row, true
		}
	}
	return proto.NodeResult{}, false
}

// mustOutcome fails the test if the node has no grid row at all. Every planned
// target gets one whether or not it was started — that is the difference
// between a report and a list of things that happened to work — so a missing
// row is a defect, not a test-setup problem.
func (r fleetRun) mustOutcome(nodeID string) proto.NodeResult {
	r.t.Helper()
	row, ok := r.outcome(nodeID)
	if !ok {
		r.t.Fatalf("no grid row for %s; the report accounted for %d node(s): %v",
			nodeID, len(r.Results), r.nodeIDs())
	}
	return row
}

func (r fleetRun) nodeIDs() []string {
	out := make([]string, len(r.Results))
	for i, row := range r.Results {
		out[i] = row.NodeID
	}
	return out
}

// withOutcome lists the nodes whose row carries the given outcome, in planned
// order.
func (r fleetRun) withOutcome(o proto.NodeOutcome) []string {
	var out []string
	for _, row := range r.Results {
		if row.Outcome == o {
			out = append(out, row.NodeID)
		}
	}
	return out
}

// changes lists the events of one type, in publication order.
func (r fleetRun) changes(c proto.SystemUpdateChangeType) []proto.SystemUpdateChangeEvt {
	var out []proto.SystemUpdateChangeEvt
	for _, ev := range r.Events {
		if ev.Change == c {
			out = append(out, ev)
		}
	}
	return out
}

// startOrder is the node ids in the order the cascade started them.
func (r fleetRun) startOrder() []string {
	var out []string
	for _, ev := range r.changes(proto.SystemUpdateNodeStarted) {
		out = append(out, ev.NodeID)
	}
	return out
}

// skipReason returns the reason a node was left out of the plan.
func (r fleetRun) skipReason(nodeID string) (proto.SkipReason, bool) {
	for _, sk := range r.Skipped {
		if sk.NodeID == nodeID {
			return sk.Reason, true
		}
	}
	return "", false
}

// nodeUpdateRow reads the durable per-node row the saga wrote. The grid is the
// report; this is the ledger, and the two disagreeing has been a bug more than
// once (#53).
func (f *fleet) nodeUpdateRow(t *testing.T, run fleetRun, nodeID string) *NodeUpdate {
	t.Helper()
	row := run.mustOutcome(nodeID)
	if row.ChildJobID == "" {
		return nil
	}
	nu, err := f.store.GetNodeUpdate(context.Background(), row.ChildJobID)
	if err != nil {
		t.Fatalf("get node_update for %s: %v", nodeID, err)
	}
	return nu
}

// node returns a simulated node by id.
func (f *fleet) node(t *testing.T, id string) *simNode {
	t.Helper()
	n, ok := f.nodes[id]
	if !ok {
		t.Fatalf("no simulated node %q", id)
	}
	return n
}

// invNode reads a node's inventory row.
func (f *fleet) invNode(t *testing.T, id string) *proto.Node {
	t.Helper()
	n, err := f.inv.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("inventory get %s: %v", id, err)
	}
	if n == nil {
		t.Fatalf("node %s vanished from inventory", id)
	}
	return n
}

// ----- fleet shapes -------------------------------------------------------

// computeFleet builds n compute nodes, alternating arch when both are asked
// for, plus the storage/controlplane/firewall nodes the caller wants.
func computeFleet(n int, arch string) []simNodeSpec {
	out := make([]simNodeSpec, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, simNodeSpec{
			ID:   fmt.Sprintf("c%02d", i+1),
			Role: proto.RoleCompute,
			Arch: arch,
		})
	}
	return out
}

// bitscopeShaped is a 24-node cluster shaped like the one Decision 10 rations:
// a large mixed-arch compute tier, a storage pair, the controlplane and the
// firewall. 24 is proto.MaxClusterNodes, so this is the largest cluster the
// product admits, not an arbitrary big number.
func bitscopeShaped() []simNodeSpec {
	var out []simNodeSpec
	for i := 0; i < 12; i++ {
		out = append(out, simNodeSpec{ID: fmt.Sprintf("c%02d", i+1), Role: proto.RoleCompute, Arch: "amd64"})
	}
	for i := 12; i < 20; i++ {
		out = append(out, simNodeSpec{ID: fmt.Sprintf("c%02d", i+1), Role: proto.RoleCompute, Arch: "arm64"})
	}
	out = append(out,
		simNodeSpec{ID: "s01", Role: proto.RoleStorage, Arch: "amd64"},
		simNodeSpec{ID: "s02", Role: proto.RoleStorage, Arch: "arm64"},
		simNodeSpec{ID: "cp01", Role: proto.RoleControlPlane, Arch: "amd64"},
		simNodeSpec{ID: "fw01", Role: proto.RoleFirewall, Arch: "amd64"},
	)
	return out
}

// behave returns a copy of specs with one node's behaviour replaced.
func behave(specs []simNodeSpec, id string, b simBehaviour) []simNodeSpec {
	out := append([]simNodeSpec(nil), specs...)
	found := false
	for i := range out {
		if out[i].ID == id {
			out[i].Behaviour = b
			found = true
		}
	}
	if !found {
		panic("behave: no node " + id + " in this fleet")
	}
	return out
}

// releaseSpec is the release-keyed form of the spec — the one the UI sends and
// the only one that resolves a per-arch artifact per node. "os" is the
// component id from the releases registry; the firewall's is "fw", and a run
// carries exactly one of them (Decision 8).
func releaseSpec(version string) proto.SystemUpdateSpec {
	return proto.SystemUpdateSpec{Version: version, Component: "os"}
}
