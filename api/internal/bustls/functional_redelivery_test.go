package bustls_test

// THE FUNCTIONAL TEST for pin redelivery (geekdojo/geekdojo-brain#615), on the
// harness functional_test.go describes: the real embedded bus with the auth
// callout enforced, the real inventory service, job store and bustls service,
// and the real rasputin-agent binary as subprocesses.
//
// It walks the sequence that left nodes on plaintext: a controlplane restarts
// with a fleet that enrolled before the pin existed; the agents are back on
// its bus before it is listening for them; and the mode moves to migrate
// before the api has heard from them. Nothing the test does after that touches
// a node: no agent is restarted, reconnected or made to register.
//
// Run alone: scripts/test-bus-tls.sh -run TestFunctional_NodesMissed

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
	_ "modernc.org/sqlite" // the driver the api's stores use, for ageLastSeen
)

// ageLastSeen rewrites every node row's last_seen to long ago, with the
// controlplane stopped. It stands for the time a real api runs between a
// node's registration and its own restart: last_seen is written on
// registration only, so after hours of uptime every row is hours old, and a
// restarted api reads every node as offline until it hears from it. The test
// cannot wait hours, and must not wait at all.
func ageLastSeen(t *testing.T, dataDir string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE nodes SET last_seen = ?`, time.Now().Add(-6*time.Hour).UnixMilli())
	if err != nil {
		t.Fatalf("age last_seen: %v", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		t.Fatalf("age last_seen: %d row(s) changed (%v), want every node", n, err)
	}
}

func TestFunctional_NodesMissedAtTheMoveToMigrateStillReachTLS(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	computes := []string{"n1", "n2", "n3"}
	all := append([]string{"cp1"}, computes...)

	// 1. A fleet enrolled before the pin existed, on a controlplane held at
	// offer by a self-update in flight.
	c := startCP(t, cpOpts{selfNode: "cp1"})
	if c.mode != bustls.ModeOffer {
		t.Fatalf("the controlplane starts in %s, want offer", c.mode)
	}
	now := time.Now().UTC()
	selfUpdate := &jobs.Job{ID: "01SELFUPDATE", Kind: "node.update", Spec: json.RawMessage(`{"nodeId":"cp1"}`), Status: jobs.StatusQueued, CreatedAt: now}
	if err := c.jobStore.CreateJob(ctx, selfUpdate); err != nil {
		t.Fatal(err)
	}
	if err := c.jobStore.MarkJobStarted(ctx, selfUpdate.ID, now); err != nil {
		t.Fatal(err)
	}
	agents := map[string]*agentProc{
		"cp1": startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), tokenFile: c.agentTokenFile()}),
	}
	for _, id := range computes {
		agents[id] = startAgent(t, agentOpts{id: id, url: c.url(), token: c.mint(t, id)})
	}
	for _, id := range all {
		c.waitRegistered(t, id, false)
		c.waitRecorded(t, id)
	}
	c.svc.Wait()
	if got := c.svc.Mode(); got != bustls.ModeOffer {
		t.Fatalf("mode = %s with a self-update in flight, want offer", got)
	}

	// 2. The controlplane restarts. The agents keep running and find the new
	// bus on their own reconnect loops; each publishes its registration as
	// soon as it is admitted, which is before inventory is listening.
	c.stop()
	ageLastSeen(t, c.dataDir)

	var (
		mu        sync.Mutex
		published = map[string]bool{}
		early     signal
		earlySub  *nats.Subscription
	)
	c2 := startCP(t, cpOpts{
		dataDir: c.dataDir, port: c.port, selfNode: "cp1",
		beforeAdmission: func(c *cp) {
			sub, err := c.srv.Conn().Subscribe(proto.NodeRegisteredSubject("*"), func(m *nats.Msg) {
				var ev proto.NodeRegisteredEvt
				if json.Unmarshal(m.Data, &ev) != nil {
					return
				}
				mu.Lock()
				published[ev.NodeID] = true
				mu.Unlock()
				early.fire()
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.srv.Conn().Flush(); err != nil {
				t.Fatal(err)
			}
			earlySub = sub
		},
		beforeInventory: func(*cp) {
			waitFact(t, "registration from every agent before inventory is listening", &early, func() bool {
				mu.Lock()
				defer mu.Unlock()
				for _, id := range all {
					if !published[id] {
						return false
					}
				}
				return true
			}, func() string {
				mu.Lock()
				defer mu.Unlock()
				return fmt.Sprintf("published so far: %v", published)
			})
			_ = earlySub.Unsubscribe()
		},
	})
	if c2.mode != bustls.ModeOffer {
		t.Fatalf("the restarted controlplane starts in %s, want offer", c2.mode)
	}
	c2.svc.Wait() // the evaluation the start kicked
	if got := c2.svc.Mode(); got != bustls.ModeOffer {
		t.Fatalf("mode = %s with the self-update still in flight, want offer", got)
	}
	for _, id := range all {
		if c2.registeredAtAll(id) {
			t.Fatalf("the restarted controlplane received a registration from %s: the test did not reproduce the gap", id)
		}
	}

	// What the fan-out is about to see. Every node that has not sent a
	// heartbeat since inventory started listening reads as not online, and
	// the fan-out skips it. Which ones have is a matter of where each agent's
	// heartbeat schedule happens to be, so it is logged and not asserted: the
	// outcome below must hold either way.
	st, err := c2.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var unheard []string
	for _, n := range st.Nodes {
		if n.BusTLS {
			t.Fatalf("%s is recorded as on TLS before any pin was delivered: %+v", n.ID, n)
		}
		if n.Status != proto.StatusOnline {
			unheard = append(unheard, n.ID)
		}
	}
	sort.Strings(unheard)
	t.Logf("not heard from by the restarted controlplane at the move to migrate: %v of %v", unheard, all)

	// 3. The self-update ends: the build is committed, the mode moves to
	// migrate and the pin is fanned out — to whoever reads as online.
	c2.runner.FinishDeferred(ctx, selfUpdate.ID, true, "")

	// 4. With no further action: every node ends on TLS, and the bus stops
	// accepting plaintext.
	for _, id := range all {
		c2.waitRegistered(t, id, true)
	}
	c2.waitSwitched(t)
	if got, _ := c2.settings.Get(ctx, bustls.SettingKey); got != string(bustls.ModeRequire) {
		t.Fatalf("recorded mode = %q, want require", got)
	}
	if st, err = c2.svc.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if st.Mode != bustls.ModeRequire || st.PlaintextAllowed || st.Switching || st.SwitchFailed != "" || len(st.Blockers) != 0 {
		t.Fatalf("status at the end = %+v, want require with nothing held back", st)
	}
	pin := c2.key.Pin()
	for _, n := range st.Nodes {
		if !n.BusTLS || !n.Reported {
			t.Errorf("%s ended on busTls=%t reported=%t, want TLS", n.ID, n.BusTLS, n.Reported)
		}
		if n.PinDelivery == nil || n.PinDelivery.Outcome != bustls.PinDelivered {
			t.Errorf("%s: the status does not say its pin was delivered: %+v", n.ID, n.PinDelivery)
		}
	}
	for _, id := range all {
		a := agents[id]
		saved, err := os.ReadFile(filepath.Join(a.stateDir, "bus", "pin"))
		if err != nil || strings.TrimSpace(string(saved)) != pin {
			t.Errorf("%s saved pin = (%q, %v), want %s", id, saved, err, pin)
		}
		select {
		case <-a.done:
			t.Errorf("agent %s exited; it must have reached TLS as the same process", id)
		default:
		}
	}
	assertPlaintextRefused(t, c2.port)
}
