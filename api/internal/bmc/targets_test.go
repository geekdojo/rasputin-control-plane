package bmc

import (
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// registerHost inserts the fixture's BMC-host node ("host-1"), optionally
// advertising a bmc-targets list the way a real host agent would.
func registerHost(t *testing.T, f *fixture, inv *inventory.Store, targets []string) {
	t.Helper()
	n := &proto.Node{
		ID: "host-1", Role: proto.RoleControlPlane, Hostname: "host-1.local",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}
	if targets != nil {
		n.Capabilities = []string{proto.CapabilityBMCTargets}
		n.Metadata = map[string]any{proto.MetadataBMCTargets: targets}
	}
	if err := inv.Insert(f.ctx, n); err != nil {
		t.Fatalf("insert host: %v", err)
	}
}

func TestTargetReachable_HostNotRegistered(t *testing.T) {
	// Interim behavior: an unregistered host doesn't gate (presence-only
	// checks elsewhere still apply).
	f := newFixture(t)
	inv := newInvStore(t)
	if err := f.svc.TargetReachable(f.ctx, inv, "node-1"); err != nil {
		t.Errorf("unregistered host should not gate: %v", err)
	}
}

func TestTargetReachable_HostWithoutCapability(t *testing.T) {
	// Older agents / mock hosts advertise nothing — presence-only
	// behavior is preserved for them.
	f := newFixture(t)
	inv := newInvStore(t)
	registerHost(t, f, inv, nil)
	if err := f.svc.TargetReachable(f.ctx, inv, "node-1"); err != nil {
		t.Errorf("non-advertising host should not gate: %v", err)
	}
}

func TestTargetReachable_AdvertisedTarget(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	registerHost(t, f, inv, []string{"node-1", "node-2"})
	if err := f.svc.TargetReachable(f.ctx, inv, "node-2"); err != nil {
		t.Errorf("advertised target refused: %v", err)
	}
}

func TestTargetReachable_UnadvertisedTargetRefused(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	registerHost(t, f, inv, []string{"node-1"})
	err := f.svc.TargetReachable(f.ctx, inv, "node-9")
	if err == nil {
		t.Fatal("unadvertised target must be refused")
	}
	if !strings.Contains(err.Error(), "bmc-targets") {
		t.Errorf("refusal should name the gate: %v", err)
	}
}

func TestPowerValidate_GatesOnAdvertisedTargets(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	registerHost(t, f, inv, []string{"node-1"})
	for _, n := range []string{"node-1", "node-9"} {
		if err := inv.Insert(f.ctx, &proto.Node{
			ID: n, Role: proto.RoleCompute, Hostname: n + ".local",
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	step := powerValidate(f.svc, inv)

	sc := stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "node-1", Verb: proto.BMCPowerOn})
	if _, err := step(sc); err != nil {
		t.Errorf("advertised target should validate: %v", err)
	}

	sc = stepCtx(f.ctx, f.nc, Spec{TargetNodeID: "node-9", Verb: proto.BMCPowerOn})
	if _, err := step(sc); err == nil {
		t.Error("registered-but-unadvertised target must be refused")
	}
}
