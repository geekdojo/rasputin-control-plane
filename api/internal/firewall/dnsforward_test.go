package firewall

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func dnsForwardIntent(t *testing.T, id string, enabled bool, zone, target string) *Intent {
	t.Helper()
	spec, err := json.Marshal(proto.DNSForwardSpec{Zone: zone, Target: target})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	now := time.Now().UTC()
	return &Intent{
		ID: id, Kind: string(proto.IntentDNSForward), Name: dnsForwardName,
		Enabled: enabled, Spec: spec, CreatedAt: now, UpdatedAt: now,
	}
}

func TestCompile_DNSForward(t *testing.T) {
	state, _, err := Compile([]*Intent{dnsForwardIntent(t, "d1", true, "home1.internal", "192.168.1.5")})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dhcp, ok := state["dhcp"].(map[string]any)
	if !ok {
		t.Fatalf("no dhcp key: %v", state)
	}
	if dhcp["server"] != "/home1.internal/192.168.1.5" {
		t.Errorf("server = %v, want /home1.internal/192.168.1.5", dhcp["server"])
	}
}

func TestCompile_DNSForwardDisabledOmitsKey(t *testing.T) {
	state, _, err := Compile([]*Intent{dnsForwardIntent(t, "d1", false, "home1.internal", "192.168.1.5")})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, ok := state["dhcp"]; ok {
		t.Error("a disabled dns_forward must emit no dhcp key (the agent then removes the forward)")
	}
}

func TestCompile_DNSForwardRejectsIPv6Target(t *testing.T) {
	if _, _, err := Compile([]*Intent{dnsForwardIntent(t, "d1", true, "home1.internal", "fd00::1")}); err == nil {
		t.Error("IPv6 target must be rejected (decision #9)")
	}
}

func TestCompile_DNSForwardRejectsTwoEnabled(t *testing.T) {
	ins := []*Intent{
		dnsForwardIntent(t, "d1", true, "home1.internal", "192.168.1.5"),
		dnsForwardIntent(t, "d2", true, "home1.internal", "192.168.1.6"),
	}
	if _, _, err := Compile(ins); err == nil {
		t.Error("two enabled dns_forward intents must error")
	}
}

func TestUpsertDNSForward_CreateUpdateNoopRemove(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Create.
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.5", true); err != nil || !changed {
		t.Fatalf("create: changed=%v err=%v", changed, err)
	}
	if onlyDNSForward(t, s) == nil {
		t.Fatal("no dns_forward intent after create")
	}

	// No-op when unchanged.
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.5", true); err != nil || changed {
		t.Fatalf("unchanged upsert should be a no-op: changed=%v err=%v", changed, err)
	}

	// Update on a new CP IP.
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.9", true); err != nil || !changed {
		t.Fatalf("update: changed=%v err=%v", changed, err)
	}
	var spec proto.DNSForwardSpec
	_ = json.Unmarshal(onlyDNSForward(t, s).Spec, &spec)
	if spec.Target != "192.168.1.9" {
		t.Errorf("target = %q, want 192.168.1.9", spec.Target)
	}

	// Remove when not wanted (mode left a firewall mode).
	if changed, err := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.9", false); err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if onlyDNSForward(t, s) != nil {
		t.Error("dns_forward intent still present after removal")
	}

	// Idempotent remove.
	if changed, _ := UpsertDNSForward(ctx, s, "home1.internal", "192.168.1.9", false); changed {
		t.Error("removing an absent forward must be a no-op")
	}
}

func onlyDNSForward(t *testing.T, s *Store) *Intent {
	t.Helper()
	ins, err := s.ListIntents(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *Intent
	for _, in := range ins {
		if proto.FirewallIntentKind(in.Kind) == proto.IntentDNSForward {
			if found != nil {
				t.Fatal("more than one dns_forward intent")
			}
			found = in
		}
	}
	return found
}
