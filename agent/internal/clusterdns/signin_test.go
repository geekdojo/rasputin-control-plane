package clusterdns

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-983-01 (clusterdns half): the routing domain for the app door is the
// proto constructor's name, byte for byte.
func TestDomains_AppDoorFromTheConstructor(t *testing.T) {
	got := Domains("bench")
	if got[2] != "~"+proto.SignInFQDN("bench") || got[2] != "~signin.bench.internal" {
		t.Errorf("Domains(bench)[2] = %q", got[2])
	}
	if got[1] != "~"+proto.BaseDomain("bench") {
		t.Errorf("Domains(bench)[1] = %q", got[1])
	}
}

// TC-983-17: the rendered drop-in carries the door's routing domain, and an
// agent upgraded over a pre-upgrade drop-in rewrites it and reloads resolved
// exactly once, then changes nothing.
func TestApply_UpgradesAPreDoorDropInOnce(t *testing.T) {
	const ip = "192.168.197.224"
	body := Render("bench", ip)
	if !strings.Contains(body, "Domains=~bench.local ~bench.internal ~signin.bench.internal\n") {
		t.Fatalf("rendered drop-in lacks the door domain:\n%s", body)
	}

	h, _ := connected(t, ip)
	old := strings.Replace(Render(h.cfg.ClusterID, ip), " ~signin."+h.cfg.ClusterID+".internal", "", 1)
	if old == Render(h.cfg.ClusterID, ip) {
		t.Fatal("could not build the pre-upgrade drop-in")
	}
	if err := os.MkdirAll(h.cfg.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path(), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := Apply(context.Background(), h.cfg, TriggerConnected)
	if err != nil || !changed {
		t.Fatalf("first Apply = %v, %v; want a rewrite", changed, err)
	}
	if got, _ := os.ReadFile(h.path()); string(got) != Render(h.cfg.ClusterID, ip) {
		t.Errorf("drop-in after upgrade:\n%s", got)
	}
	if h.reloaded() != 1 {
		t.Errorf("reloads = %d, want 1", h.reloaded())
	}
	changed, err = Apply(context.Background(), h.cfg, TriggerTick)
	if err != nil || changed || h.reloaded() != 1 {
		t.Errorf("second Apply = %v, %v, reloads %d; want no change", changed, err, h.reloaded())
	}
}
