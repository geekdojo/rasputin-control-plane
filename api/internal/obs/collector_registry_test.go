package obs

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// A collector is the node's HTTPS credential, so the collector jobs follow
// the node's join token — read from the api's one in-memory node registry,
// the same list the ingress admits handshakes against.

func admittedStore(t *testing.T, nodes ...string) *inventory.Store {
	t.Helper()
	ctx := context.Background()
	inv, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	now := time.Now().UTC()
	live := map[string][]string{}
	for _, id := range nodes {
		if err := inv.Insert(ctx, &proto.Node{
			ID: id, Role: proto.RoleCompute, Hostname: id, FirstSeen: now, LastSeen: now,
		}); err != nil {
			t.Fatal(err)
		}
		live[id] = []string{"tok-" + id}
	}
	inv.Registry().ReplaceLiveTokens(live)
	return inv
}

// The converge decision skips a node the registry no longer admits, with its
// own tally entry, whether obs is on or off.
func TestDecideCollectorActions_SkipsANodeThatIsNotAdmitted(t *testing.T) {
	now := time.Now().UTC()
	nodes := []*proto.Node{
		{ID: "n1", Role: proto.RoleCompute, LastSeen: now},
		{ID: "n2", Role: proto.RoleCompute, LastSeen: now},
	}
	admitted := func(id string) bool { return id == "n1" }
	act := decideCollectorActions(nodes, map[string]*nodeJobState{}, map[string]*nodeJobState{}, true, now, admitted)
	if len(act.deploy) != 1 || act.deploy[0] != "n1" {
		t.Errorf("deploy = %v, want [n1]", act.deploy)
	}
	if act.skipped["not_admitted"] != 1 {
		t.Errorf("skipped = %v, want not_admitted:1", act.skipped)
	}
}

// The per-node deploy refuses before it mints a leaf: a node that stopped
// being admitted between the reconcile and the job is a no-op success, and
// the mint is never called.
func TestCollectorDeploy_StopsWhenTheNodeIsNotAdmitted(t *testing.T) {
	inv := admittedStore(t, "n1")
	minted := 0
	deps := CollectorDeployDeps{
		Inv: inv,
		Mint: func(string) (string, string, string, error) {
			minted++
			return "", "", "", errors.New("should not be reached")
		},
		IngressBaseURL: "https://cluster.local:8443",
		ServerName:     "cluster.local",
	}
	spec, _ := json.Marshal(CollectorNodeSpec{NodeID: "n1"})
	run := func() error {
		_, err := collectorDeploy(deps)(&jobs.StepCtx{
			Ctx: context.Background(), JobID: "j", Spec: spec, Log: func(string, string) {},
		})
		return err
	}

	// Its last token is revoked: the row stays, the admission does not.
	inv.Registry().ReplaceLiveTokens(map[string][]string{})
	if err := run(); !errors.Is(err, jobs.ErrStopWorkflow) {
		t.Errorf("deploy for a node that is not admitted = %v, want ErrStopWorkflow", err)
	}
	if minted != 0 {
		t.Errorf("a leaf was minted for a node the ingress would refuse (%d mints)", minted)
	}
}
