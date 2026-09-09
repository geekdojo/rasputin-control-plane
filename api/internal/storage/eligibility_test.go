package storage

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// CanHoldTarget is the ONE rule the picker, the claim handler, the saga and
// the target listing share (#397). These cases pin what it says today —
// controlplane only — and the words it says it in, because those words are
// what the operator reads on four surfaces and they have to match.
func TestCanHoldTarget(t *testing.T) {
	for _, role := range proto.AllRoles {
		node := &proto.Node{ID: "n-1", Role: role, Hostname: "shelf"}
		ok, reason := CanHoldTarget(node)
		if role == proto.RoleControlPlane {
			if !ok || reason != "" {
				t.Errorf("%s: ok=%v reason=%q — the controlplane is where the ingest writes, so its disks are the ones that can be targets", role, ok, reason)
			}
			continue
		}
		if ok {
			t.Errorf("%s: a disk on a %s node was offered as a target, and nothing can carry an archive to it", role, role)
		}
		for _, want := range []string{"a disk on shelf (" + string(role) + ") cannot receive backups yet", "controlplane's ingest", "storage SKU (#302)"} {
			if !strings.Contains(reason, want) {
				t.Errorf("%s: reason %q should say %q", role, reason, want)
			}
		}
	}
}

func TestCanHoldTarget_NamesTheNodeTheOperatorSees(t *testing.T) {
	_, reason := CanHoldTarget(&proto.Node{ID: "n-2", Role: proto.RoleStorage})
	if !strings.Contains(reason, "a disk on n-2 (storage)") {
		t.Errorf("with no hostname the id is the name: %q", reason)
	}
	if ok, reason := CanHoldTarget(nil); ok || reason == "" {
		t.Errorf("a nil node is refused with a reason, never guessed at: ok=%v reason=%q", ok, reason)
	}
}
