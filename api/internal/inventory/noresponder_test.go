package inventory

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The e3bench case and its two neighbours: the same silence on the bus reads
// three different ways depending on what inventory knows about the node, and
// each reading is a different sentence — the old-agent one naming the verb
// and the release that answers it.
func TestExplainNoResponderTellsTheThreeCasesApart(t *testing.T) {
	now := time.Now().UTC()
	subject := proto.BackupStageVolumeSubject("e3bench-compute1")
	min, ok := proto.VerbMinAgentVersion("storage.backup_stage_volume")
	if !ok {
		t.Fatal("storage.backup_stage_volume has no recorded minimum agent version")
	}

	cases := []struct {
		name string
		node *proto.Node
		kind Silence
		want []string
		not  []string
	}{
		{
			name: "offline",
			node: &proto.Node{ID: "e3bench-compute1", AgentVersion: "2026.08.4-dev.130", LastSeen: now.Add(-time.Hour)},
			kind: SilenceOffline,
			want: []string{"e3bench-compute1 is offline", "storage.backup_stage_volume"},
			not:  []string{"online", "predates"},
		},
		{
			name: "stale is not online",
			node: &proto.Node{ID: "e3bench-compute1", AgentVersion: "2026.08.4-dev.130", LastSeen: now.Add(-staleAfter - time.Second)},
			kind: SilenceOffline,
			want: []string{"e3bench-compute1 is stale"},
		},
		{
			name: "online, agent too old",
			node: &proto.Node{ID: "e3bench-compute1", AgentVersion: "2026.08.4-dev.130", LastSeen: now},
			kind: SilenceOldAgent,
			want: []string{"e3bench-compute1 is online", "(v2026.08.4-dev.130) predates storage.backup_stage_volume", "update the node to ≥ v" + min},
			not:  []string{"offline", "OFFLINE"},
		},
		{
			name: "online, agent at the floor, still silent",
			node: &proto.Node{ID: "e3bench-compute1", AgentVersion: min, LastSeen: now},
			kind: SilenceUnexplained,
			want: []string{"e3bench-compute1 is online", "(v" + min + ") should answer storage.backup_stage_volume", "did not"},
			not:  []string{"offline", "predates", "update the node"},
		},
		{
			name: "online, agent newer than the floor, still silent",
			node: &proto.Node{ID: "e3bench-compute1", AgentVersion: "2026.09.0", LastSeen: now},
			kind: SilenceUnexplained,
			want: []string{"should answer", "did not"},
			not:  []string{"predates"},
		},
		{
			name: "online, agent never reported a version",
			node: &proto.Node{ID: "e3bench-compute1", LastSeen: now},
			kind: SilenceUnexplained,
			want: []string{"never reported an agent version", "storage.backup_stage_volume"},
			not:  []string{"predates", "offline"},
		},
		{
			name: "online, agent version unreadable",
			node: &proto.Node{ID: "e3bench-compute1", AgentVersion: "dev", LastSeen: now},
			kind: SilenceUnexplained,
			not:  []string{"predates"},
		},
		{
			name: "not in inventory",
			node: nil,
			kind: SilenceNodeUnknown,
			want: []string{"e3bench-compute1 is not in inventory", "storage.backup_stage_volume"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := ExplainNoResponder(tc.node, subject)
			if n.Kind != tc.kind {
				t.Errorf("kind = %d, want %d (%s)", n.Kind, tc.kind, n)
			}
			if n.NodeID != "e3bench-compute1" || n.Verb != "storage.backup_stage_volume" {
				t.Errorf("node/verb = %q/%q", n.NodeID, n.Verb)
			}
			if n.Online() != (tc.kind == SilenceOldAgent || tc.kind == SilenceUnexplained) {
				t.Errorf("Online() = %v for kind %d", n.Online(), tc.kind)
			}
			s := n.String()
			for _, w := range tc.want {
				if !strings.Contains(s, w) {
					t.Errorf("%q does not say %q", s, w)
				}
			}
			for _, w := range tc.not {
				if strings.Contains(s, w) {
					t.Errorf("%q must not say %q", s, w)
				}
			}
		})
	}
}

// A verb proto records no floor for is still reported honestly — as an
// unanswered request, without an invented minimum.
func TestExplainNoResponderUnrecordedVerb(t *testing.T) {
	n := ExplainNoResponder(&proto.Node{ID: "n1", AgentVersion: "2026.08.4", LastSeen: time.Now()}, proto.NodeCmdSubject("n1", "diag.ping"))
	if n.Kind != SilenceUnexplained || n.MinVersion != "" {
		t.Fatalf("%+v", n)
	}
	if s := n.String(); !strings.Contains(s, "no minimum agent version is recorded") || !strings.Contains(s, "diag.ping") {
		t.Errorf("%q", s)
	}
}

// A reported version with a leading "v" compares the same as a bare one.
func TestExplainNoResponderToleratesALeadingV(t *testing.T) {
	n := ExplainNoResponder(&proto.Node{ID: "n1", AgentVersion: "v2026.08.4-dev.130", LastSeen: time.Now()}, proto.AppVolumesListSubject("n1"))
	if n.Kind != SilenceOldAgent {
		t.Fatalf("%+v", n)
	}
	if s := n.String(); !strings.Contains(s, "(v2026.08.4-dev.130) predates docker.volumes.list") {
		t.Errorf("%q", s)
	}
}

// The store form looks the node up itself, and an unknown node is said to be
// unknown rather than offline.
func TestStoreExplainNoResponder(t *testing.T) {
	ctx := context.Background()
	st, err := OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Insert(ctx, &proto.Node{ID: "c1", Role: proto.RoleCompute, Hostname: "c1", AgentVersion: "2026.08.4-dev.130", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if n := st.ExplainNoResponder(ctx, proto.AppVolumesListSubject("c1")); n.Kind != SilenceOldAgent {
		t.Errorf("c1: %+v (%s)", n, n)
	}
	if n := st.ExplainNoResponder(ctx, proto.AppVolumesListSubject("ghost")); n.Kind != SilenceNodeUnknown || n.Err != nil {
		t.Errorf("ghost: %+v (%s)", n, n)
	}
}
