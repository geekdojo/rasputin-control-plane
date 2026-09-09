package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The version-skew gate. An agent below the floor does not refuse a purpose it
// has never heard of — it never sees the field, so the claim it acts on is
// indistinguishable from a backup claim and it formats the disk as a backup
// target. These tests pin that the api refuses to send it, and refuses in
// every "we cannot tell" case too.

func purposeInv(t *testing.T, nodes ...*proto.Node) *inventory.Store {
	t.Helper()
	inv, err := inventory.OpenStore(context.Background(), filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	for _, n := range nodes {
		if err := inv.Insert(context.Background(), n); err != nil {
			t.Fatalf("inv insert %s: %v", n.ID, err)
		}
	}
	return inv
}

func nodeAt(id, agentVersion string) *proto.Node {
	now := time.Now().UTC()
	return &proto.Node{ID: id, Role: proto.RoleControlPlane, Hostname: id + ".test", FirstSeen: now, LastSeen: now, AgentVersion: agentVersion}
}

func TestCheckClaimPurposeSupported(t *testing.T) {
	const node = "n-1"
	tests := []struct {
		name    string
		version string
		// unregistered replaces the node with a different one, so the lookup
		// misses.
		unregistered bool
		noInventory  bool
		purpose      proto.StoragePurpose
		wantErr      bool
		wantIn       []string
	}{
		{
			name: "a data claim to an agent below the floor is refused",
			// The release published before the floor: the exact skew.
			version: "2026.08.5-dev.147",
			purpose: proto.StoragePurposeData,
			wantErr: true,
			wantIn:  []string{"n-1", "v2026.08.5-dev.147", "v" + proto.StorageClaimPurposeMinAgentVersion, "BACKUP target", "update the node"},
		},
		{
			name:    "a data claim to an agent far below the floor is refused",
			version: "2026.08.4-dev.130",
			purpose: proto.StoragePurposeData,
			wantErr: true,
			wantIn:  []string{"predates the claim purpose"},
		},
		{
			name:    "a data claim at the floor is allowed",
			version: proto.StorageClaimPurposeMinAgentVersion,
			purpose: proto.StoragePurposeData,
		},
		{
			name:    "a data claim above the floor is allowed",
			version: "2026.09.1-dev.3",
			purpose: proto.StoragePurposeData,
		},
		// Backup is never gated: every agent that answers storage.claim at
		// all formats a backup target, and an absent purpose IS the way to
		// ask an old agent for one.
		{name: "a backup claim to an ancient agent is allowed", version: "2026.07.1-dev.33", purpose: proto.StoragePurposeBackup},
		{name: "an absent purpose is a backup claim and is allowed", version: "2026.07.1-dev.33", purpose: ""},
		// Fail closed on every kind of not-knowing.
		{
			name:    "no reported version is a refusal",
			version: "",
			purpose: proto.StoragePurposeData,
			wantErr: true,
			wantIn:  []string{"never reported an agent version"},
		},
		{
			name:    "an unparseable version is a refusal",
			version: "not-a-version",
			purpose: proto.StoragePurposeData,
			wantErr: true,
			wantIn:  []string{"could not be compared"},
		},
		{
			name:         "an unregistered node is a refusal",
			unregistered: true,
			purpose:      proto.StoragePurposeData,
			wantErr:      true,
			wantIn:       []string{"not registered"},
		},
		{
			name:        "no inventory at all is a refusal",
			noInventory: true,
			purpose:     proto.StoragePurposeData,
			wantErr:     true,
			wantIn:      []string{"cannot look up which agent version"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var inv *inventory.Store
			if !tc.noInventory {
				id := node
				if tc.unregistered {
					id = "somebody-else"
				}
				inv = purposeInv(t, nodeAt(id, tc.version))
			}
			err := CheckClaimPurposeSupported(context.Background(), inv, node, tc.purpose)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("CheckClaimPurposeSupported: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a %q claim was allowed through to an agent at %q", tc.purpose, tc.version)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q should say %q", err, want)
				}
			}
		})
	}
}

// The gate refuses rather than downgrades, and the proof is that no bytes come
// out of it: a caller cannot accidentally publish a claim that got as far as
// being encoded with the purpose stripped.
func TestClaimCmdBytesRefusesRatherThanDowngrades(t *testing.T) {
	inv := purposeInv(t, nodeAt("n-1", "2026.08.5-dev.147"))
	cmd := proto.StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp", Purpose: proto.StoragePurposeData}
	b, err := claimCmdBytes(context.Background(), inv, "n-1", cmd)
	if err == nil {
		t.Fatalf("a data claim was encoded for an agent that cannot read the purpose: %s", b)
	}
	if b != nil {
		t.Errorf("a refused claim still produced %d bytes to send", len(b))
	}
}

// The backup path this saga actually uses goes through the same function, and
// the command it produces still carries no purpose at all — which is what an
// agent from before §6 needs to see.
func TestClaimCmdBytesLeavesTheBackupClaimAlone(t *testing.T) {
	inv := purposeInv(t, nodeAt("n-1", "2026.08.5-dev.132"))
	b, err := claimCmdBytes(context.Background(), inv, "n-1", proto.StorageClaimCmd{DevicePath: "/dev/sdb", Fingerprint: "fp"})
	if err != nil {
		t.Fatalf("claimCmdBytes: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := wire["purpose"]; present {
		t.Errorf("the backup claim put a purpose on the wire: %s", b)
	}
}
