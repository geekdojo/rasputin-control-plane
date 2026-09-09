package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The version-skew gate on StorageClaimCmd.Purpose.
//
// An agent below proto.StorageClaimPurposeMinAgentVersion does not refuse a
// purpose it does not know — it never sees the field at all. encoding/json
// drops the unknown key, and the StorageClaimCmd it unmarshals is
// byte-identical to one an api predating §6 would have sent, which
// EffectivePurpose resolves to backup ON PURPOSE so that older api keeps
// working. So a `data` claim delivered to such an agent is not rejected; it is
// PERFORMED, as a backup target: the rasputin-backup GPT name, the
// RASPUTIN-BACKUP filesystem label, the backup marker. The disk then reads
// back to enumeration as a backup target, and the operator's data disk is
// something §4.8's adopt-or-wipe prompt will offer to adopt.
//
// The api therefore refuses to SEND it. Not downgrade, not warn-and-proceed:
// silently formatting a disk as the wrong thing is the outcome the whole
// purpose mechanism exists to prevent, and doing it in the name of
// compatibility would prevent nothing.
//
// Backup is never gated. Every agent that answers storage.claim at all formats
// a backup target — that floor is verbMinAgentVersion["storage.claim"] — and
// an empty purpose on the wire is the documented way to ask for one.

// CheckClaimPurposeSupported reports whether the agent on nodeID is new enough
// to read StorageClaimCmd.Purpose, for a claim carrying purpose. A nil error
// means the claim may be sent.
//
// It FAILS CLOSED on every kind of not-knowing — no inventory, no such node,
// no reported version, an unparseable version. "We could not tell what the
// agent would do with this field" and "the agent ignores this field" have the
// same consequence on the platter, so they get the same answer.
func CheckClaimPurposeSupported(ctx context.Context, inv *inventory.Store, nodeID string, purpose proto.StoragePurpose) error {
	if purpose == proto.StoragePurposeBackup || purpose == "" {
		return nil
	}
	floor := proto.StorageClaimPurposeMinAgentVersion
	consequence := fmt.Sprintf("a %q claim sent to it would be formatted as a BACKUP target — the backup GPT name, the backup filesystem label and the backup marker — and would then read back as a backup disk", purpose)
	if inv == nil {
		return fmt.Errorf("refusing to claim a disk on %s for %q: this api cannot look up which agent version that node runs, so it cannot tell whether the agent reads the claim's purpose (first read by agent v%s). %s",
			nodeID, purpose, floor, consequence)
	}
	node, err := inv.Get(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("refusing to claim a disk on %s for %q: the node's agent version could not be read (%v), and an agent below v%s ignores the purpose. %s",
			nodeID, purpose, err, floor, consequence)
	}
	if node == nil {
		return fmt.Errorf("refusing to claim a disk on %s for %q: the node is not registered, so its agent version is unknown (the purpose is first read by agent v%s). %s",
			nodeID, purpose, floor, consequence)
	}
	v := strings.TrimPrefix(strings.TrimSpace(node.AgentVersion), "v")
	if v == "" {
		return fmt.Errorf("refusing to claim a disk on %s for %q: that node never reported an agent version, so whether its agent reads the claim's purpose is unknown (first read by agent v%s). %s — update the node and re-register it",
			nodeID, purpose, floor, consequence)
	}
	c, cerr := releases.Compare(releases.SchemeCalVer, v, floor)
	if cerr != nil {
		return fmt.Errorf("refusing to claim a disk on %s for %q: its reported agent version %q could not be compared with v%s, so whether the agent reads the claim's purpose is unknown. %s",
			nodeID, purpose, node.AgentVersion, floor, consequence)
	}
	if c < 0 {
		return fmt.Errorf("refusing to claim a disk on %s for %q: the agent there (v%s) predates the claim purpose, which is first read by agent v%s. %s — update the node to ≥ v%s and claim again",
			nodeID, purpose, v, floor, consequence, floor)
	}
	return nil
}

// claimCmdBytes is the ONE way a StorageClaimCmd reaches the wire: it applies
// the version gate for the command's own purpose and then encodes it.
//
// Gate and encode are one function so the gate cannot be forgotten by a caller
// that adds a second claim path later. A claim that fails the gate produces no
// bytes at all, so there is nothing to accidentally publish.
func claimCmdBytes(ctx context.Context, inv *inventory.Store, nodeID string, cmd proto.StorageClaimCmd) ([]byte, error) {
	if err := CheckClaimPurposeSupported(ctx, inv, nodeID, cmd.EffectivePurpose()); err != nil {
		return nil, err
	}
	return json.Marshal(cmd)
}
