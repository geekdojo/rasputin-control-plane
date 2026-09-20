package alerts

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The "node key changed" alert (geekdojo/geekdojo-brain#514,
// auth-methodology §5.2).
//
// A node registers its own TLS keys and the api records them. A later
// registration presenting a DIFFERENT key for a purpose replaces the recorded
// one — refusing would strand every reflashed node — so the change is made
// visible instead. This is that visibility.
//
// Why it is persisted rather than derived on read, like node-offline: a key
// change is an event, not a state. There is nothing to recompute a minute
// later, and the operator needs to be able to say "yes, I reflashed that node"
// and have it stay said. The persisted row carries that ack.
//
// One row per node per NEW key set: a second, different change raises its own
// alert rather than quietly updating an acknowledged one, because "the key
// changed again" is a fact the first ack did not cover.

// nodeKeyChangedAlertName is the alertname label and the row's id prefix.
const nodeKeyChangedAlertName = "NodeKeyChanged"

// NodeKeyChangedID is the persisted alert's id for one node and one new key
// set. Exported so a test can assert on it without rebuilding the derivation.
func NodeKeyChangedID(fingerprint string) string {
	return "node-key-changed:" + fingerprint
}

// RaiseNodeKeyChanged persists a crit alert for a node whose registered key
// was replaced. It is wired to inventory.Service.SetOnNodeKeyChanged.
//
// It is a no-op with no store (the aggregator-only configuration a dev run
// uses): the change is still audited in the log by the caller, which is where
// a dev run would read it.
func (s *Service) RaiseNodeKeyChanged(ctx context.Context, change inventory.NodeKeyChange) error {
	if s.store == nil || len(change.Replaced) == 0 {
		return nil
	}
	labels := map[string]string{
		"alertname": nodeKeyChangedAlertName,
		"severity":  "critical",
		"nodeId":    change.NodeID,
		// Read back by toAlert so the UI files this under the security
		// concerns rather than among vmalert's rules.
		"source": string(proto.AlertSourceSecurity),
		// The new identity is part of what makes this alert distinct: a
		// second, different change is a second alert, not an update to one
		// the operator already acknowledged.
		"nodeKeys": change.Current.String(),
	}
	fp := fingerprintFromLabels(labels)
	saved, isNew, err := s.store.Upsert(ctx, &PersistedAlert{
		ID:          NodeKeyChangedID(fp),
		Fingerprint: fp,
		Status:      "firing",
		Severity:    proto.AlertCrit,
		Title:       fmt.Sprintf("Node %s changed its registered key", change.NodeID),
		Detail:      nodeKeyChangedDetail(change),
		Labels:      labels,
		Annotations: map[string]string{},
		StartsAt:    s.clock(),
	})
	if err != nil {
		return err
	}
	if isNew {
		s.publishChange(proto.AlertFired, saved)
	}
	return nil
}

// nodeKeyChangedDetail names what changed and what the operator should do
// about it — both readings, because the api cannot tell them apart.
func nodeKeyChangedDetail(change inventory.NodeKeyChange) string {
	purposes := make([]string, 0, len(change.Replaced))
	for _, p := range change.Replaced {
		purposes = append(purposes, fmt.Sprintf("%s (was %s, now %s)", p,
			proto.ShortFingerprint(strings.TrimPrefix(change.Previous[p], proto.BusPinPrefix)),
			proto.ShortFingerprint(strings.TrimPrefix(change.Current[p], proto.BusPinPrefix))))
	}
	sort.Strings(purposes)
	return fmt.Sprintf(
		"This node registered a different key for %s, and its HTTPS sessions under the old key were ended. "+
			"A node's keys survive a reboot and a sysupgrade, so this normally means it was reflashed. "+
			"If it was not, its join token is being used by something else: revoke the token and re-seed the node.",
		strings.Join(purposes, ", "))
}
