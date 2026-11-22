package alerts

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The "admin client restored" alert (geekdojo/geekdojo-brain#1127,
// Identity 2.8).
//
// identity.recover_admin re-created the control plane's admin client at the
// sign-in service from the shipped baseline. Nothing in Rasputin removes that
// client, so the operator has to see that it happened. Like node-key-changed
// it is an event, not a state, so it is persisted rather than derived on
// read: one row per job, which the operator acknowledges.

// identityAdminRestoredAlertName is the alertname label.
const identityAdminRestoredAlertName = "IdentityAdminRestored"

// IdentityAdminRestoredID is the persisted alert's id for one job's labels.
func IdentityAdminRestoredID(fingerprint string) string {
	return "identity-admin-restored:" + fingerprint
}

const (
	identityAdminRestoredTitle  = "The control plane's admin client at the sign-in service was restored."
	identityAdminRestoredDetail = "The control plane was refused as its sign-in service's administrator, so it re-created its admin client from the shipped baseline. Nothing in Rasputin removes that client; see Tasks for the run."
)

// RaiseIdentityAdminRestored persists a warning security alert for the
// identity.recover_admin job jobID that succeeded. Raising it again for the
// same job changes nothing the operator sees. It is a no-op with no store,
// as RaiseNodeKeyChanged is.
func (s *Service) RaiseIdentityAdminRestored(ctx context.Context, jobID string) error {
	if s.store == nil {
		return nil
	}
	labels := map[string]string{
		"alertname": identityAdminRestoredAlertName,
		"severity":  "warning",
		"source":    string(proto.AlertSourceSecurity),
		"jobId":     jobID,
	}
	fp := fingerprintFromLabels(labels)
	return s.raisePersisted(ctx, &PersistedAlert{
		ID:          IdentityAdminRestoredID(fp),
		Fingerprint: fp,
		Status:      "firing",
		Severity:    proto.AlertWarn,
		Title:       identityAdminRestoredTitle,
		Detail:      identityAdminRestoredDetail,
		Labels:      labels,
		Annotations: map[string]string{},
		StartsAt:    s.clock(),
	})
}
