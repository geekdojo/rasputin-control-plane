package alerts

import (
	"context"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The "tailnet device renamed" alert (geekdojo/geekdojo-brain#983).
//
// A tailnet device whose given name, its MagicDNS name, was a label the
// sign-in doors reserve is renamed by the mesh reconcile to <label>-<hsID>.
// The condition is gone the moment the rename lands, so this is an event,
// not a state, and is persisted and acknowledgeable like NodeKeyChanged
// (node_key.go): the operator learns the device's name changed and why.

// tailnetDeviceRenamedAlertName is the alertname label and the row's id prefix.
const tailnetDeviceRenamedAlertName = "TailnetDeviceRenamed"

// TailnetDeviceRenamedID is the persisted alert's id for one rename.
func TailnetDeviceRenamedID(fingerprint string) string {
	return "tailnet-device-renamed:" + fingerprint
}

// RaiseTailnetDeviceRenamed persists a warn alert naming the renamed device
// and both its names. A no-op with no store, as RaiseNodeKeyChanged is; the
// mesh reconcile has already logged the rename at WARN.
func (s *Service) RaiseTailnetDeviceRenamed(ctx context.Context, hsID, from, to string) error {
	if s.store == nil {
		return nil
	}
	labels := map[string]string{
		"alertname": tailnetDeviceRenamedAlertName,
		"severity":  "warning",
		"source":    string(proto.AlertSourceSecurity),
		"hsId":      hsID,
		"from":      from,
		"to":        to,
	}
	fp := fingerprintFromLabels(labels)
	return s.raisePersisted(ctx, &PersistedAlert{
		ID:          TailnetDeviceRenamedID(fp),
		Fingerprint: fp,
		Status:      "firing",
		Severity:    proto.AlertWarn,
		Title:       fmt.Sprintf("Tailnet device %s renamed to %s", from, to),
		Detail: fmt.Sprintf("The private-network device %s (id %s) was named %s, a name kept for the cluster's sign-in addresses, "+
			"so it was renamed to %s. Reach it by its new name.", from, hsID, from, to),
		Labels:      labels,
		Annotations: map[string]string{},
		StartsAt:    s.clock(),
	})
}
