package signinname

import (
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The responder's alert IDs.
const (
	AlertConflict    = "signin-name:conflict"
	AlertUnpublished = "signin-name:unpublished"
	AlertRefused     = "signin-name:refused"
)

// State classifies the current facts at now. It is computed when read.
func (r *Responder) State(now time.Time) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return classify(r.f, now)
}

// MetricState is the state for the rasputin_signin_name_state metric, and
// false on a nil Responder.
func (r *Responder) MetricState(now time.Time) (string, bool) {
	if r == nil {
		return "", false
	}
	return string(r.State(now).State), true
}

// Alerts is the responder's alert at now, or none: crit, source security.
// Probing and announcing raise nothing.
func (r *Responder) Alerts(now time.Time) []proto.Alert {
	st := r.State(now)
	a := proto.Alert{Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity, Since: st.Since}
	switch {
	case st.State == StateConflict:
		a.ID = AlertConflict
		a.Title = fmt.Sprintf("Another device on your network is using this system's sign-in address, %s, at %s. Turn that device off or rename it.", r.host, st.Owner)
		a.Detail = a.Title
	case st.State != StateUnpublished || st.Cause == CauseProbing:
		return nil
	case st.Cause == CauseRefused:
		a.ID = AlertRefused
		a.Title, a.Detail = refusedSentences(r.clusterID, r.reason)
	default:
		a.ID = AlertUnpublished
		a.Title = fmt.Sprintf("Sign-in isn't reachable: this system's sign-in address, %s, is not being published.", r.host)
		a.Detail = causeDetail[st.Cause]
	}
	return []proto.Alert{a}
}

// causeDetail is the unpublished alert's Detail for each cause it is raised
// for.
var causeDetail = map[Cause]string{
	CauseNoAddress:  "The control plane has no LAN address.",
	CauseOpenFailed: "The sign-in name responder could not open its network socket.",
	CauseStopped:    "The sign-in name responder stopped after an internal error. Restart the control plane to publish the name again.",
}

// refusedSentences are the refused alert's title and detail for the rule the
// cluster id broke (F-995-06): the design's sentence for the two cluster-id
// rules, and its own for an id that is not a label.
func refusedSentences(id string, reason error) (title, detail string) {
	const prefixTitle = "This cluster's name can't carry a sign-in address. Re-provision it with a cluster id that does not start with sso- and has at most 59 characters."
	switch {
	case errors.Is(reason, proto.ErrClusterIDTooLong):
		return prefixTitle, fmt.Sprintf("The cluster id %q is %d characters, and a cluster id may have at most %d so that its sign-in address fits in one DNS label.", id, len(id), proto.ClusterIDMaxLen)
	case errors.Is(reason, proto.ErrClusterIDReservedPrefix):
		return prefixTitle, fmt.Sprintf("The cluster id %q starts with sso-, which is reserved for sign-in addresses.", id)
	case errors.Is(reason, doors.ErrNotLabel):
		return "This cluster's name can't carry a sign-in address. Re-provision it with a cluster id made only of lowercase letters, digits and hyphens.",
			fmt.Sprintf("The cluster id %q is not a lowercase DNS label.", id)
	}
	return prefixTitle, fmt.Sprintf("The cluster id %q was refused.", id)
}
