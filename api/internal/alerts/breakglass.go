package alerts

import (
	"context"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The break-glass alerts (geekdojo/geekdojo-brain#321).
//
// A repair code issued on the control plane and a repair session opened with
// one are events, not states, so each is persisted, one row per event, which
// the operator acknowledges: the shape of the admin-client-restored alert
// (identity_admin.go). The no-last-resort warning is a state, derived on
// read (SetLastResortAlerts).

const (
	breakGlassIssuedAlertName   = "BreakGlassCodeIssued"
	breakGlassRedeemedAlertName = "BreakGlassSessionOpened"

	breakGlassIssuedTitle    = "A break-glass code was issued on the control plane."
	breakGlassIssuedDetail   = "Someone with root on the control plane ran rasputin-api repair-code. If it wasn't you or another administrator, treat the control plane as compromised."
	breakGlassRedeemedTitle  = "A break-glass code was used to open a repair session."
	breakGlassRedeemedDetail = "A repair session can read the sign-in service's state and restart it, and nothing else. It ends when it is ended on the repair page, when an administrator signs in normally, or when the control plane's api restarts."

	// LastResortAlertID is the no-last-resort warning's id.
	LastResortAlertID    = "break-glass-no-last-resort"
	lastResortAlertTitle = "There is no last-resort way in: set a console password in Settings → Node access."
	lastResortDetail     = "If sign-in breaks, a repair code made on the control plane is the way back in, and making one needs root there: a console password or an SSH key. This control plane has neither."
)

// RaiseBreakGlassIssued persists the warning for the repair code issued as
// event eventID. Raising it again for the same event changes nothing the
// operator sees. It is a no-op with no store, as RaiseIdentityAdminRestored
// is.
func (s *Service) RaiseBreakGlassIssued(ctx context.Context, eventID string) error {
	return s.raiseBreakGlass(ctx, breakGlassIssuedAlertName, "warning", proto.AlertWarn,
		breakGlassIssuedTitle, breakGlassIssuedDetail, eventID)
}

// RaiseBreakGlassRedeemed persists the critical alert for the repair session
// opened as event eventID.
func (s *Service) RaiseBreakGlassRedeemed(ctx context.Context, eventID string) error {
	return s.raiseBreakGlass(ctx, breakGlassRedeemedAlertName, "critical", proto.AlertCrit,
		breakGlassRedeemedTitle, breakGlassRedeemedDetail, eventID)
}

func (s *Service) raiseBreakGlass(ctx context.Context, name, severityLabel string, severity proto.AlertSeverity,
	title, detail, eventID string) error {
	if s.store == nil {
		return nil
	}
	labels := map[string]string{
		"alertname": name,
		"severity":  severityLabel,
		"source":    string(proto.AlertSourceSecurity),
		"eventId":   eventID,
	}
	fp := fingerprintFromLabels(labels)
	return s.raisePersisted(ctx, &PersistedAlert{
		ID:          "break-glass:" + fp,
		Fingerprint: fp,
		Status:      "firing",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Labels:      labels,
		Annotations: map[string]string{},
		StartsAt:    s.clock(),
	})
}

// LastResort derives the no-last-resort warning: it shows while the control
// plane has no console password and its own authorized_keys holds no valid
// key line, so nobody can become root there to make a repair code.
type LastResort struct {
	// ConsoleHash is the console password's current hash id, "" when none
	// is set (console.Store.CurrentHashID).
	ConsoleHash func(ctx context.Context) (string, error)
	// KeyLines is the valid key lines of the control plane's own
	// authorized_keys (setup.AuthorizedKeyLines over the file); an absent
	// file is no lines and no error.
	KeyLines func() ([]string, error)
}

// Alerts is the warning, or none. A read that fails raises nothing: the
// warning says a fact is true, and an unread fact is not one.
func (l LastResort) Alerts(ctx context.Context, now time.Time) []proto.Alert {
	if l.ConsoleHash == nil || l.KeyLines == nil {
		return nil
	}
	if id, err := l.ConsoleHash(ctx); err != nil || id != "" {
		return nil
	}
	if keys, err := l.KeyLines(); err != nil || len(keys) > 0 {
		return nil
	}
	return []proto.Alert{{
		ID:       LastResortAlertID,
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceSecurity,
		Title:    lastResortAlertTitle,
		Detail:   lastResortDetail,
		Since:    now,
	}}
}

// SetLastResortAlerts wires the no-last-resort warning (LastResort.Alerts).
// Set before List.
func (s *Service) SetLastResortAlerts(fn func(ctx context.Context, now time.Time) []proto.Alert) {
	s.lastResortAlerts = fn
}
