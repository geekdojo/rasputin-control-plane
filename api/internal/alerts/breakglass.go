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
	breakGlassRedeemedDetail = "A repair session can read the sign-in service's state and restart it, reset one administrator's or designated account's sign-in once, and, only while sign-in has lost its accounts and this cluster still has the ones from before the sign-in update, bring those back. Every other part of the console refuses it. It ends when it is ended on the repair page, when an administrator signs in normally, or when the control plane's api restarts."

	breakGlassResetAlertName = "BreakGlassSignInReset"
	breakGlassResetTitle     = "A break-glass repair reset an administrator's sign-in."
	breakGlassResetDetail    = "A repair session removed this account's second steps, recovery codes and roles and set a temporary password. Its roles come back once it has signed in, chosen a new password, added a passkey, security key or authenticator app and saved new recovery codes. If nobody here asked for this, treat the control plane as compromised."

	// LostAccountsAlertID is C9's lost-accounts alert's id.
	LostAccountsAlertID    = "identity:blank"
	lostAccountsAlertTitle = "Sign-in has lost its accounts, but this cluster still has its accounts from before the sign-in update. Open a repair session with a repair code to bring them back."

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
		breakGlassIssuedTitle, breakGlassIssuedDetail, map[string]string{"eventId": eventID})
}

// RaiseBreakGlassRedeemed persists the critical alert for the repair session
// opened as event eventID.
func (s *Service) RaiseBreakGlassRedeemed(ctx context.Context, eventID string) error {
	return s.raiseBreakGlass(ctx, breakGlassRedeemedAlertName, "critical", proto.AlertCrit,
		breakGlassRedeemedTitle, breakGlassRedeemedDetail, map[string]string{"eventId": eventID})
}

// RaiseBreakGlassReset persists the critical alert for the repair reset of
// accountID, the account's opaque id, as event eventID (C1, design Appendix
// F). One row per event; raising an event again changes nothing.
func (s *Service) RaiseBreakGlassReset(ctx context.Context, eventID, accountID string) error {
	return s.raiseBreakGlass(ctx, breakGlassResetAlertName, "critical", proto.AlertCrit,
		breakGlassResetTitle, breakGlassResetDetail, map[string]string{"eventId": eventID, "accountId": accountID})
}

// raiseBreakGlass persists one event alert, labelled with extra besides its
// name, severity and source.
func (s *Service) raiseBreakGlass(ctx context.Context, name, severityLabel string, severity proto.AlertSeverity,
	title, detail string, extra map[string]string) error {
	if s.store == nil {
		return nil
	}
	labels := map[string]string{
		"alertname": name,
		"severity":  severityLabel,
		"source":    string(proto.AlertSourceSecurity),
	}
	for k, v := range extra {
		labels[k] = v
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

// LostAccounts derives C9's alert: it shows while sign-in has lost its
// accounts and this cluster still holds the ones from before the sign-in
// update (move.State.Repair's Holds), so a repair session can bring them
// back.
type LostAccounts struct {
	// Repair reports whether C9's state holds.
	Repair func(ctx context.Context) (bool, error)
}

// Alerts is the alert, or none. A read that fails raises nothing, as
// LastResort's does: an unread fact is not one.
func (l LostAccounts) Alerts(ctx context.Context, now time.Time) []proto.Alert {
	if l.Repair == nil {
		return nil
	}
	if holds, err := l.Repair(ctx); err != nil || !holds {
		return nil
	}
	return []proto.Alert{{
		ID:       LostAccountsAlertID,
		Severity: proto.AlertCrit,
		Source:   proto.AlertSourceSecurity,
		Title:    lostAccountsAlertTitle,
		Since:    now,
	}}
}

// SetLostAccountsAlerts wires C9's lost-accounts alert (LostAccounts.Alerts),
// under keycloak only. Set before List.
func (s *Service) SetLostAccountsAlerts(fn func(ctx context.Context, now time.Time) []proto.Alert) {
	s.lostAccountsAlerts = fn
}
