// Package markers keeps the per-door second-step markers on accounts
// (geekdojo/geekdojo-brain#987, Identity 4.5; identity-authz.md §5.1): the
// admin-only attributes the sign-in flows' conditions read to ask for a
// second step only where the account can answer it.
//
// Writer sets them from each drained credential event (a user-event sink of
// the sign-in history drain) and, for the Jobs that make an account
// privileged (Identity 4.8 and 6.3), from the account's credentials before
// the role takes effect (BeforePrivilege). Markers are only ever set here,
// never cleared: removing a credential is Identity 4.12's.
//
// Nothing here logs a user id.
package markers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// MetricMarkerCorrections is the counter of marker writes that changed a
// marker (Corrections).
const MetricMarkerCorrections = "rasputin_identity_marker_corrections_total"

// ErrNoSecondStep is BeforePrivilege's answer for an account that holds no
// authenticator app, passkey or security key: it must not be made
// privileged.
var ErrNoSecondStep = errors.New("markers: the account holds no second step")

// The credential types (Keycloak 26.8.2's credential type names).
const (
	typeOTP          = "otp"
	typeWebAuthn     = "webauthn"
	typePasswordless = "webauthn-passwordless"
)

// profileFields are the user profile's own fields a user PUT carries.
var profileFields = []string{"username", "email", "firstName", "lastName"}

// The user events that store a credential.
var credentialEvents = []string{"UPDATE_CREDENTIAL", "UPDATE_TOTP"}

// Admin is the Admin API session (*idclient.Session).
type Admin interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// Deps are a Writer's collaborators. New refuses a missing one.
type Deps struct {
	Admin Admin
	// Realm is the realm the accounts are in: rasputin.
	Realm string
	// DoorOf is the door a client belongs to; false for a client no door
	// serves.
	DoorOf func(clientID string) (flows.Door, bool)
	Log    *slog.Logger
}

// Writer writes the markers.
type Writer struct {
	d           Deps
	log         *slog.Logger
	corrections atomic.Uint64

	mu   sync.Mutex
	down bool
}

// New checks d and returns a Writer. It does no I/O.
func New(d Deps) (*Writer, error) {
	switch {
	case d.Admin == nil:
		return nil, errors.New("markers: Deps.Admin is nil")
	case d.Realm == "":
		return nil, errors.New("markers: Deps.Realm is empty")
	case d.DoorOf == nil:
		return nil, errors.New("markers: Deps.DoorOf is nil")
	case d.Log == nil:
		return nil, errors.New("markers: Deps.Log is nil")
	}
	return &Writer{d: d, log: d.Log.With("component", "identity")}, nil
}

// Corrections counts the writes that changed a marker.
func (w *Writer) Corrections() uint64 { return w.corrections.Load() }

var _ events.UserSink = (*Writer)(nil)

// UserEvent sets the markers a stored credential calls for: a passkey or
// security key sets its door's webauthn and second-step markers; an
// authenticator app sets both doors' second-step markers; either sets
// rasputin_second_step_any. A privileged account's two second-step markers
// follow rasputin_second_step_any. Recovery codes and passwords set nothing.
func (w *Writer) UserEvent(ctx context.Context, e events.UserEvent) {
	if !slices.Contains(credentialEvents, e.Type) || e.UserID == "" {
		return
	}
	set := map[string]bool{}
	switch e.CredentialType {
	case typeWebAuthn, typePasswordless:
		door, ok := w.d.DoorOf(e.ClientID)
		if e.ClientID == "" || !ok {
			w.log.LogAttrs(ctx, slog.LevelWarn, "A passkey was stored at a client no door serves, so no marker was set.",
				slog.String("event", "identity.markers.no_door"), slog.String("client_id", e.ClientID))
			return
		}
		set[flows.WebAuthnMarker(door)] = true
		set[flows.SecondStepMarker(door)] = true
	case typeOTP:
		set[flows.MarkerSecondStepHome] = true
		set[flows.MarkerSecondStepApp] = true
	default:
		return
	}
	set[flows.MarkerSecondStepAny] = true
	err := w.apply(ctx, e.UserID, set, true)
	w.outage(ctx, err)
}

// BeforePrivilege sets both doors' second-step markers and
// rasputin_second_step_any from the account's credentials, before a Job
// makes it privileged. It returns ErrNoSecondStep, writing nothing, when the
// account holds no authenticator app, passkey or security key.
func (w *Writer) BeforePrivilege(ctx context.Context, userID string) error {
	var creds []struct {
		Type string `json:"type"`
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, w.userPath(userID)+"/credentials", nil, &creds); err != nil {
		return fmt.Errorf("markers: read the account's credentials: %w", err)
	}
	if !slices.ContainsFunc(creds, func(c struct {
		Type string `json:"type"`
	}) bool {
		return c.Type == typeOTP || c.Type == typeWebAuthn || c.Type == typePasswordless
	}) {
		return ErrNoSecondStep
	}
	set := map[string]bool{flows.MarkerSecondStepHome: true, flows.MarkerSecondStepApp: true, flows.MarkerSecondStepAny: true}
	if err := w.apply(ctx, userID, set, false); err != nil {
		return fmt.Errorf("markers: write the account's markers: %w", err)
	}
	return nil
}

func (w *Writer) userPath(userID string) string {
	return "/admin/realms/" + url.PathEscape(w.d.Realm) + "/users/" + url.PathEscape(userID)
}

// apply reads the account, sets each marker in set to true (and, with
// follow, a privileged account's two second-step markers once it holds
// rasputin_second_step_any), and writes the account back, its other
// attributes as read, only when a marker changed.
func (w *Writer) apply(ctx context.Context, userID string, set map[string]bool, follow bool) error {
	var user map[string]any
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, w.userPath(userID), nil, &user); err != nil {
		return err
	}
	attrs, _ := user["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	if follow {
		privileged, err := w.privileged(ctx, userID, attrs)
		if err != nil {
			return err
		}
		if privileged {
			set[flows.MarkerSecondStepHome] = true
			set[flows.MarkerSecondStepApp] = true
		}
	}
	changed := false
	for name := range set {
		if !holds(attrs, name, "true") {
			attrs[name] = []any{"true"}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	// Only the profile's fields go back, as read, with the attributes: a
	// whole representation would also write back the required actions as
	// read, undoing one the account completed meanwhile.
	body := map[string]any{"attributes": attrs}
	for _, k := range profileFields {
		if v, ok := user[k]; ok {
			body[k] = v
		}
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodPut, w.userPath(userID), body, nil); err != nil {
		return err
	}
	w.corrections.Add(1)
	return nil
}

// privileged reports whether the account is privileged: console admin or
// operator, app admin, or gear-admin.
func (w *Writer) privileged(ctx context.Context, userID string, attrs map[string]any) (bool, error) {
	if holds(attrs, "rasputin_app_role", "admin") || holds(attrs, "rasputin_network", "gear-admin") {
		return true, nil
	}
	var roles []struct {
		Name string `json:"name"`
	}
	path := w.userPath(userID) + "/role-mappings/clients/"
	var clients []struct {
		ID string `json:"id"`
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(w.d.Realm)+"/clients?clientId="+
		url.QueryEscape(flows.ConsoleClient), nil, &clients); err != nil {
		return false, err
	}
	if len(clients) != 1 {
		return false, fmt.Errorf("markers: %d console clients", len(clients))
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, path+url.PathEscape(clients[0].ID)+"/composite", nil, &roles); err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Name == "admin" || r.Name == "operator" {
			return true, nil
		}
	}
	return false, nil
}

// holds reports whether the attribute name holds value.
func holds(attrs map[string]any, name, value string) bool {
	vs, _ := attrs[name].([]any)
	return slices.ContainsFunc(vs, func(v any) bool { s, _ := v.(string); return s == value })
}

// outage logs an Admin API failure at WARN once per run of failures, with
// no user id, and clears the flag on success.
func (w *Writer) outage(ctx context.Context, err error) {
	w.mu.Lock()
	first := err != nil && !w.down
	w.down = err != nil
	w.mu.Unlock()
	if !first {
		return
	}
	attrs := []slog.Attr{slog.String("event", "identity.markers.write_failed")}
	// An Admin API error's path names the account, so only its status and
	// kind are logged.
	var ie *idclient.Error
	if errors.As(err, &ie) {
		attrs = append(attrs, slog.Int("status", ie.Status), slog.String("err", fmt.Sprint(ie.Kind)))
	} else {
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	w.log.LogAttrs(ctx, slog.LevelWarn, "A sign-in marker could not be written; the next credential event writes it.", attrs...)
}
