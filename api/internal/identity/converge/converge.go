package converge

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// HashKey is the setting holding the hash of the desired state the last
// successful converge run reached.
const HashKey = "identity.converge_hash"

// DriftAlertID is the drift alert's ID.
const DriftAlertID = "identity:converge-drift"

const (
	driftTitle      = "A sign-in setting had drifted from Rasputin's and was put back."
	keyProviderType = "org.keycloak.keys.KeyProvider"
	attrFrontendURL = "frontendUrl"
	attrAdminEvents = "adminEventsExpiration"
	webAuthnPrefix  = "webAuthnPolicy"
	// The two-factor policy's RP ID and entity name, then the passwordless
	// (second) policy's.
	rpIDKey            = "webAuthnPolicyRpId"
	rpIDSecondPolicy   = "webAuthnPolicyPasswordlessRpId"
	entityName         = "webAuthnPolicyRpEntityName"
	entitySecondPolicy = "webAuthnPolicyPasswordlessRpEntityName"
)

// Admin is the api's Admin API session as rasputin-admin (*idclient.Session).
type Admin interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// Settings is the settings store (*setup.Store). Get answers "" for a key
// that is not set.
type Settings interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// Deps is everything a Converger needs. New refuses an incomplete one.
type Deps struct {
	Admin    Admin
	Settings Settings
	// Realm is the realm converged: rasputin.
	Realm string
	// Lock is the realm lock, shared with the migrations runner.
	Lock *sync.Mutex
	// Inputs reads the facts the desired state is built from.
	Inputs func(ctx context.Context) (Inputs, error)
	// Now stamps the drift alert's Since, and nothing else.
	Now func() time.Time
	Log *slog.Logger
}

// Converger runs identity.converge's one step.
type Converger struct {
	d   Deps
	log *slog.Logger

	mu sync.Mutex
	// drift is the raised drift alert, nil for none.
	drift *proto.Alert
}

// New checks d and returns a Converger. It does no I/O.
func New(d Deps) (*Converger, error) {
	if d.Admin == nil || d.Settings == nil || d.Lock == nil || d.Inputs == nil || d.Now == nil || d.Log == nil {
		return nil, errors.New("converge: a collaborator is nil")
	}
	if d.Realm == "" {
		return nil, errors.New("converge: Deps.Realm is empty")
	}
	return &Converger{d: d, log: d.Log.With("component", "identity")}, nil
}

// stepError is a failure sentence a person reads: the runner stores a failed
// step's err.Error() as the job's error. The Admin API's detail goes to the
// log under the job's id.
type stepError string

func (e stepError) Error() string { return string(e) }

const (
	errInputs       = stepError("The sign-in settings Rasputin wants could not be read, so none was changed.")
	errSettings     = stepError("The record of the last sign-in settings check could not be read, so none was changed.")
	errRead         = stepError("The sign-in service's settings could not be read, so they were not checked.")
	errKeyMissing   = stepError("A signing key provider is missing from the sign-in service, so no setting was changed; re-creating it would replace a signing key.")
	errEntityName   = stepError("A passkey policy in the sign-in service has no name, so the passkey settings were not rewritten.")
	errWrite        = stepError("A sign-in setting could not be written back to Rasputin's.")
	errStillDiffers = stepError("A sign-in setting still differs from Rasputin's after it was written back.")
	errHashWrite    = stepError("The sign-in settings were put back, but the record of it could not be stored.")
)

// client is a client's owned fields, by its internal id. The secret is
// never decoded.
type client struct {
	ID                        string   `json:"id"`
	ClientID                  string   `json:"clientId"`
	Enabled                   *bool    `json:"enabled"`
	DirectAccessGrantsEnabled *bool    `json:"directAccessGrantsEnabled"`
	RedirectURIs              []string `json:"redirectUris"`
}

// component is a key provider.
type component struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// observed is one reading of the realm.
type observed struct {
	realm   map[string]json.RawMessage
	clients map[string]client // by client id
	keys    []component
}

// writes is what a diff calls for.
type writes struct {
	// fields are the drifted fields' names, never their values.
	fields []string
	// realm is the realm PUT's body, nil for none.
	realm map[string]any
	// clients are the client PUTs' bodies by internal id, in clientOrder.
	clients     map[string]map[string]any
	clientOrder []string
	// deletes are the fallback key providers' ids.
	deletes []string
	// missingKeys are the expected key providers absent.
	missingKeys []string
	// blankEntity is set when a WebAuthn policy must be rewritten and its
	// entity name is blank: Keycloak would replace that policy with its
	// defaults.
	blankEntity bool
}

func (c *Converger) realmPath() string { return "/admin/realms/" + url.PathEscape(c.d.Realm) }

// observe reads the realm, its clients and its key providers.
func (c *Converger) observe(ctx context.Context) (observed, error) {
	var o observed
	if _, err := c.d.Admin.Admin(ctx, http.MethodGet, c.realmPath(), nil, &o.realm); err != nil {
		return o, err
	}
	var list []client
	if _, err := c.d.Admin.Admin(ctx, http.MethodGet, c.realmPath()+"/clients", nil, &list); err != nil {
		return o, err
	}
	o.clients = map[string]client{}
	for _, cl := range list {
		o.clients[cl.ClientID] = cl
	}
	if _, err := c.d.Admin.Admin(ctx, http.MethodGet, c.realmPath()+"/components?type="+url.QueryEscape(keyProviderType), nil, &o.keys); err != nil {
		return o, err
	}
	return o, nil
}

// diff compares o with d.
func diff(d Desired, o observed) writes {
	var w writes
	realm := map[string]any{}
	drift := func(field string, value any) {
		w.fields = append(w.fields, "realm."+field)
		realm[field] = value
	}
	if str(o.realm, "displayName") != d.DisplayName {
		drift("displayName", d.DisplayName)
	}
	if str(o.realm, "displayNameHtml") != d.DisplayNameHTML {
		drift("displayNameHtml", d.DisplayNameHTML)
	}
	if boolean(o.realm, "eventsEnabled") != d.EventsEnabled {
		drift("eventsEnabled", d.EventsEnabled)
	}
	if !sameSet(list(o.realm, "eventsListeners"), d.EventsListeners) {
		drift("eventsListeners", d.EventsListeners)
	}
	if !sameSet(list(o.realm, "enabledEventTypes"), d.EnabledEventTypes) {
		drift("enabledEventTypes", d.EnabledEventTypes)
	}
	if integer(o.realm, "eventsExpiration") != d.EventsExpirySeconds {
		drift("eventsExpiration", d.EventsExpirySeconds)
	}
	if boolean(o.realm, "adminEventsEnabled") != d.AdminEventsEnabled {
		drift("adminEventsEnabled", d.AdminEventsEnabled)
	}
	if boolean(o.realm, "adminEventsDetailsEnabled") != d.AdminEventsDetailsEnabled {
		drift("adminEventsDetailsEnabled", d.AdminEventsDetailsEnabled)
	}
	var smtp map[string]any
	_ = json.Unmarshal(o.realm["smtpServer"], &smtp)
	if len(smtp) != 0 {
		drift("smtpServer", d.SMTPServer)
	}

	// attributes: sent only when an owned attribute must change, and then as
	// the whole map as read, because Keycloak removes every attribute a sent
	// map leaves out.
	var attrs map[string]json.RawMessage
	_ = json.Unmarshal(o.realm["attributes"], &attrs)
	_, hasFrontend := attrs[attrFrontendURL]
	adminExpiry := str(attrs, attrAdminEvents)
	if hasFrontend || adminExpiry != d.AdminEventsExpirySeconds {
		out := map[string]json.RawMessage{}
		maps.Copy(out, attrs)
		if hasFrontend {
			w.fields = append(w.fields, "realm.attributes."+attrFrontendURL)
			delete(out, attrFrontendURL)
		}
		if adminExpiry != d.AdminEventsExpirySeconds {
			w.fields = append(w.fields, "realm.attributes."+attrAdminEvents)
			v, _ := json.Marshal(d.AdminEventsExpirySeconds)
			out[attrAdminEvents] = v
		}
		realm["attributes"] = out
	}

	// WebAuthn: Keycloak applies a policy only with a non-empty entity name,
	// and then rebuilds it from the request with defaults for every field
	// left out. So each policy is sent whole, as read, with only its RP ID
	// cleared.
	rpDrift := str(o.realm, rpIDKey) != d.WebAuthnRPID
	pwDrift := str(o.realm, rpIDSecondPolicy) != d.WebAuthnPasswordlessRPID
	if rpDrift || pwDrift {
		if rpDrift {
			w.fields = append(w.fields, "realm."+rpIDKey)
		}
		if pwDrift {
			w.fields = append(w.fields, "realm."+rpIDSecondPolicy)
		}
		w.blankEntity = strings.TrimSpace(str(o.realm, entityName)) == "" || strings.TrimSpace(str(o.realm, entitySecondPolicy)) == ""
		for k, v := range o.realm {
			if strings.HasPrefix(k, webAuthnPrefix) {
				realm[k] = v
			}
		}
		realm[rpIDKey] = d.WebAuthnRPID
		realm[rpIDSecondPolicy] = d.WebAuthnPasswordlessRPID
	}
	if len(realm) > 0 {
		w.realm = realm
	}

	// Clients: one partial body per drifted client, the owned fields only.
	w.clients = map[string]map[string]any{}
	addClient := func(cl client, field string, value any) {
		w.fields = append(w.fields, "client."+cl.ClientID+"."+field)
		body, ok := w.clients[cl.ID]
		if !ok {
			body = map[string]any{}
			w.clients[cl.ID] = body
			w.clientOrder = append(w.clientOrder, cl.ID)
		}
		body[field] = value
	}
	for _, id := range d.DisabledClients {
		cl, ok := o.clients[id]
		if !ok {
			continue // nothing to disable
		}
		if cl.Enabled == nil || *cl.Enabled {
			addClient(cl, "enabled", false)
		}
		if id == "admin-cli" && (cl.DirectAccessGrantsEnabled == nil || *cl.DirectAccessGrantsEnabled) {
			addClient(cl, "directAccessGrantsEnabled", false)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(d.RedirectURIs)) {
		want := d.RedirectURIs[id]
		cl, ok := o.clients[id]
		if !ok {
			// It cannot be written; the read-back reports it again and
			// fails the run.
			w.fields = append(w.fields, "client."+id+".missing")
			continue
		}
		if !sameSet(cl.RedirectURIs, want) {
			addClient(cl, "redirectUris", want)
		}
	}

	// Key providers.
	present := map[string]bool{}
	for _, k := range o.keys {
		present[k.Name] = true
		if strings.HasPrefix(k.Name, fallbackPrefix) {
			w.fields = append(w.fields, "keys."+k.Name)
			w.deletes = append(w.deletes, k.ID)
		}
	}
	for _, name := range d.KeyProviders {
		if !present[name] {
			w.missingKeys = append(w.missingKeys, name)
		}
	}
	return w
}

// Run is RunJob outside a job.
func (c *Converger) Run(ctx context.Context) ([]string, error) { return c.RunJob(ctx, "") }

// RunJob holds the realm lock, reads the realm, writes only what drifted,
// reads it all back and stores the desired state's hash. It returns the
// repaired fields' names. jobID names the job in its log records.
func (c *Converger) RunJob(ctx context.Context, jobID string) ([]string, error) {
	c.d.Lock.Lock()
	defer c.d.Lock.Unlock()
	fail := func(e stepError, msg string, err error, extra ...slog.Attr) ([]string, error) {
		c.logFailure(ctx, jobID, msg, err, extra...)
		return nil, e
	}
	in, err := c.d.Inputs(ctx)
	if err != nil {
		return fail(errInputs, "The desired sign-in settings could not be read.", err)
	}
	desired := NewDesired(in)
	hash := desired.Hash()
	stored, err := c.d.Settings.Get(ctx, HashKey)
	if err != nil {
		return fail(errSettings, "The converge record could not be read.", err)
	}
	o, err := c.observe(ctx)
	if err != nil {
		return fail(errRead, "The sign-in service's settings could not be read.", err)
	}
	w := diff(desired, o)
	if len(w.missingKeys) > 0 {
		return fail(errKeyMissing, "A signing key provider is missing; nothing was written.", nil,
			slog.Any("key_providers", w.missingKeys))
	}
	if w.blankEntity {
		return fail(errEntityName, "A WebAuthn policy's entity name is blank; nothing was written.", nil)
	}
	if err := c.write(ctx, w); err != nil {
		return fail(errWrite, "A sign-in setting could not be written.", err, slog.Any("fields", w.fields))
	}
	after, err := c.observe(ctx)
	if err != nil {
		return fail(errRead, "The sign-in service's settings could not be read back.", err)
	}
	if left := diff(desired, after); len(left.fields) > 0 || len(left.missingKeys) > 0 {
		return fail(errStillDiffers, "A sign-in setting still differs after converge wrote it.", nil,
			slog.Any("fields", left.fields), slog.Any("key_providers", left.missingKeys))
	}
	if err := c.d.Settings.Set(ctx, HashKey, hash); err != nil {
		return fail(errHashWrite, "The converge record could not be stored.", err)
	}
	c.settle(ctx, jobID, w.fields, stored == hash)
	return w.fields, nil
}

// write makes w's writes: one realm PUT, one PUT per drifted client and one
// DELETE per fallback key provider.
func (c *Converger) write(ctx context.Context, w writes) error {
	if w.realm != nil {
		if _, err := c.d.Admin.Admin(ctx, http.MethodPut, c.realmPath(), w.realm, nil); err != nil {
			return err
		}
	}
	for _, id := range w.clientOrder {
		if _, err := c.d.Admin.Admin(ctx, http.MethodPut, c.realmPath()+"/clients/"+url.PathEscape(id), w.clients[id], nil); err != nil {
			return err
		}
	}
	for _, id := range w.deletes {
		if _, err := c.d.Admin.Admin(ctx, http.MethodDelete, c.realmPath()+"/components/"+url.PathEscape(id), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// settle logs a successful run's repairs and raises or clears the drift
// alert. Repairs while the stored hash equals the desired one are drift:
// nothing Rasputin changed explains them, so they WARN and raise the alert.
// Repairs on the first run, or after an input changed, are INFO. A clean run
// clears the alert.
func (c *Converger) settle(ctx context.Context, jobID string, fields []string, sameHash bool) {
	attrs := []slog.Attr{slog.String("job_id", jobID), slog.Any("fields", fields)}
	switch {
	case len(fields) == 0:
		c.mu.Lock()
		c.drift = nil
		c.mu.Unlock()
	case sameHash:
		c.log.LogAttrs(ctx, slog.LevelWarn, "Sign-in settings had drifted and were put back.",
			append([]slog.Attr{slog.String("event", "identity.converge.drift")}, attrs...)...)
		c.mu.Lock()
		c.drift = &proto.Alert{
			ID: DriftAlertID, Severity: proto.AlertWarn, Source: proto.AlertSourceSecurity,
			Title: driftTitle, Detail: driftTitle, Since: c.d.Now(), RelatedKind: "accounts",
		}
		c.mu.Unlock()
	default:
		c.log.LogAttrs(ctx, slog.LevelInfo, "Sign-in settings were set to Rasputin's.",
			append([]slog.Attr{slog.String("event", "identity.converge.repaired")}, attrs...)...)
	}
}

// Alerts is the drift alert while it is raised.
func (c *Converger) Alerts(context.Context, time.Time) []proto.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.drift == nil {
		return nil
	}
	return []proto.Alert{*c.drift}
}

// Pending reports the desired state's hash and the stored one, for the
// trigger.
func (c *Converger) Pending(ctx context.Context) (desired, stored string, err error) {
	in, err := c.d.Inputs(ctx)
	if err != nil {
		return "", "", err
	}
	stored, err = c.d.Settings.Get(ctx, HashKey)
	if err != nil {
		return "", "", err
	}
	return NewDesired(in).Hash(), stored, nil
}

// logFailure writes the one ERROR of a failed run, with the Admin API's
// detail when err carries it. It never logs a value.
func (c *Converger) logFailure(ctx context.Context, jobID, msg string, err error, extra ...slog.Attr) {
	attrs := append([]slog.Attr{slog.String("event", "identity.converge.failed"), slog.String("job_id", jobID)}, extra...)
	var ie *idclient.Error
	switch {
	case errors.As(err, &ie):
		attrs = append(attrs, ie.LogAttrs()...)
	case err != nil:
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	c.log.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}

// ----- reading a representation --------------------------------------------

func str(m map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(m[k], &s)
	return s
}

func boolean(m map[string]json.RawMessage, k string) bool {
	var b bool
	_ = json.Unmarshal(m[k], &b)
	return b
}

func integer(m map[string]json.RawMessage, k string) int {
	var n int
	_ = json.Unmarshal(m[k], &n)
	return n
}

func list(m map[string]json.RawMessage, k string) []string {
	var s []string
	_ = json.Unmarshal(m[k], &s)
	return s
}

// sameSet reports whether a and b hold the same strings, ignoring order.
func sameSet(a, b []string) bool {
	return slices.Equal(sorted(a), sorted(b))
}
