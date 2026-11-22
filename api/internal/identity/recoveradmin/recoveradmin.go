// Package recoveradmin is the identity.recover_admin job
// (geekdojo/geekdojo-brain#978, Identity 3.2): it re-creates the identity
// service's administrator client, rasputin-admin in realm rasputin, from the
// shipped realm baseline when it is gone or broken, and leaves no account in
// the master realm behind.
//
// Keycloak's own recovery command, kc.sh bootstrap-admin service, runs only
// while the service is stopped and makes a temporary master-realm client
// authenticated by a client secret (register row E39). The job makes that
// secret and hands it to Deps.Bootstrap, which the composition root wires to
// the OS's recovery launcher: the secret reaches the command on the
// launcher's standard input and from there only the command's own
// environment (geekdojo/geekdojo-brain#1131). The job uses the
// temporary client to put rasputin-admin back exactly as the baseline
// declares it, deletes every temporary client, and reports restored only
// once rasputin-admin itself has logged in by client-x509 and read the realm.
//
// It is a System workflow: the runner refuses it from POST /api/jobs. The
// Trigger (trigger.go, geekdojo/geekdojo-brain#1127, Identity 2.8) is what
// submits it, on the fact that the identity service is ready and refuses the
// api's own admin login.
package recoveradmin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Kind is the job kind.
const Kind = "identity.recover_admin"

const (
	// realm and adminClient are the baseline's realm and its administrator
	// client.
	realm       = "rasputin"
	adminClient = adminguard.AdminClientID
	// realmManagement is the client whose roles the administrator holds.
	realmManagement = "realm-management"
	// masterRealm is where bootstrap-admin makes its temporary client.
	masterRealm = "master"
	// TempClientPrefix starts every temporary client's id; the job's id
	// follows it.
	TempClientPrefix = "rasputin-recover-"
	// secretBytes is how many random bytes the temporary secret carries.
	secretBytes = 32
)

// identityAPI is the identity client as the job uses it.
type identityAPI interface {
	ClientCredentials(ctx context.Context, realm, clientID string, clientSecret *secret.Value) (secret.Value, error)
	Admin(ctx context.Context, token secret.Value, method, path string, in, out any) (idclient.Response, error)
	Ready(ctx context.Context) error
}

// units is the identity service's systemd unit.
type units interface {
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
	Active(ctx context.Context) (bool, error)
}

// Deps is everything a Recoverer needs. New refuses an incomplete one.
type Deps struct {
	Identity identityAPI
	Units    units
	// Unit names the unit in records.
	Unit string
	// Bootstrap runs Keycloak's bootstrap-admin service command for the
	// temporary client id with clientSecret as its secret. It must not keep
	// or destroy clientSecret: the step logs in with it afterwards.
	Bootstrap func(ctx context.Context, clientID string, clientSecret secret.Value) error
	// ReadBaseline returns the shipped realm baseline, the administrator
	// client's only source.
	ReadBaseline func() ([]byte, error)
	// Rand makes the temporary secret.
	Rand io.Reader
	// Restored raises the persisted "admin client restored" alert for a job
	// that succeeded. Its error is logged; the job's outcome stands.
	Restored func(ctx context.Context, jobID string) error
	Log      *slog.Logger
	// StepTimeout bounds the one step; it marks work gone far outside
	// normal and decides nothing else.
	StepTimeout time.Duration
}

// Recoverer runs identity.recover_admin.
type Recoverer struct{ d Deps }

// New checks d and returns a Recoverer. It does no I/O.
func New(d Deps) (*Recoverer, error) {
	switch {
	case d.Identity == nil || d.Units == nil || d.Bootstrap == nil || d.ReadBaseline == nil || d.Rand == nil || d.Restored == nil || d.Log == nil:
		return nil, errors.New("recoveradmin: a collaborator is nil")
	case d.Unit == "":
		return nil, errors.New("recoveradmin: Deps.Unit is empty")
	case d.StepTimeout <= 0:
		return nil, fmt.Errorf("recoveradmin: Deps.StepTimeout %v is not positive", d.StepTimeout)
	}
	return &Recoverer{d: d}, nil
}

// Workflow is the job's one step. It is Irreversible, so it is never retried
// and never replayed, and System, so no operator can start it. A job that
// succeeds raises the restored alert once, from OnTerminal.
func (r *Recoverer) Workflow() jobs.Workflow {
	return jobs.Workflow{Kind: Kind, System: true, Steps: []jobs.WorkflowStep{
		{Name: "restore", Do: r.restore, Timeout: r.d.StepTimeout, Retries: 0, Irreversible: true},
	}, OnTerminal: r.terminal}
}

// terminal raises the restored alert for a job that succeeded. A failed job
// is recorded by the ledger and its job-failed alert, so it raises nothing
// here.
func (r *Recoverer) terminal(ctx context.Context, jobID string, success bool, _ string) {
	if !success {
		return
	}
	if err := r.d.Restored(ctx, jobID); err != nil {
		r.d.Log.ErrorContext(ctx, "The admin client restored alert was not raised.",
			"component", "identity", "job_id", jobID, "err", err.Error())
	}
}

// stepError is a failure sentence a person reads: the runner stores a failed
// step's err.Error() as the job's error. It never carries a command's output
// or a service's answer; those go to the logger under the job's id.
type stepError string

func (e stepError) Error() string { return string(e) }

const (
	errBaseline = stepError("The sign-in baseline could not be read, so the admin client was not restored.")
	errSecret   = stepError("The temporary recovery secret could not be made, so the admin client was not restored.")
	errStop     = stepError("The identity service could not be stopped, so the admin client was not restored.")
	errCommand  = stepError("The identity service's recovery command failed, so the admin client was not restored.")
	errNotReady = stepError("The identity service did not become ready after the recovery, so the admin client was not restored.")
	errRecreate = stepError("The admin client could not be re-created.")
	errCleanup  = stepError("The admin client was restored, but the temporary recovery client could not be removed.")
)

// result is the step's recorded outcome.
type result struct {
	Restored bool `json:"restored"`
}

// baselineAdmin is what the baseline declares for the administrator client.
type baselineAdmin struct {
	client      map[string]any
	accountRole []string // realm-management roles of its service account
	scopeRoles  []string // realm-management roles in its scope
}

func (r *Recoverer) restore(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := sc.Ctx
	temp := TempClientPrefix + sc.JobID
	attrs := []any{"component", "identity", "unit", r.d.Unit, "temp_client", temp}
	fail := func(e stepError, msg string, err error) (json.RawMessage, error) {
		jobs.LogStep(r.d.Log, sc, slog.LevelError, msg, append(attrs, "err", err.Error())...)
		return nil, e
	}

	base, err := r.readBaseline()
	if err != nil {
		return fail(errBaseline, "The sign-in baseline could not be read.", err)
	}
	sec, err := r.tempSecret()
	if err != nil {
		return fail(errSecret, "The temporary recovery secret could not be made.", err)
	}
	defer sec.Destroy()

	// Every start below runs on a context the step's cancellation does not
	// reach (F-978-09): a step that timed out or was cancelled must never
	// leave the sign-in service stopped. systemctl start is bounded by the
	// unit's own TimeoutStartSec= (F-979-11). Starting an active unit does
	// nothing, so a stop that failed is followed by a start too (F-1127-05).
	startCtx := context.WithoutCancel(ctx)
	if err := r.d.Units.Stop(ctx); err != nil {
		return fail(errStop, "The identity service could not be stopped.", errors.Join(err, r.d.Units.Start(startCtx)))
	}
	jobs.LogStep(r.d.Log, sc, slog.LevelInfo, "The identity service is stopped for the admin client's recovery.",
		append(attrs, "event", "identity.recover_admin_stopped")...)

	bootErr := r.d.Bootstrap(ctx, temp, sec)
	if bootErr == nil {
		jobs.LogStep(r.d.Log, sc, slog.LevelInfo, "The identity service's recovery command made the temporary client.",
			append(attrs, "event", "identity.recover_admin_bootstrapped")...)
	}
	// The unit is started whether or not the command worked: a stopped
	// identity service is worse than the missing client.
	startErr := r.d.Units.Start(startCtx)
	if bootErr != nil {
		return fail(errCommand, "The identity service's recovery command failed.", errors.Join(bootErr, startErr))
	}
	if startErr != nil {
		return fail(errNotReady, "The identity service could not be started after the recovery command.", startErr)
	}
	if err := idclient.WaitReady(ctx, r.d.Identity, r.d.Units.Active); err != nil {
		return fail(errNotReady, "The identity service did not become ready after the recovery command.", err)
	}
	jobs.LogStep(r.d.Log, sc, slog.LevelInfo, "The identity service is ready after the recovery command.",
		append(attrs, "event", "identity.recover_admin_ready")...)

	tok, err := r.d.Identity.ClientCredentials(ctx, masterRealm, temp, &sec)
	if err != nil {
		return fail(errRecreate, "The temporary recovery client could not log in.", err)
	}
	defer tok.Destroy()

	recreateErr := r.recreate(ctx, tok, base)
	// The temporary clients go whether or not the re-creation worked; an
	// earlier run that crashed is cleaned up here too.
	cleanupErr := r.deleteTempClients(ctx, tok, temp)
	if recreateErr != nil {
		return fail(errRecreate, "The admin client could not be re-created.", errors.Join(recreateErr, cleanupErr))
	}
	if err := r.prove(ctx); err != nil {
		return fail(errRecreate, "The re-created admin client could not use the Admin API.", errors.Join(err, cleanupErr))
	}
	if cleanupErr != nil {
		return fail(errCleanup, "The temporary recovery client could not be removed.", cleanupErr)
	}
	jobs.LogStep(r.d.Log, sc, slog.LevelInfo, "The identity service's admin client is restored.",
		append(attrs, "event", "identity.recover_admin_restored")...)
	return json.Marshal(result{Restored: true})
}

// readBaseline parses the administrator client, its service account's
// realm-management roles and its scope's from the baseline. Anything missing
// is an error, before anything is stopped.
func (r *Recoverer) readBaseline() (baselineAdmin, error) {
	raw, err := r.d.ReadBaseline()
	if err != nil {
		return baselineAdmin{}, err
	}
	var b struct {
		Clients             []map[string]any `json:"clients"`
		ClientScopeMappings map[string][]struct {
			Client string   `json:"client"`
			Roles  []string `json:"roles"`
		} `json:"clientScopeMappings"`
		Users []struct {
			ServiceAccountClientID string              `json:"serviceAccountClientId"`
			ClientRoles            map[string][]string `json:"clientRoles"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return baselineAdmin{}, errors.New("the baseline is not the expected JSON")
	}
	var out baselineAdmin
	for _, c := range b.Clients {
		if id, _ := c["clientId"].(string); id == adminClient {
			out.client = c
		}
	}
	for _, m := range b.ClientScopeMappings[realmManagement] {
		if m.Client == adminClient {
			out.scopeRoles = m.Roles
		}
	}
	for _, u := range b.Users {
		if u.ServiceAccountClientID == adminClient {
			out.accountRole = u.ClientRoles[realmManagement]
		}
	}
	switch {
	case out.client == nil:
		return baselineAdmin{}, errors.New("the baseline has no " + adminClient + " client")
	case len(out.accountRole) == 0 || len(out.scopeRoles) == 0:
		return baselineAdmin{}, errors.New("the baseline grants " + adminClient + " no " + realmManagement + " roles")
	}
	return out, nil
}

// tempSecret is 32 bytes from Rand as unpadded base64url: 43 printable ASCII
// characters, which a line on stdin, an environment entry and the JVM all carry unchanged
// (F-978-01). The raw bytes and the encoding buffer are zeroed.
func (r *Recoverer) tempSecret() (secret.Value, error) {
	raw := make([]byte, secretBytes)
	defer clear(raw)
	if _, err := io.ReadFull(r.d.Rand, raw); err != nil {
		return secret.Value{}, fmt.Errorf("read the random source: %w", err)
	}
	enc := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	defer clear(enc)
	base64.RawURLEncoding.Encode(enc, raw)
	return secret.New(enc), nil
}

// adminPath is realm's Admin API path for the parts, each escaped.
func adminPath(realm string, parts ...string) string {
	escaped := make([]string, len(parts))
	for i, p := range parts {
		escaped[i] = url.PathEscape(p)
	}
	return "/admin/realms/" + url.PathEscape(realm) + "/" + strings.Join(escaped, "/")
}

// clientRef is the part of a client representation the job reads.
type clientRef struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
}

// findClients lists realm's clients whose clientId is clientID, or starts
// with it when search is set.
func (r *Recoverer) findClients(ctx context.Context, tok secret.Value, realm, clientID string, search bool) ([]clientRef, error) {
	q := url.Values{"clientId": {clientID}}
	if search {
		q.Set("search", "true")
	}
	var list []clientRef
	if _, err := r.d.Identity.Admin(ctx, tok, http.MethodGet, adminPath(realm, "clients")+"?"+q.Encode(), nil, &list); err != nil {
		return nil, fmt.Errorf("list the %s clients in %s: %w", clientID, realm, err)
	}
	return list, nil
}

// recreate deletes any surviving administrator client, creates it from the
// baseline and grants the baseline's realm-management roles to its service
// account and its scope.
func (r *Recoverer) recreate(ctx context.Context, tok secret.Value, base baselineAdmin) error {
	old, err := r.findClients(ctx, tok, realm, adminClient, false)
	if err != nil {
		return err
	}
	for _, c := range old {
		if err := r.deleteClient(ctx, tok, realm, c); err != nil {
			return err
		}
	}
	resp, err := r.d.Identity.Admin(ctx, tok, http.MethodPost, adminPath(realm, "clients"), base.client, nil)
	if err != nil {
		return fmt.Errorf("create %s: %w", adminClient, err)
	}
	id := path.Base(resp.Location)
	if resp.Location == "" || id == "" || id == "." || id == "/" {
		return fmt.Errorf("create %s: the answer named no client", adminClient)
	}
	rm, err := r.findClients(ctx, tok, realm, realmManagement, false)
	if err != nil {
		return err
	}
	if len(rm) != 1 || rm[0].ID == "" {
		return fmt.Errorf("%s: %d clients, want 1", realmManagement, len(rm))
	}
	var roles []map[string]any
	if _, err := r.d.Identity.Admin(ctx, tok, http.MethodGet, adminPath(realm, "clients", rm[0].ID, "roles"), nil, &roles); err != nil {
		return fmt.Errorf("list the %s roles: %w", realmManagement, err)
	}
	accountRoles, err := pickRoles(roles, base.accountRole)
	if err != nil {
		return err
	}
	scopeRoles, err := pickRoles(roles, base.scopeRoles)
	if err != nil {
		return err
	}
	var account struct {
		ID string `json:"id"`
	}
	if _, err := r.d.Identity.Admin(ctx, tok, http.MethodGet, adminPath(realm, "clients", id, "service-account-user"), nil, &account); err != nil {
		return fmt.Errorf("read %s's service account: %w", adminClient, err)
	}
	if account.ID == "" {
		return fmt.Errorf("%s's service account has no id", adminClient)
	}
	if _, err := r.d.Identity.Admin(ctx, tok, http.MethodPost,
		adminPath(realm, "users", account.ID, "role-mappings", "clients", rm[0].ID), accountRoles, nil); err != nil {
		return fmt.Errorf("grant %s's service account its roles: %w", adminClient, err)
	}
	if _, err := r.d.Identity.Admin(ctx, tok, http.MethodPost,
		adminPath(realm, "clients", id, "scope-mappings", "clients", rm[0].ID), scopeRoles, nil); err != nil {
		return fmt.Errorf("map %s's scope to its roles: %w", adminClient, err)
	}
	return nil
}

// pickRoles is the representations of the named roles, in the order named.
// A role the service does not have is an error.
func pickRoles(all []map[string]any, names []string) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		i := slices.IndexFunc(all, func(r map[string]any) bool { name, _ := r["name"].(string); return name == n })
		if i < 0 {
			return nil, fmt.Errorf("%s has no role %s", realmManagement, n)
		}
		out = append(out, all[i])
	}
	return out, nil
}

// deleteClient deletes one client; one already gone is not an error.
func (r *Recoverer) deleteClient(ctx context.Context, tok secret.Value, realm string, c clientRef) error {
	if c.ID == "" {
		return fmt.Errorf("a %s client in %s has no id", c.ClientID, realm)
	}
	_, err := r.d.Identity.Admin(ctx, tok, http.MethodDelete, adminPath(realm, "clients", c.ID), nil, nil)
	if err != nil && !errors.Is(err, idclient.ErrNotFound) {
		return fmt.Errorf("delete %s in %s: %w", c.ClientID, realm, err)
	}
	return nil
}

// deleteTempClients deletes every master client whose id starts with
// TempClientPrefix, this run's own last, since its token makes the calls.
func (r *Recoverer) deleteTempClients(ctx context.Context, tok secret.Value, own string) error {
	list, err := r.findClients(ctx, tok, masterRealm, TempClientPrefix, true)
	if err != nil {
		return err
	}
	slices.SortStableFunc(list, func(a, b clientRef) int {
		switch {
		case a.ClientID == own && b.ClientID != own:
			return 1
		case b.ClientID == own && a.ClientID != own:
			return -1
		}
		return 0
	})
	var errs []error
	for _, c := range list {
		if !strings.HasPrefix(c.ClientID, TempClientPrefix) {
			continue
		}
		errs = append(errs, r.deleteClient(ctx, tok, masterRealm, c))
	}
	return errors.Join(errs...)
}

// prove logs in as the administrator client by client-x509 and reads the
// realm; only a 200 proves the client is back.
func (r *Recoverer) prove(ctx context.Context) error {
	tok, err := r.d.Identity.ClientCredentials(ctx, realm, adminClient, nil)
	if err != nil {
		return fmt.Errorf("log in as %s: %w", adminClient, err)
	}
	defer tok.Destroy()
	var rep struct {
		Realm string `json:"realm"`
	}
	resp, err := r.d.Identity.Admin(ctx, tok, http.MethodGet, "/admin/realms/"+realm, nil, &rep)
	if err != nil {
		return fmt.Errorf("read realm %s as %s: %w", realm, adminClient, err)
	}
	if resp.Status != http.StatusOK || rep.Realm != realm {
		return fmt.Errorf("reading realm %s as %s answered %d for realm %q", realm, adminClient, resp.Status, rep.Realm)
	}
	return nil
}
