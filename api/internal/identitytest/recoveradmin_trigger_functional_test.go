package identitytest

// TC-1127-15 to TC-1127-18: identity.recover_admin's trigger against the real
// pinned Keycloak with the repo's realm baseline imported
// (geekdojo/geekdojo-brain#1127, Identity 2.8). Outside bad credentials past
// the realm's brute-force threshold never make the fact; a deleted client and
// a client stripped of its roles are restored by exactly one job the real
// scheduler submits on the trigger; a failed run is not tried again.
//
// It is in package identitytest because the recovery stops the Env's
// Keycloak and runs its own kc.sh, which only the package sees. It starts an
// Env of its own, closed with proof in its cleanup. It skips without
// RASPUTIN_IDENTITY_HOME and fails instead under
// RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it. It runs
// on linux/amd64 natively, never under emulation.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// serviceAccountUser is rasputin-admin's service-account user.
const serviceAccountUser = "service-account-" + baselineAdminClient

// terminal is one OnTerminal call.
type terminal struct {
	jobID   string
	success bool
}

// triggerRig is one api process's view: a job ledger, a real runner with
// the workflow registered, the api's Admin API session and the trigger over
// it, and the alerts list.
type triggerRig struct {
	store    *jobs.Store
	runner   *jobs.Runner
	session  *idclient.Session
	trig     *recoveradmin.Trigger
	seen     *envRecovery
	terminal chan terminal
	restored chan string
	alerts   *alerts.Service
}

// inProcessNATS is a NATS server inside the test process.
func inProcessNATS(t *testing.T) *nats.Conn {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, DontListen: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		t.Fatal("the in-process NATS server never became ready")
	}
	t.Cleanup(func() { ns.Shutdown(); ns.WaitForShutdown() })
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func newTriggerRig(t *testing.T, env *Env, client *idclient.Client, readBaseline func() ([]byte, error)) *triggerRig {
	t.Helper()
	ctx, dir := t.Context(), t.TempDir()
	store, err := jobs.OpenStore(ctx, filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	r := &triggerRig{store: store, runner: jobs.NewRunner(store, inProcessNATS(t)),
		terminal: make(chan terminal, 8), restored: make(chan string, 8)}
	rec, seen := newEnvRecoverer(t, env, client, readBaseline, func(_ context.Context, jobID string) error {
		r.restored <- jobID
		return nil
	})
	r.seen = seen
	wf := rec.Workflow()
	inner := wf.OnTerminal
	wf.OnTerminal = func(ctx context.Context, jobID string, success bool, errMsg string) {
		inner(ctx, jobID, success, errMsg)
		r.terminal <- terminal{jobID: jobID, success: success}
	}
	r.runner.Register(wf)
	t.Cleanup(r.runner.Wait)

	r.session, err = idclient.NewSession(idclient.SessionConfig{
		Login: client, Admin: client, Realm: baselineRealm, ClientID: baselineAdminClient, Log: env.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.trig, err = recoveradmin.NewTrigger(recoveradmin.TriggerDeps{Ready: client, Admin: r.session, Ledger: store, Log: env.log})
	if err != nil {
		t.Fatal(err)
	}

	inv, err := inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	ap, err := apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ap.Close() })
	st, err := setup.OpenStore(ctx, filepath.Join(dir, "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	no := func(context.Context) (bool, error) { return false, nil }
	r.alerts = alerts.New(inv, store, ap, setup.NewService(st, setup.Probes{HasUsers: no, ConsoleRootSet: no}, "", "", ""), nil, nil, true)
	r.alerts.SetIdentityAlerts(r.trig.Alerts)
	return r
}

// schedule starts a real scheduler with the trigger's entry, first ticking
// at once and then every 30 seconds (the scheduler's floor). Each tick's
// count is sent on ticks when it is set.
func (r *triggerRig) schedule(t *testing.T, ticks chan<- int) *scheduler.Scheduler {
	t.Helper()
	var n atomic.Int64
	due := func(ctx context.Context) (bool, string) {
		ok, reason := r.trig.Due(ctx)
		if ticks != nil {
			ticks <- int(n.Add(1))
		}
		return ok, reason
	}
	s := scheduler.New(r.runner, []scheduler.Entry{{Kind: recoveradmin.Kind, Interval: 30 * time.Second, InitialDelay: time.Millisecond, Due: due}})
	s.Start(t.Context())
	t.Cleanup(s.Stop)
	return s
}

// waitTerminal waits for the job's outcome, bounded only by the test's
// context.
func (r *triggerRig) waitTerminal(t *testing.T) terminal {
	t.Helper()
	select {
	case got := <-r.terminal:
		return got
	case <-t.Context().Done():
		t.Fatal("the test ended before identity.recover_admin reached an outcome")
	}
	return terminal{}
}

// jobsOfKind are the ledger's identity.recover_admin jobs.
func (r *triggerRig) jobsOfKind(t *testing.T) []*jobs.Job {
	t.Helper()
	list, err := r.store.ListAllJobsByKind(t.Context(), recoveradmin.Kind)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// realmStatus is the session's GET of the realm: its status, 0 with the
// error when it failed.
func realmStatus(t *testing.T, s *idclient.Session) (int, error) {
	t.Helper()
	resp, err := s.Admin(t.Context(), http.MethodGet, "/admin/realms/"+baselineRealm, nil, nil)
	if err != nil {
		var e *idclient.Error
		if errors.As(err, &e) {
			return e.Status, err
		}
		return 0, err
	}
	return resp.Status, nil
}

// leafTLSFor is a TLS 1.3 client config presenting an identity-CA leaf with
// common name cn.
func leafTLSFor(t *testing.T, env *Env, cn string) *tls.Config {
	t.Helper()
	paths, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: cn})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: env.Roots(),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }}
}

// baselineFailureFactor is the realm baseline's brute-force threshold.
func baselineFailureFactor(t *testing.T) int {
	t.Helper()
	raw, err := readRepoBaseline()
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		BruteForceProtected bool `json:"bruteForceProtected"`
		FailureFactor       int  `json:"failureFactor"`
	}
	if err := json.Unmarshal(raw, &b); err != nil || !b.BruteForceProtected || b.FailureFactor <= 0 {
		t.Fatalf("the baseline's brute-force settings: protected %v, failureFactor %d (%v)", b.BruteForceProtected, b.FailureFactor, err)
	}
	return b.FailureFactor
}

func TestRecoverAdminTrigger_AgainstPinnedKeycloak(t *testing.T) {
	recLog, rec := logkittest.New()
	p := NewPackage(func() (Config, error) {
		cfg, err := ConfigFromEnv()
		if err != nil {
			return cfg, err
		}
		cfg.Logger = slog.New(slog.NewMultiHandler(cfg.Logger.Handler(), recLog.Handler()))
		return cfg, nil
	})
	env := p.Env(t)
	if env == nil {
		return
	}
	t.Cleanup(func() {
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("identitytest: teardown proof failed: %v", err)
		}
	})
	importBaseline(t, env)

	apiLeaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	client := productionClient(t, env, apiLeaf)
	apiHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: apiLeafTLS(t, env)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(apiHTTP.CloseIdleConnections)
	// admin is the realm's Admin API as rasputin-admin with a fresh token,
	// outside any session under test.
	admin := func(t *testing.T) adminAPI {
		t.Helper()
		tok, err := client.ClientCredentials(t.Context(), baselineRealm, baselineAdminClient, nil)
		if err != nil {
			t.Fatalf("rasputin-admin login: %v", err)
		}
		defer tok.Destroy()
		return adminAPI{t: t, client: apiHTTP, base: env.KeycloakURL() + "/admin/realms/" + baselineRealm, token: string(tok.Reveal())}
	}
	// serviceAccountID is rasputin-admin's service-account user's id.
	serviceAccountID := func(api adminAPI) string {
		api.t.Helper()
		id, _ := api.clientRep(baselineAdminClient)
		_, out := api.must(http.StatusOK, http.MethodGet, "/clients/"+id+"/service-account-user", nil)
		var u struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		}
		if err := json.Unmarshal(out, &u); err != nil || u.ID == "" || u.Username != serviceAccountUser {
			api.t.Fatalf("rasputin-admin's service account = %q %q (%v)", u.ID, u.Username, err)
		}
		return u.ID
	}

	t.Run("TC-1127-15 outside bad credentials past the brute-force threshold never make the fact", func(t *testing.T) {
		r := newTriggerRig(t, env, client, readRepoBaseline)
		n := baselineFailureFactor(t) + 1
		ctx := t.Context()

		doorLeaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-door"})
		if err != nil {
			t.Fatal(err)
		}
		door := productionClient(t, env, doorLeaf)
		d := tlsca.Deps{Now: env.h.cfg.Now, Rand: env.h.cfg.Rand, Log: env.log}
		foreignCA, err := tlsca.Ensure(caConfig(), filepath.Join(t.TempDir(), "foreign"), "foreign", d)
		if err != nil {
			t.Fatal(err)
		}
		foreignLeaf, err := foreignCA.MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
		if err != nil {
			t.Fatal(err)
		}
		foreign := productionClient(t, env, foreignLeaf)
		bogus, err := randomSecret(env.h.cfg.Rand)
		if err != nil {
			t.Fatal(err)
		}
		defer bogus.Destroy()
		wrong, err := randomSecret(env.h.cfg.Rand)
		if err != nil {
			t.Fatal(err)
		}
		defer wrong.Destroy()

		doorTLS := leafTLSFor(t, env, "rasputin-door")
		doorTransport := &http.Transport{TLSClientConfig: doorTLS}
		t.Cleanup(doorTransport.CloseIdleConnections)
		doorHTTP := &http.Client{Transport: doorTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

		// The login form's client needs a redirect URI, which the baseline
		// leaves to the cluster (TC-980-13), as TC-980-25 sets it.
		api := admin(t)
		consoleID, consoleRep := api.clientRep(baselineConsole)
		consoleRep["redirectUris"] = []string{RedirectURI}
		api.must(http.StatusNoContent, http.MethodPut, "/clients/"+consoleID, consoleRep)
		form, err := signin.New(signin.Config{Transport: doorTransport, Issuer: env.KeycloakURL() + "/realms/" + baselineRealm,
			ClientID: baselineConsole, RedirectURI: RedirectURI, Rand: env.h.cfg.Rand, Logger: env.log})
		if err != nil {
			t.Fatal(err)
		}

		counts := map[string]int{}
		refusedLogin := func(kind string, c *idclient.Client, s *secret.Value) {
			tok, err := c.ClientCredentials(ctx, baselineRealm, baselineAdminClient, s)
			if err == nil || tok.Len() != 0 {
				tok.Destroy()
				t.Fatalf("%s: rasputin-admin login succeeded", kind)
			}
			counts[kind]++
		}
		for range n {
			refusedLogin("client-credentials, door leaf", door, nil)
			refusedLogin("client-credentials, foreign-CA leaf", foreign, nil)
			refusedLogin("client-credentials, door leaf and a client secret", door, &bogus)

			pw := url.Values{"grant_type": {"password"}, "client_id": {baselineConsole},
				"username": {serviceAccountUser}, "password": {string(wrong.Reveal())}}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				env.KeycloakURL()+"/realms/"+baselineRealm+"/protocol/openid-connect/token", strings.NewReader(pw.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := doorHTTP.Do(req)
			if err != nil {
				t.Fatalf("password grant: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatal("a password grant for the service account succeeded")
			}
			counts["password grant, "+serviceAccountUser]++

			_, err = form.PasswordCodeFlow(ctx, serviceAccountUser, wrong)
			var refused *signin.RefusedError
			if !errors.As(err, &refused) {
				t.Fatalf("login form as %s: %v, want a refusal on the sign-in page", serviceAccountUser, err)
			}
			counts["login form, "+serviceAccountUser]++
		}
		for kind, c := range counts {
			t.Logf("%s: %d refused requests (failureFactor+1 = %d)", kind, c, n)
			if c < n {
				t.Errorf("%s: %d requests, want at least %d", kind, c, n)
			}
		}
		if len(counts) != 5 {
			t.Fatalf("%d kinds of request, want 5", len(counts))
		}

		if due, reason := r.trig.Due(ctx); due {
			t.Errorf("Due after the floods = true (%s), want false", reason)
		}
		tok, err := client.ClientCredentials(ctx, baselineRealm, baselineAdminClient, nil)
		if err != nil {
			t.Fatalf("the api leaf's login after the floods: %v", err)
		}
		tok.Destroy()
		if st, err := realmStatus(t, r.session); st != http.StatusOK {
			t.Errorf("the session's realm GET after the floods = %d, %v; want 200", st, err)
		}
		api = admin(t)
		_, out := api.must(http.StatusOK, http.MethodGet, "/attack-detection/brute-force/users/"+serviceAccountID(api), nil)
		t.Logf("brute-force status of %s: %s", serviceAccountUser, out)
		var bf struct {
			Disabled    bool `json:"disabled"`
			NumFailures int  `json:"numFailures"`
		}
		if err := json.Unmarshal(out, &bf); err != nil {
			t.Fatal(err)
		}
		if bf.Disabled {
			t.Errorf("Keycloak disabled %s after the floods (numFailures %d): the deviation the plan stops on", serviceAccountUser, bf.NumFailures)
		}
		if j := r.jobsOfKind(t); len(j) != 0 {
			t.Errorf("%d identity.recover_admin jobs, want 0", len(j))
		}
	})

	t.Run("TC-1127-16 a deleted client is restored once", func(t *testing.T) {
		r := newTriggerRig(t, env, client, readRepoBaseline)
		api := admin(t)
		id, _ := api.clientRep(baselineAdminClient)
		api.must(http.StatusNoContent, http.MethodDelete, "/clients/"+id, nil)

		r.schedule(t, nil)
		got := r.waitTerminal(t)
		list := r.jobsOfKind(t)
		if len(list) != 1 || list[0].ID != got.jobID || !got.success || list[0].Status != jobs.StatusSucceeded {
			t.Fatalf("jobs = %d, outcome %+v; want one that succeeded", len(list), got)
		}
		steps, err := r.store.ListSteps(t.Context(), got.jobID)
		if err != nil || len(steps) != 1 || string(steps[0].Result) != `{"restored":true}` {
			t.Errorf("steps = %+v (%v), want one with {\"restored\":true}", steps, err)
		}
		select {
		case jobID := <-r.restored:
			if jobID != got.jobID {
				t.Errorf("Restored(%s), want %s", jobID, got.jobID)
			}
		default:
			t.Error("Restored was not called")
		}
		if len(r.restored) != 0 {
			t.Error("Restored was called more than once")
		}

		if st, err := realmStatus(t, r.session); st != http.StatusOK {
			t.Fatalf("the session's realm GET after the restore = %d, %v; want 200", st, err)
		}
		resp, err := r.session.Admin(t.Context(), http.MethodPost, "/admin/realms/"+baselineRealm+"/users",
			map[string]any{"username": "tc-1127-16-write", "enabled": true}, nil)
		if err != nil || resp.Status != http.StatusCreated {
			t.Fatalf("create a user as the restored client: %d, %v", resp.Status, err)
		}
		loc, err := url.Parse(resp.Location)
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := r.session.Admin(t.Context(), http.MethodDelete, loc.Path, nil, nil); err != nil || resp.Status != http.StatusNoContent {
			t.Errorf("delete the user as the restored client: %d, %v", resp.Status, err)
		}
		if due, _ := r.trig.Due(t.Context()); due {
			t.Error("Due after the restore = true")
		}
		if n := len(r.jobsOfKind(t)); n != 1 {
			t.Errorf("jobs after the restore = %d, want 1", n)
		}
		secretText := r.seen.secret()
		if len(secretText) != 43 {
			t.Fatalf("the recovery command's environment carried a %d-character secret, want 43", len(secretText))
		}
		if strings.Contains(rec.Text(), secretText) || strings.Contains(string(r.seen.output()), secretText) {
			t.Error("the temporary secret appears in a log record or in kc.sh's output")
		}
		if len(rec.Records()) == 0 {
			t.Fatal("no records were recorded; the secret scan proved nothing")
		}
	})

	t.Run("TC-1127-17 a client stripped of its roles is the fact and is restored", func(t *testing.T) {
		r := newTriggerRig(t, env, client, readRepoBaseline)
		api := admin(t)
		rmID, _ := api.clientRep("realm-management")
		path := "/users/" + serviceAccountID(api) + "/role-mappings/clients/" + rmID
		_, out := api.must(http.StatusOK, http.MethodGet, path, nil)
		var roles []map[string]any
		if err := json.Unmarshal(out, &roles); err != nil || len(roles) == 0 {
			t.Fatalf("the service account's realm-management roles: %d (%v)", len(roles), err)
		}
		api.must(http.StatusNoContent, http.MethodDelete, path, roles)

		// The rig's session has no token yet, so its first login is after
		// the strip.
		if st, err := realmStatus(t, r.session); st != http.StatusForbidden || !errors.Is(err, idclient.ErrForbidden) {
			t.Fatalf("the session's realm GET after the strip = %d, %v; want 403", st, err)
		}
		if due, _ := r.trig.Due(t.Context()); !due {
			t.Fatal("Due after the strip = false, want true")
		}

		r.schedule(t, nil)
		got := r.waitTerminal(t)
		if list := r.jobsOfKind(t); len(list) != 1 || !got.success || list[0].Status != jobs.StatusSucceeded {
			t.Fatalf("jobs = %d, outcome %+v; want one that succeeded", len(list), got)
		}
		if st, err := realmStatus(t, r.session); st != http.StatusOK {
			t.Errorf("the session's realm GET after the restore = %d, %v; want 200", st, err)
		}
		if due, _ := r.trig.Due(t.Context()); due {
			t.Error("Due after the restore = true")
		}
	})

	t.Run("TC-1127-18 a failed run is not tried again", func(t *testing.T) {
		r := newTriggerRig(t, env, client, func() ([]byte, error) { return nil, os.ErrNotExist })
		api := admin(t)
		id, _ := api.clientRep(baselineAdminClient)
		api.must(http.StatusNoContent, http.MethodDelete, "/clients/"+id, nil)

		ticks := make(chan int, 64)
		r.schedule(t, ticks)
		got := r.waitTerminal(t)
		if got.success {
			t.Fatal("the run with an unreadable baseline succeeded")
		}
		// Two more ticks after the failure, waited on as facts.
		last := 0
		for drained := false; !drained; {
			select {
			case last = <-ticks:
			default:
				drained = true
			}
		}
		for want := last + 2; last < want; {
			select {
			case last = <-ticks:
			case <-t.Context().Done():
				t.Fatalf("the test ended after %d ticks", last)
			}
		}
		t.Logf("%d scheduler ticks", last)

		list := r.jobsOfKind(t)
		if len(list) != 1 || list[0].ID != got.jobID || list[0].Status != jobs.StatusFailed ||
			list[0].Error != "The sign-in baseline could not be read, so the admin client was not restored." {
			t.Fatalf("jobs = %d (%+v), want exactly one failed with the baseline sentence", len(list), list)
		}
		all, err := r.alerts.List(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, a := range all {
			ids = append(ids, a.ID)
		}
		for _, want := range []string{"job-failed:" + got.jobID, recoveradmin.AdminRefusedAlertID} {
			if !slices.Contains(ids, want) {
				t.Errorf("alerts = %v, want %s", ids, want)
			}
		}
		if len(r.restored) != 0 {
			t.Error("Restored was called for a failed run")
		}
	})
}
