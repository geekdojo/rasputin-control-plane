package identitytest

// TC-1127-15 to TC-1127-18: identity.recover_admin's trigger against the real
// pinned Keycloak with the repo's realm baseline imported
// (geekdojo/geekdojo-brain#1127, Identity 2.8). Requests naming the api's
// admin account past the realm's brute-force threshold, through the front
// that applies the door's admin-account guard and as client authentication
// on the inside path, leave its failure count at 0; a deleted client and
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
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// serviceAccountUser is rasputin-admin's service-account user.
const serviceAccountUser = adminguard.ServiceAccountUsername

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

// sentenceCount carries requests to the front and counts the answers that
// are a 400 whose body is exactly sentence (http.Error adds a newline), the
// front's refusal.
type sentenceCount struct {
	inner    http.RoundTripper
	sentence string
	n        int
}

func (c *sentenceCount) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.inner.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if strings.TrimSuffix(string(body), "\n") == c.sentence {
		c.n++
	}
	return resp, nil
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

	t.Run("TC-1127-15 outside requests naming the admin account never reach Keycloak's failure count", func(t *testing.T) {
		r := newTriggerRig(t, env, client, readRepoBaseline)
		n := baselineFailureFactor(t) + 1
		ctx := t.Context()
		refusal := adminguard.Sentence(adminguard.ErrAdminAccount)

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

		// The login form's client needs a redirect URI, which the baseline
		// leaves to the cluster (TC-980-13), as TC-980-25 sets it.
		api := admin(t)
		consoleID, consoleRep := api.clientRep(baselineConsole)
		consoleRep["redirectUris"] = []string{RedirectURI}
		api.must(http.StatusNoContent, http.MethodPut, "/clients/"+consoleID, consoleRep)

		// The control user, with a full profile and a password, deleted
		// afterwards.
		controlPW, err := randomSecret(env.h.cfg.Rand)
		if err != nil {
			t.Fatal(err)
		}
		defer controlPW.Destroy()
		const controlUser = "tc-1127-15-control"
		controlLoc, _ := api.must(http.StatusCreated, http.MethodPost, "/users", map[string]any{
			"username": controlUser, "enabled": true, "email": "tc-1127-15@identitytest.invalid", "emailVerified": true,
			"firstName": "Control", "lastName": "User", "requiredActions": []string{},
			"credentials": []map[string]any{{"type": "password", "value": string(controlPW.Reveal()), "temporary": false}},
		})
		defer func() { a := admin(t); a.must(http.StatusNoContent, http.MethodDelete, controlLoc, nil) }()
		controlID := controlLoc[strings.LastIndex(controlLoc, "/")+1:]

		type bruteForce struct {
			Disabled    bool `json:"disabled"`
			NumFailures int  `json:"numFailures"`
		}
		status := func(api adminAPI, userID string) (bruteForce, []byte) {
			api.t.Helper()
			_, out := api.must(http.StatusOK, http.MethodGet, "/attack-detection/brute-force/users/"+userID, nil)
			var bf bruteForce
			if err := json.Unmarshal(out, &bf); err != nil {
				api.t.Fatal(err)
			}
			return bf, out
		}
		saID := serviceAccountID(api)
		if bf, out := status(api, saID); bf.NumFailures != 0 || bf.Disabled {
			t.Fatalf("brute-force status of %s before the floods: %s, want numFailures 0", serviceAccountUser, out)
		}
		r0 := env.FrontRefusals()

		// (a) The inside path: client-credentials logins as rasputin-admin
		// with the door leaf, straight to Keycloak, each refused by Keycloak
		// (F-1127-16).
		doorLeaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-door"})
		if err != nil {
			t.Fatal(err)
		}
		door := productionClient(t, env, doorLeaf)

		// (b) to (e) go through the front. Every answer it gives with its
		// refusal sentence is counted.
		frontTransport := &http.Transport{TLSClientConfig: env.ClientTLS()}
		t.Cleanup(frontTransport.CloseIdleConnections)
		seen := &sentenceCount{inner: frontTransport, sentence: refusal}
		frontHTTP := &http.Client{Transport: seen,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		tokenURL := env.FrontURL() + "/realms/" + baselineRealm + "/protocol/openid-connect/token"
		frontPost := func(kind string, form url.Values, authorization string) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if authorization != "" {
				req.Header.Set("Authorization", authorization)
			}
			resp, err := frontHTTP.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatalf("%s: read the answer: %v", kind, err)
			}
			if resp.StatusCode != http.StatusBadRequest || strings.TrimSuffix(string(body), "\n") != refusal {
				t.Fatalf("%s: the front answered %d %.200q, want 400 %q", kind, resp.StatusCode, body, refusal)
			}
		}
		form, err := signin.New(signin.Config{Transport: seen, Issuer: env.FrontURL() + "/realms/" + baselineRealm,
			ClientID: baselineConsole, RedirectURI: RedirectURI, Rand: env.h.cfg.Rand, Logger: env.log})
		if err != nil {
			t.Fatal(err)
		}
		basicAdmin := "Basic " + base64.StdEncoding.EncodeToString([]byte(baselineAdminClient+":"+string(bogus.Reveal())))

		counts := map[string]int{}
		for range n {
			tok, err := door.ClientCredentials(ctx, baselineRealm, baselineAdminClient, nil)
			if err == nil || tok.Len() != 0 {
				tok.Destroy()
				t.Fatal("(a) client-credentials as rasputin-admin with the door leaf succeeded")
			}
			counts["(a) direct client-credentials, door leaf"]++

			frontPost("(b)", url.Values{"grant_type": {"client_credentials"}, "client_id": {baselineAdminClient}}, "")
			counts["(b) front client-credentials, form client_id"]++

			frontPost("(c)", url.Values{"grant_type": {"client_credentials"}}, basicAdmin)
			counts["(c) front client-credentials, Basic"]++

			frontPost("(d)", url.Values{"grant_type": {"password"}, "client_id": {baselineConsole},
				"username": {serviceAccountUser}, "password": {string(wrong.Reveal())}}, "")
			counts["(d) front password grant"]++

			before := seen.n
			if _, err := form.PasswordCodeFlow(ctx, serviceAccountUser, wrong); err == nil {
				t.Fatalf("(e) the login form signed %s in", serviceAccountUser)
			}
			if seen.n != before+1 {
				t.Fatalf("(e) the login-form post as %s drew %d refusals from the front, want 1", serviceAccountUser, seen.n-before)
			}
			counts["(e) front login form"]++
		}
		for kind, c := range counts {
			t.Logf("%s: %d requests (failureFactor+1 = %d)", kind, c, n)
			if c < n {
				t.Errorf("%s: %d requests, want at least %d", kind, c, n)
			}
		}
		if len(counts) != 5 {
			t.Fatalf("%d kinds of request, want 5", len(counts))
		}
		if got, want := env.FrontRefusals()-r0, int64(4*n); got != want || seen.n != 4*n {
			t.Fatalf("the front refused %d requests and %d answers carried the sentence, want %d of each", got, seen.n, want)
		}

		// The control: one wrong password through the same front.
		var refused *signin.RefusedError
		if _, err := form.PasswordCodeFlow(ctx, controlUser, wrong); !errors.As(err, &refused) {
			t.Fatalf("the control user's wrong password: %v, want a refusal on the sign-in page", err)
		}
		// Keycloak records a failure on its own executor, so the control's
		// count is waited on as a fact, bounded only by the test's context.
		api = admin(t)
		var control []byte
		for {
			bf, out := status(api, controlID)
			if bf.NumFailures >= 1 {
				if bf.NumFailures != 1 {
					t.Fatalf("the control user's brute-force status: %s, want numFailures 1", out)
				}
				control = out
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("the test ended before the control user's failure was recorded: %s", out)
			}
		}
		t.Logf("brute-force status of %s: %s", controlUser, control)
		bf, out := status(api, saID)
		t.Logf("brute-force status of %s: %s", serviceAccountUser, out)
		if bf.NumFailures != 0 || bf.Disabled {
			t.Errorf("brute-force status of %s after the floods: %s, want numFailures 0 and not disabled", serviceAccountUser, out)
		}

		if due, reason := r.trig.Due(ctx); due {
			t.Errorf("Due after the floods = true (%s), want false", reason)
		}
		t.Log("Due after the floods = false")
		tok, err := client.ClientCredentials(ctx, baselineRealm, baselineAdminClient, nil)
		if err != nil {
			t.Fatalf("the api leaf's login after the floods: %v", err)
		}
		tok.Destroy()
		t.Log("the api leaf's login after the floods: 200")
		if st, err := realmStatus(t, r.session); st != http.StatusOK {
			t.Errorf("the session's realm GET after the floods = %d, %v; want 200", st, err)
		}
		t.Log("the session's realm GET after the floods: 200")
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
