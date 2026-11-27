package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-994-01: a fresh set_roles operator on an account that is not complete
// is a designation: the guard answers Designate, a grant-reason row with
// operator is stored, the console role is unchanged, and the step outcome
// carries the sentence naming "this person" and what is missing.
func TestChanges_TC994_01_Designation(t *testing.T) {
	const start = "This role starts after this person "
	for _, c := range []struct {
		name    string
		creds   []string
		actions []any
		want    string
	}{
		{"nothing", []string{"password"}, []any{}, start + "adds a passkey, security key or authenticator app and saves recovery codes at the next sign-in."},
		{"second step only", []string{"password", "otp"}, []any{}, start + "saves recovery codes at the next sign-in."},
		{"codes only", []string{"password", "recovery-authn-codes"}, []any{}, start + "adds a passkey, security key or authenticator app at the next sign-in."},
		{"action pending", completeCreds, []any{"CONFIGURE_TOTP"}, start + "finishes setting up their account at the next sign-in."},
	} {
		h := newChangeHarness(t)
		h.kc.add(person{sub: "maya", name: "maya", email: "maya@example.invalid", enabled: true, creds: c.creds, actions: c.actions})
		r := h.run(t, adminSubmitter, KindSetRoles, RoleSpec{AccountID: "maya", Role: "operator"}, true, "")
		out := r.out(StepChange)
		if r.job.Status != jobs.StatusSucceeded || out["outcome"] != outcomeDesignated || out["sentence"] != c.want {
			t.Errorf("%s: job %s %q, outcome %v", c.name, r.job.Status, r.job.Error, out)
		}
		if strings.Contains(string(r.step(StepChange).Result), "maya") {
			t.Errorf("%s: the outcome names the person", c.name)
		}
		x, ok := h.designation(t, "maya")
		if !ok || x.ConsoleRole != "operator" || x.Reason != ReasonPrivileged {
			t.Errorf("%s: designation %+v, %v", c.name, x, ok)
		}
		if w := h.writes(); len(w) != 0 || len(h.consoleOf("maya")) != 0 {
			t.Errorf("%s: writes %v, console %v", c.name, w, h.consoleOf("maya"))
		}
	}
}

// TC-994-02: removing an operator's second steps re-designates every
// privileged level first, deletes each second step (codes and password
// kept), clears the markers, demotes, then ends the sessions.
func TestChanges_TC994_02_RemoveSecondSteps(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "op", name: "op", email: "op@example.invalid", enabled: true, console: []string{"operator"}, roles: []string{"operator"},
		appRole: "admin", network: []string{"join", "gear-admin"}, actions: []any{},
		creds: []string{"password", "otp", "webauthn", "recovery-authn-codes"}, offline: map[string][]string{appUUID: {"so"}}})
	r := h.run(t, adminSubmitter, KindRemoveSecondSteps, AccountSpec{AccountID: "op"}, true, "")
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", r.job.Status, r.job.Error)
	}
	calls := h.log.all()
	d, first := index(calls, "designate"), index(calls, "delete-credential")
	if d < 0 || first < 0 || d > first {
		t.Errorf("the designation (%d) is not written before the first credential delete (%d): %v", d, first, calls)
	}
	if got := h.log.only("delete-credential"); !slices.Equal(got, []string{"delete-credential:otp", "delete-credential:webauthn"}) {
		t.Errorf("deleted %v", got)
	}
	x, _ := h.designation(t, "op")
	if x.ConsoleRole != "operator" || x.AppRole != AppAdmin || x.Network != "gear-admin" || x.Reason != ReasonReset {
		t.Errorf("designation %+v", x)
	}
	if h.attr("op", "rasputin_second_step_any") != "" {
		t.Error("the markers were not cleared")
	}
	if len(h.consoleOf("op")) != 0 || h.attr("op", AttrAppRole) != "user" || h.attr("op", AttrNetwork) != "join" {
		t.Errorf("not demoted: console %v, app %q, network %q", h.consoleOf("op"), h.attr("op", AttrAppRole), h.attr("op", AttrNetwork))
	}
	after := calls[index(calls, "after-removal"):]
	for _, want := range []string{"remove-console:operator", "set-attr:user", "logout", "offline-delete:so", "console", "moved", StepApps} {
		if index(after, want) < 0 {
			t.Errorf("%s did not follow the removal: %v", want, after)
		}
	}
	if index(after, "logout") < index(after, "set-attr:user") {
		t.Errorf("the sessions ended before the demotion: %v", after)
	}
}

// TC-994-03: set_email's spec is the account id alone, and the address is
// in no job row, step result, event or log record.
func TestChanges_TC994_03_SpecCarriesNoAddress(t *testing.T) {
	h := newChangeHarness(t)
	const addr = "a@example.test"
	ans, err := h.requests.Request(t.Context(), adminSubmitter, "sid-a", RequestInput{Kind: KindSetEmail,
		Spec: json.RawMessage(`{"accountId":"` + target + `"}`), Value: secret.New([]byte(addr)), HasValue: true})
	if err != nil || ans.Job == nil {
		t.Fatalf("Request: %+v, %v", ans, err)
	}
	h.runner.Wait()
	r := h.result(t, ans.Job.ID)
	if r.job.Status != jobs.StatusSucceeded || string(r.job.Spec) != `{"accountId":"`+target+`"}` {
		t.Fatalf("job %s %q, spec %s", r.job.Status, r.job.Error, r.job.Spec)
	}
	if h.attr(target, "rasputin_email") != "" || !strings.EqualFold(h.kc.users[target].rep["email"].(string), addr) {
		t.Error("the address was not set")
	}
	var seen []string
	seen = append(seen, string(r.job.Spec), r.job.Error)
	for _, s := range r.steps {
		seen = append(seen, string(s.Result), s.Error)
	}
	evs, err := h.jobs.ListEvents(t.Context(), ans.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		seen = append(seen, string(e.Data))
	}
	seen = append(seen, h.clog.Text(), h.rec.Text())
	for _, s := range seen {
		if strings.Contains(strings.ToLower(s), addr) {
			t.Errorf("the address appears in %q", s)
		}
	}
	if h.held.size() != 0 {
		t.Error("the address is still held")
	}
}

// TC-994-04: a privileged account keeps its recovery codes and its last
// second step, and nobody removes a password; with a second second step
// the app goes.
func TestChanges_TC994_04_KeepsCodesAndLastStep(t *testing.T) {
	cases := []struct {
		name string
		p    person
	}{
		{"operator", person{console: []string{"operator"}}},
		{"app administrator", person{appRole: "admin"}},
		{"gear administrator", person{network: []string{"gear-admin"}}},
	}
	for _, c := range cases {
		h := newChangeHarness(t)
		p := c.p
		p.sub, p.name, p.email, p.enabled, p.actions = "self", "self", "self@example.invalid", true, []any{}
		p.creds = []string{"password", "otp", "recovery-authn-codes"}
		h.kc.add(p)
		me := who("self", p.console...)
		for _, cred := range []struct{ id, sentence string }{
			{"id-recovery-authn-codes-2", sentenceKeepCodes},
			{"id-otp-1", sentenceKeepLast},
			{"id-password-0", sentencePassword},
		} {
			r := h.run(t, me, KindRemoveCredential, CredentialSpec{AccountID: "self", CredentialID: cred.id}, true, "")
			if r.job.Status != jobs.StatusFailed || r.job.Error != cred.sentence {
				t.Errorf("%s %s: job %s %q, want %q", c.name, cred.id, r.job.Status, r.job.Error, cred.sentence)
			}
		}
		if got := h.log.only("delete-credential"); len(got) != 0 {
			t.Errorf("%s: refused removals deleted %v", c.name, got)
		}
	}
	h := newChangeHarness(t)
	h.kc.add(person{sub: "self", name: "self", email: "s@example.invalid", enabled: true, console: []string{"operator"}, actions: []any{},
		creds: []string{"password", "otp", "webauthn", "recovery-authn-codes"}})
	r := h.run(t, who("self", "operator"), KindRemoveCredential, CredentialSpec{AccountID: "self", CredentialID: "id-otp-1"}, true, "")
	if r.job.Status != jobs.StatusSucceeded || !slices.Equal(h.log.only("delete-credential"), []string{"delete-credential:otp"}) ||
		index(h.log.all(), "after-removal") < 0 {
		t.Errorf("with a second second step: job %s %q, deletes %v", r.job.Status, r.job.Error, h.log.only("delete-credential"))
	}
}

// TC-994-05: a self remove_credential request answers a fresh sign-in and
// submits nothing; through POST /api/jobs it fails at authorize with
// nothing deleted; through the fresh action it deletes and sends the
// browser to the job.
func TestChanges_TC994_05_FreshAtTheCallback(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "self", name: "self", email: "s@example.invalid", enabled: true, actions: []any{},
		creds: []string{"password", "otp", "webauthn", "recovery-authn-codes"}, sessions: []string{"S1", "S2"}})
	me := auth.Principal{Sub: "self", Session: auth.SessionRef{SID: "S1"}}
	spec := `{"accountId":"self","credentialId":"id-otp-1"}`
	ans, err := h.requests.Request(t.Context(), me.Submitter(), me.Session.SID, RequestInput{Kind: KindRemoveCredential, Spec: json.RawMessage(spec)})
	if err != nil || ans.Fresh == nil || ans.Job != nil || ans.Fresh.Kind != KindRemoveCredential {
		t.Fatalf("Request: %+v, %v", ans, err)
	}
	if js, _ := h.jobs.ListJobs(t.Context(), 10); len(js) != 0 {
		t.Fatalf("%d jobs before the fresh sign-in", len(js))
	}
	r := h.operatorSpec(t, me.Submitter(), KindRemoveCredential, spec)
	if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceFresh || r.step(StepAuthorize).Status != jobs.StepFailed ||
		len(h.log.only("delete-credential")) != 0 {
		t.Errorf("POST /api/jobs: job %s %q, deletes %v", r.job.Status, r.job.Error, h.log.only("delete-credential"))
	}
	action, err := NewFreshAction(h.runner, h.fresh)
	if err != nil {
		t.Fatal(err)
	}
	next, err := action.Run(t.Context(), me, ans.Fresh)
	if err != nil {
		t.Fatal(err)
	}
	h.runner.Wait()
	id := strings.TrimPrefix(next, "/tasks?id=")
	r = h.result(t, id)
	if !strings.HasPrefix(next, "/tasks?id=") || r.job.Status != jobs.StatusSucceeded ||
		!slices.Equal(h.log.only("delete-credential"), []string{"delete-credential:otp"}) {
		t.Errorf("the fresh action: %q, job %s %q", next, r.job.Status, r.job.Error)
	}
	// C18: the request's own session is kept.
	if got := h.log.only("session-delete"); !slices.Equal(got, []string{"session-delete:S2"}) || !strings.Contains(string(r.job.Spec), `"keepSid":"S1"`) {
		t.Errorf("sessions ended %v, spec %s", got, r.job.Spec)
	}
	if _, err := action.Run(t.Context(), me, &FreshPayload{Kind: KindSetEmail, Spec: AccountSpec{AccountID: "self"}}); err == nil {
		t.Error("the fresh action ran a kind that is not fresh-gated")
	}
}

// TC-994-06: every privileged grant needs a fresh sign-in (C24), to a
// complete or an incomplete account: the request answers fresh with no
// job, POST /api/jobs fails with fresh_signin and no write, and a fresh
// job applies or designates. Lowering needs none.
func TestChanges_TC994_06_EveryPrivilegedGrantIsFresh(t *testing.T) {
	grants := []struct {
		kind, spec string
		typed      func(sub string) any
		write      string
	}{
		{KindSetRoles, `"role":"admin"`, func(s string) any { return RoleSpec{AccountID: s, Role: "admin"} }, "add-console:admin"},
		{KindSetRoles, `"role":"operator"`, func(s string) any { return RoleSpec{AccountID: s, Role: "operator"} }, "add-console:operator"},
		{KindGrantAccess, `"level":"admin"`, func(s string) any { return AccessSpec{AccountID: s, Level: "admin"} }, "set-attr:admin"},
		{KindSetNetwork, `"grants":["gear-admin"]`, func(s string) any { return NetworkSpec{AccountID: s, Grants: []string{"gear-admin"}} }, "set-rasputin_network:gear-admin"},
	}
	for _, completeTarget := range []bool{true, false} {
		for _, g := range grants {
			h := newChangeHarness(t)
			p := person{sub: "t", name: "t", email: "t@example.invalid", enabled: true, console: []string{"viewer"}, creds: []string{"password"}, actions: []any{}}
			if completeTarget {
				p.creds = completeCreds
			}
			h.kc.add(p)
			raw := `{"accountId":"t",` + g.spec + `}`
			ans, err := h.requests.Request(t.Context(), adminSubmitter, "sid", RequestInput{Kind: g.kind, Spec: json.RawMessage(raw)})
			if err != nil || ans.Fresh == nil {
				t.Errorf("%s %s complete=%v: Request %+v, %v", g.kind, g.spec, completeTarget, ans, err)
			}
			r := h.operatorSpec(t, adminSubmitter, g.kind, raw)
			if r.job.Status != jobs.StatusFailed || len(h.writes()) != 0 || len(h.clog.Matching(slog.LevelWarn, "change: failed")) != 1 {
				t.Errorf("%s %s: POST /api/jobs %s %q, writes %v", g.kind, g.spec, r.job.Status, r.job.Error, h.writes())
			}
			if code, _ := logkittest.Attr(h.clog.Matching(slog.LevelWarn, "change: failed")[0], "code"); code != authz.CodeFreshSignIn {
				t.Errorf("%s: the refusal's code is %q", g.kind, code)
			}
			r = h.run(t, adminSubmitter, g.kind, g.typed("t"), true, "")
			out := r.out(StepChange)["outcome"]
			switch {
			case r.job.Status != jobs.StatusSucceeded:
				t.Errorf("%s %s: fresh job %s %q", g.kind, g.spec, r.job.Status, r.job.Error)
			case completeTarget && (out != outcomeApplied || index(h.writes(), g.write) < 0):
				t.Errorf("%s %s: complete target %v, writes %v", g.kind, g.spec, out, h.writes())
			case !completeTarget && out != outcomeDesignated:
				t.Errorf("%s %s: incomplete target %v", g.kind, g.spec, out)
			}
		}
	}
	h := newChangeHarness(t)
	h.kc.add(person{sub: "t", name: "t", email: "t@example.invalid", enabled: true, console: []string{"operator"}, actions: []any{}})
	ans, err := h.requests.Request(t.Context(), adminSubmitter, "sid", RequestInput{Kind: KindSetRoles, Spec: json.RawMessage(`{"accountId":"t","role":"viewer"}`)})
	if err != nil || ans.Fresh != nil || ans.Job == nil {
		t.Fatalf("a lowering: %+v, %v", ans, err)
	}
	h.runner.Wait()
	if r := h.result(t, ans.Job.ID); r.job.Status != jobs.StatusSucceeded || !slices.Equal(h.consoleOf("t"), []string{"viewer"}) {
		t.Errorf("a lowering: %s %q, console %v", r.job.Status, r.job.Error, h.consoleOf("t"))
	}
}

// TC-994-12: the one lock serializes two grants on one person: the second
// reads its facts only after the first's role write returns, and decides on
// its result.
func TestChanges_TC994_12_LockSerializes(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "t", name: "t", email: "t@example.invalid", enabled: true, creds: completeCreds, actions: []any{}})
	entered, release := make(chan struct{}), make(chan struct{})
	var seq callLog
	h.kc.observe = func(method, rel string) {
		switch {
		case method == "POST" && strings.HasSuffix(rel, "/users/t/role-mappings/clients/"+consoleUUID):
			if len(seq.only("write")) == 0 {
				seq.add("write-start")
				close(entered)
				<-release
				seq.add("write-returned")
				return
			}
			seq.add("write-again")
		case method == "GET" && rel == "/users/t":
			seq.add("read-t")
		}
	}
	submit := func() string {
		j, err := h.runner.SubmitFor(t.Context(), adminSubmitter, KindSetRoles, RoleSpec{AccountID: "t", Role: "operator"},
			func(id string) error { h.fresh.Mark(id); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return j.ID
	}
	first := submit()
	<-entered
	before := len(seq.only("read-t"))
	second := submit()
	waitFor(t, "the second job waiting for the accounts lock", func() bool { return h.lock.waiting.Load() == 1 })
	if len(seq.only("read-t")) != before {
		t.Error("the second job read the account while the first held the lock")
	}
	close(release)
	h.runner.Wait()
	calls := seq.all()
	s, w := index(calls, "write-start"), index(calls, "write-returned")
	if s < 0 || w < s || slices.Contains(calls[s:w], "read-t") || !slices.Contains(calls[w:], "read-t") {
		t.Errorf("the second job's facts read is not after the first's write returned: %v", calls)
	}
	for _, id := range []string{first, second} {
		if r := h.result(t, id); r.job.Status != jobs.StatusSucceeded {
			t.Errorf("job %s %q", r.job.Status, r.job.Error)
		}
	}
	if r := h.result(t, second); r.out(StepChange)["outcome"] != outcomeApplied || len(h.log.only("logout")) != 1 || len(seq.only("write-again")) != 0 {
		t.Errorf("the second job did not decide on the first's result: logouts %v, writes %v", h.log.only("logout"), seq.all())
	}
}

// TC-994-13: a fresh raise on a complete account sets the markers, then
// ends the online and offline identity sessions, then writes (C23); when
// the sessions can't be ended nothing is written.
func TestChanges_TC994_13_SessionsEndBeforeTheRaise(t *testing.T) {
	cases := []struct {
		kind  string
		spec  any
		write string
	}{
		{KindSetRoles, RoleSpec{AccountID: "t", Role: "operator"}, "add-console:operator"},
		{KindGrantAccess, AccessSpec{AccountID: "t", Level: "admin"}, "set-attr:admin"},
		{KindSetNetwork, NetworkSpec{AccountID: "t", Grants: []string{"gear-admin"}}, "set-rasputin_network:gear-admin"},
	}
	for _, c := range cases {
		h := newChangeHarness(t)
		h.kc.add(person{sub: "t", name: "t", email: "t@example.invalid", enabled: true, console: []string{"viewer"}, appRole: "user",
			creds: completeCreds, actions: []any{}, offline: map[string][]string{appUUID: {"off"}}})
		r := h.run(t, adminSubmitter, c.kind, c.spec, true, "")
		calls := h.log.all()
		b, l, o, w := index(calls, "before-privilege"), index(calls, "logout"), index(calls, "offline-delete:off"), index(calls, c.write)
		if r.job.Status != jobs.StatusSucceeded || b < 0 || !(b < l && l < o && o < w) {
			t.Errorf("%s: job %s %q, order %v", c.kind, r.job.Status, r.job.Error, calls)
		}

		h = newChangeHarness(t)
		h.kc.add(person{sub: "t", name: "t", email: "t@example.invalid", enabled: true, console: []string{"viewer"}, appRole: "user",
			creds: completeCreds, actions: []any{}})
		h.kc.fail = func(method, path string) error {
			if method == "POST" && path == "/users/t/logout" {
				return &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
			}
			return nil
		}
		r = h.run(t, adminSubmitter, c.kind, c.spec, true, "")
		if r.job.Status != jobs.StatusFailed || r.job.Error != SentenceSessions || len(h.writes()) != 0 {
			t.Errorf("%s: sessions down: job %s %q, writes %v", c.kind, r.job.Status, r.job.Error, h.writes())
		}
	}
}

// TC-994-14: applying or removing a level withdraws its pending field;
// delete and decline withdraw them all; a later grant on a completed
// account grants nothing withdrawn.
func TestChanges_TC994_14_Withdrawal(t *testing.T) {
	seed := func(t *testing.T, h *changeHarness, sub string) {
		t.Helper()
		for _, c := range [][2]string{{string(LevelConsole), "operator"}, {string(LevelApp), "admin"}, {string(LevelNetwork), "gear-admin"}} {
			if err := h.designations.Choose(t.Context(), sub, Level(c[0]), c[1]); err != nil {
				t.Fatal(err)
			}
		}
	}
	h := newChangeHarness(t)
	seed(t, h, target)
	h.run(t, adminSubmitter, KindSetRoles, RoleSpec{AccountID: target, Role: "viewer"}, false, "")
	if x, _ := h.designation(t, target); x.ConsoleRole != "" || x.AppRole != AppAdmin || x.Network != "gear-admin" {
		t.Errorf("after set_roles viewer: %+v", x)
	}
	h.run(t, adminSubmitter, KindGrantAccess, AccessSpec{AccountID: target, Level: "user"}, false, "")
	if x, _ := h.designation(t, target); x.AppRole != "" || x.Network != "gear-admin" {
		t.Errorf("after grant_access user: %+v", x)
	}
	h.run(t, adminSubmitter, KindSetNetwork, NetworkSpec{AccountID: target, Grants: []string{"join"}}, false, "")
	if x, ok := h.designation(t, target); ok {
		t.Errorf("after set_network [join] the row is still %+v", x)
	}
	h.complete(target)
	if r := h.grant(t, target); r.outcome(t, StepCheck) != outcomeNotDesignated || len(h.log.only("add-console")) != 0 {
		t.Errorf("a later grant: %s, %v", r.outcome(t, StepCheck), h.log.only("add-console"))
	}

	h = newChangeHarness(t)
	seed(t, h, target)
	h.run(t, adminSubmitter, KindRevokeAccess, AccountSpec{AccountID: target}, false, "")
	if x, _ := h.designation(t, target); x.AppRole != "" || x.ConsoleRole != "operator" {
		t.Errorf("after revoke_access: %+v", x)
	}
	for _, kind := range []string{KindDelete, KindDecline} {
		h := newChangeHarness(t)
		seed(t, h, target)
		r := h.run(t, adminSubmitter, kind, AccountSpec{AccountID: target}, false, "")
		if x, ok := h.designation(t, target); ok || r.job.Status != jobs.StatusSucceeded {
			t.Errorf("after %s: job %s %q, row %+v", kind, r.job.Status, r.job.Error, x)
		}
	}
}

// TC-994-15: the latest administrator choice wins (F-994-02), and a
// system re-designation still keeps the higher.
func TestChanges_TC994_15_LatestChoiceWins(t *testing.T) {
	h := newChangeHarness(t)
	h.run(t, adminSubmitter, KindSetRoles, RoleSpec{AccountID: target, Role: "admin"}, true, "")
	if x, _ := h.designation(t, target); x.ConsoleRole != "admin" {
		t.Fatalf("pending %+v", x)
	}
	h.run(t, adminSubmitter, KindSetRoles, RoleSpec{AccountID: target, Role: "operator"}, true, "")
	if x, _ := h.designation(t, target); x.ConsoleRole != "operator" {
		t.Errorf("after set_roles operator the pending role is %+v", x)
	}
	h.complete(target)
	if r := h.grant(t, target); r.job.Status != jobs.StatusSucceeded || !slices.Equal(h.log.only("add-console"), []string{"add-console:operator"}) {
		t.Errorf("the grant: %s %q, %v", r.job.Status, r.job.Error, h.log.only("add-console"))
	}

	h = newChangeHarness(t)
	h.kc.add(person{sub: "adm", name: "adm", email: "adm@example.invalid", enabled: true, console: []string{"admin"}, directAdmin: true,
		creds: completeCreds, actions: []any{}})
	if err := h.designations.Choose(t.Context(), "adm", LevelConsole, "operator"); err != nil {
		t.Fatal(err)
	}
	r := h.run(t, adminSubmitter, KindRemoveSecondSteps, AccountSpec{AccountID: "adm"}, true, "")
	if x, _ := h.designation(t, "adm"); r.job.Status != jobs.StatusSucceeded || x.ConsoleRole != "admin" || x.Reason != ReasonReset {
		t.Errorf("a re-designation: job %s %q, %+v", r.job.Status, r.job.Error, x)
	}
}

// TC-994-16: a designated gear administrator gets the rest of the set at
// once, gear-admin is never written, and the grant adds it to the set held
// then (F-994-03).
func TestChanges_TC994_16_DesignatedGearAdmin(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "g", name: "g", email: "g@example.invalid", enabled: true, network: []string{"gear-read"}, creds: []string{"password"}, actions: []any{}})
	r := h.run(t, adminSubmitter, KindSetNetwork, NetworkSpec{AccountID: "g", Grants: []string{"join", "gear-admin"}}, true, "")
	if r.job.Status != jobs.StatusSucceeded || h.attr("g", AttrNetwork) != "join" || r.out(StepChange)["outcome"] != outcomeDesignated {
		t.Fatalf("job %s %q, network %q", r.job.Status, r.job.Error, h.attr("g", AttrNetwork))
	}
	for _, w := range h.writes() {
		if strings.Contains(w, "gear-admin") {
			t.Errorf("gear-admin was written: %v", h.writes())
		}
	}
	if x, _ := h.designation(t, "g"); x.Network != "gear-admin" {
		t.Errorf("designation %+v", x)
	}
	h.complete("g")
	if r := h.grant(t, "g"); r.job.Status != jobs.StatusSucceeded || h.attr("g", AttrNetwork) != "join,gear-admin" {
		t.Errorf("the grant: %s %q, network %q", r.job.Status, r.job.Error, h.attr("g", AttrNetwork))
	}
}

// TC-994-18: a person signing themselves out everywhere else keeps the
// request's own identity session and console session; an administrator's
// sign-out of someone else ends every session whatever the spec names; and
// keepSid is never the client's.
func TestChanges_TC994_18_KeepTheCurrentSession(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "self", name: "self", email: "s@example.invalid", enabled: true, actions: []any{},
		sessions: []string{"S1", "S2", "S3"}, offline: map[string][]string{appUUID: {"o1"}}})
	for _, sid := range []string{"S1", "S2", "S3"} {
		if _, err := h.console.Create(t.Context(), auth.Principal{Sub: "self", Session: auth.SessionRef{SID: sid}}); err != nil {
			t.Fatal(err)
		}
	}
	me := auth.Principal{Sub: "self", Session: auth.SessionRef{SID: "S1"}}
	ans, err := h.requests.Request(t.Context(), me.Submitter(), "S1", RequestInput{Kind: KindSignOut,
		Spec: json.RawMessage(`{"accountId":"self","keepSid":"client-chosen"}`)})
	if err != nil || ans.Job == nil {
		t.Fatalf("Request: %+v, %v", ans, err)
	}
	h.runner.Wait()
	r := h.result(t, ans.Job.ID)
	if r.job.Status != jobs.StatusSucceeded || string(r.job.Spec) != `{"accountId":"self","keepSid":"S1"}` {
		t.Errorf("job %s %q, spec %s", r.job.Status, r.job.Error, r.job.Spec)
	}
	if got := h.log.only("session-delete"); !slices.Equal(got, []string{"session-delete:S2", "session-delete:S3"}) || len(h.log.only("logout")) != 0 {
		t.Errorf("identity sessions ended %v, logouts %v", got, h.log.only("logout"))
	}
	if got := h.log.only("console-except"); !slices.Equal(got, []string{"console-except:S1"}) || len(h.log.only("offline-delete:o1")) != 1 {
		t.Errorf("console %v, offline %v", got, h.log.only("offline-delete"))
	}

	h = newChangeHarness(t)
	h.kc.add(person{sub: "other", name: "other", email: "o@example.invalid", enabled: true, actions: []any{}, sessions: []string{"S1", "S2"}})
	r = h.operatorSpec(t, adminSubmitter, KindSignOut, `{"accountId":"other","keepSid":"S1"}`)
	if r.job.Status != jobs.StatusSucceeded || len(h.log.only("logout")) != 1 || len(h.log.only("session-delete")) != 0 ||
		!slices.Equal(h.log.only("console"), []string{"console"}) {
		t.Errorf("an administrator's sign-out: job %s %q, calls %v", r.job.Status, r.job.Error, h.log.all())
	}
}

// TC-994-22: a value kind with nothing held fails with its sentence and
// writes nothing; the terminal hook drops the value and the mark on
// success, failure and for a recovered orphan.
func TestChanges_TC994_22_HeldValues(t *testing.T) {
	h := newChangeHarness(t)
	r := h.operatorSpec(t, adminSubmitter, KindSetDisplayName, `{"accountId":"`+target+`"}`)
	if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceValueGone || len(h.writes()) != 0 {
		t.Errorf("nothing held: job %s %q, writes %v", r.job.Status, r.job.Error, h.writes())
	}
	r = h.run(t, adminSubmitter, KindSetDisplayName, AccountSpec{AccountID: target}, true, "New Name")
	if r.job.Status != jobs.StatusSucceeded || h.held.size() != 0 || h.fresh.size() != 0 {
		t.Errorf("success: job %s %q, held %d, marks %d", r.job.Status, r.job.Error, h.held.size(), h.fresh.size())
	}
	h.kc.fail = func(method, _ string) error {
		if method == "PUT" {
			return &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
		}
		return nil
	}
	r = h.run(t, adminSubmitter, KindEnable, AccountSpec{AccountID: target}, true, "never-taken")
	if r.job.Status != jobs.StatusFailed || h.held.size() != 0 || h.fresh.size() != 0 {
		t.Errorf("failure: job %s, held %d, marks %d", r.job.Status, h.held.size(), h.fresh.size())
	}
	orphan := &jobs.Job{ID: "orphan-994", Kind: KindSetEmail, Spec: json.RawMessage(`{"accountId":"x"}`), Status: jobs.StatusRunning,
		CreatedBy: adminA, CreatedAt: time.Now().UTC()}
	if err := h.jobs.CreateJob(t.Context(), orphan); err != nil {
		t.Fatal(err)
	}
	v := secret.New([]byte("orphan@example.invalid"))
	h.held.Put(orphan.ID, v)
	h.fresh.Mark(orphan.ID)
	if err := h.runner.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v.Len() != 0 || h.held.size() != 0 || h.fresh.size() != 0 {
		t.Error("Recover left the orphan's value or mark")
	}
}

// TC-994-23: a mark is taken once; a Fresh built after a restart holds
// nothing, so a privileged job without a mark fails with fresh_signin.
func TestChanges_TC994_23_FreshMarks(t *testing.T) {
	f := NewFresh()
	f.Mark("j")
	if !f.Take("j") || f.Take("j") {
		t.Error("a mark was not taken exactly once")
	}
	f.Mark("k")
	if NewFresh().Take("k") {
		t.Error("a new Fresh held a mark")
	}
	h := newChangeHarness(t)
	h.complete(target)
	r := h.run(t, adminSubmitter, KindSetRoles, RoleSpec{AccountID: target, Role: "admin"}, false, "")
	recs := h.clog.Matching(slog.LevelWarn, "change: failed")
	code := ""
	if len(recs) == 1 {
		code, _ = logkittest.Attr(recs[0], "code")
	}
	if r.job.Status != jobs.StatusFailed || code != authz.CodeFreshSignIn || len(h.writes()) != 0 {
		t.Errorf("no mark: job %s %q, code %q, writes %v", r.job.Status, r.job.Error, code, h.writes())
	}
}

// TC-994-24: set_email's paths.
func TestChanges_TC994_24_SetEmail(t *testing.T) {
	h := newChangeHarness(t)
	if err := h.removed.Record(t.Context(), "gone", "gone@example.invalid"); err != nil {
		t.Fatal(err)
	}
	r := h.run(t, adminSubmitter, KindSetEmail, AccountSpec{AccountID: target}, false, "gone@example.invalid")
	if r.job.Error != sentenceEmailListed || len(h.writes()) != 0 {
		t.Errorf("a removed address: %q, writes %v", r.job.Error, h.writes())
	}
	h.removedC.err = errors.New("unreadable")
	if r := h.run(t, adminSubmitter, KindSetEmail, AccountSpec{AccountID: target}, false, "new@example.invalid"); r.job.Error != sentenceEmailList {
		t.Errorf("an unreadable list: %q", r.job.Error)
	}
	h.removedC.err = nil
	if r := h.run(t, adminSubmitter, KindSetEmail, AccountSpec{AccountID: target}, false, "b@example.invalid"); r.job.Error != sentenceEmailTaken {
		t.Errorf("a taken address: %q", r.job.Error)
	}
	h.kc.users[target].rep["attributes"].(map[string]any)["rasputin_email"] = []any{"target@example.invalid"}
	if r := h.run(t, adminSubmitter, KindSetEmail, AccountSpec{AccountID: target}, false, "fresh@example.invalid"); r.job.Status != jobs.StatusSucceeded ||
		h.attr(target, "rasputin_email") != "" {
		t.Errorf("a non-admin: %s %q, confirmed %q", r.job.Status, r.job.Error, h.attr(target, "rasputin_email"))
	}
	if r := h.run(t, who(adminB, "admin"), KindSetEmail, AccountSpec{AccountID: adminA}, false, "boss@example.invalid"); r.job.Status != jobs.StatusSucceeded ||
		h.attr(adminA, "rasputin_email") != "boss@example.invalid" {
		t.Errorf("an administrator: %s %q, confirmed %q", r.job.Status, r.job.Error, h.attr(adminA, "rasputin_email"))
	}
	h.kc.keepNothing = true
	r = h.run(t, who(adminB, "admin"), KindSetEmail, AccountSpec{AccountID: adminA}, false, "other@example.invalid")
	errs := h.clog.Matching(slog.LevelError, "change: failed")
	if r.job.Error != sentenceNotKept || len(errs) != 1 {
		t.Errorf("not kept: %q, %d ERROR records", r.job.Error, len(errs))
	}
}

// TC-994-25: confirm_email copies the email into rasputin_email; an
// account with none fails with its sentence and no write.
func TestChanges_TC994_25_ConfirmEmail(t *testing.T) {
	h := newChangeHarness(t)
	r := h.run(t, adminSubmitter, KindConfirmEmail, AccountSpec{AccountID: target}, false, "")
	if r.job.Status != jobs.StatusSucceeded || h.attr(target, "rasputin_email") != "target@example.invalid" {
		t.Errorf("job %s %q, confirmed %q", r.job.Status, r.job.Error, h.attr(target, "rasputin_email"))
	}
	h.kc.add(person{sub: "nomail", name: "nomail", email: "", enabled: true, actions: []any{}})
	n := len(h.writes())
	if r := h.run(t, adminSubmitter, KindConfirmEmail, AccountSpec{AccountID: "nomail"}, false, ""); r.job.Error != sentenceNoEmail || len(h.writes()) != n {
		t.Errorf("no address: %q, writes %v", r.job.Error, h.writes())
	}
}

// TC-994-26: unlock, enable, set_display_name and rename_credential, with
// the name and the label never in the spec.
func TestChanges_TC994_26_SmallChanges(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "off", name: "off", email: "off@example.invalid", enabled: false, actions: []any{}})
	h.kc.add(person{sub: "self", name: "self", email: "s@example.invalid", enabled: true, actions: []any{}, creds: []string{"password", "otp"}})
	if r := h.run(t, adminSubmitter, KindUnlock, AccountSpec{AccountID: target}, false, ""); r.job.Status != jobs.StatusSucceeded ||
		!slices.ContainsFunc(h.kc.reqs, func(q request) bool {
			return q.method == "DELETE" && q.path == "/attack-detection/brute-force/users/"+target
		}) {
		t.Errorf("unlock: %s %q", r.job.Status, r.job.Error)
	}
	if r := h.run(t, adminSubmitter, KindEnable, AccountSpec{AccountID: "off"}, false, ""); r.job.Status != jobs.StatusSucceeded || !h.kc.enabled("off") {
		t.Errorf("enable: %s %q", r.job.Status, r.job.Error)
	}
	r := h.run(t, adminSubmitter, KindSetDisplayName, AccountSpec{AccountID: target}, false, "Ana Lopez")
	if r.job.Status != jobs.StatusSucceeded || h.kc.users[target].rep["firstName"] != "Ana Lopez" || strings.Contains(string(r.job.Spec), "Ana") {
		t.Errorf("set_display_name: %s %q, spec %s", r.job.Status, r.job.Error, r.job.Spec)
	}
	r = h.run(t, who("self"), KindRenameCredential, CredentialSpec{AccountID: "self", CredentialID: "id-otp-1"}, false, "Work phone")
	i := slices.IndexFunc(h.kc.reqs, func(q request) bool { return strings.HasSuffix(q.path, "/credentials/id-otp-1/userLabel") })
	if r.job.Status != jobs.StatusSucceeded || i < 0 || h.kc.reqs[i].method != "PUT" || string(h.kc.reqs[i].body) != "text/plain:Work phone" ||
		strings.Contains(string(r.job.Spec), "Work") {
		t.Errorf("rename_credential: %s %q, spec %s", r.job.Status, r.job.Error, r.job.Spec)
	}
}

// TC-994-27: removing a network grant runs the network_change steps after
// the read-back; adding a plain grant ends there with no session ended.
func TestChanges_TC994_27_NetworkRemovalAndAddition(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "n", name: "n", email: "n@example.invalid", enabled: true, network: []string{"join", "gear-read"}, actions: []any{}})
	r := h.run(t, adminSubmitter, KindSetNetwork, NetworkSpec{AccountID: "n", Grants: []string{"join"}}, false, "")
	if r.job.Status != jobs.StatusSucceeded || h.attr("n", AttrNetwork) != "join" || r.outcome(t, StepOnlineSessions) != outcomeEnded ||
		r.outcome(t, StepOfflineSessions) != outcomeEnded || len(h.log.only(StepNetwork)) != 1 {
		t.Errorf("a removal: job %s %q, steps %v", r.job.Status, r.job.Error, r.names())
	}
	h = newChangeHarness(t)
	h.kc.add(person{sub: "n", name: "n", email: "n@example.invalid", enabled: true, network: []string{"join"}, actions: []any{}})
	r = h.run(t, adminSubmitter, KindSetNetwork, NetworkSpec{AccountID: "n", Grants: []string{"join", "gear-read"}}, false, "")
	if r.job.Status != jobs.StatusSucceeded || !slices.Equal(r.names(), []string{StepChange}) || len(h.log.only("logout")) != 0 ||
		h.attr("n", AttrNetwork) != "gear-read,join" {
		t.Errorf("an addition: job %s, steps %v, network %q", r.job.Status, r.names(), h.attr("n", AttrNetwork))
	}
}

// TC-994-28: disable and delete run #991's steps with the guard deciding;
// revoke_access removes app access and offline_access (C10) and withdraws
// the app field; delete and decline withdraw every field.
func TestChanges_TC994_28_RevocationKinds(t *testing.T) {
	h := newChangeHarness(t)
	if r := h.run(t, adminSubmitter, KindDisable, AccountSpec{AccountID: target}, false, ""); r.job.Status != jobs.StatusSucceeded ||
		h.kc.enabled(target) || len(h.log.only("guard")) != 2 {
		t.Errorf("disable: %s %q, guard %v", r.job.Status, r.job.Error, h.log.only("guard"))
	}
	h = newChangeHarness(t)
	if err := h.designations.Choose(t.Context(), target, LevelApp, "admin"); err != nil {
		t.Fatal(err)
	}
	r := h.run(t, adminSubmitter, KindRevokeAccess, AccountSpec{AccountID: target}, false, "")
	if x, ok := h.designation(t, target); r.job.Status != jobs.StatusSucceeded || ok || index(h.writes(), "remove-attr") < 0 ||
		index(h.writes(), "remove-offline") < 0 {
		t.Errorf("revoke_access: %s %q, writes %v, row %+v", r.job.Status, r.job.Error, h.writes(), x)
	}
	for _, kind := range []string{KindDelete, KindDecline} {
		h := newChangeHarness(t)
		if err := h.designations.Choose(t.Context(), target, LevelConsole, "operator"); err != nil {
			t.Fatal(err)
		}
		r := h.run(t, adminSubmitter, kind, AccountSpec{AccountID: target}, false, "")
		if _, ok := h.designation(t, target); r.job.Status != jobs.StatusSucceeded || h.kc.exists(target) || ok || len(h.log.only("guard")) != 2 {
			t.Errorf("%s: %s %q, exists %v, designated %v", kind, r.job.Status, r.job.Error, h.kc.exists(target), ok)
		}
	}
}

// TC-994-32: the grant's changes: app-only grants app admin and no console
// role; gear-admin is added to the set held at grant time; a console admin
// grant also confirms the email.
func TestChanges_TC994_32_Granter(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "a", name: "a", email: "a@example.invalid", enabled: true, creds: completeCreds, actions: []any{}})
	if err := h.designations.Choose(t.Context(), "a", LevelApp, "admin"); err != nil {
		t.Fatal(err)
	}
	if r := h.grant(t, "a"); r.job.Status != jobs.StatusSucceeded || h.attr("a", AttrAppRole) != "admin" || len(h.log.only("add-console")) != 0 {
		t.Errorf("app-only: %s %q, app %q, steps %v %s %s", r.job.Status, r.job.Error, h.attr("a", AttrAppRole), r.names(), r.steps[0].Result, r.steps[1].Result)
	}
	h.kc.add(person{sub: "g", name: "g", email: "g@example.invalid", enabled: true, creds: completeCreds, actions: []any{}, network: []string{"gear-read"}})
	if err := h.designations.Choose(t.Context(), "g", LevelNetwork, "gear-admin"); err != nil {
		t.Fatal(err)
	}
	if r := h.grant(t, "g"); r.job.Status != jobs.StatusSucceeded || h.attr("g", AttrNetwork) != "gear-read,gear-admin" {
		t.Errorf("gear: %s %q, network %q", r.job.Status, r.job.Error, h.attr("g", AttrNetwork))
	}
	h.kc.add(person{sub: "c", name: "c", email: "c@example.invalid", enabled: true, creds: completeCreds, actions: []any{}})
	if err := h.designations.Choose(t.Context(), "c", LevelConsole, "admin"); err != nil {
		t.Fatal(err)
	}
	if r := h.grant(t, "c"); r.job.Status != jobs.StatusSucceeded || h.attr("c", "rasputin_email") != "c@example.invalid" {
		t.Errorf("console admin: %s %q, confirmed %q", r.job.Status, r.job.Error, h.attr("c", "rasputin_email"))
	}
}

// TC-994-33: removing a moved administrator's second steps deletes its
// pre-update credentials and sessions rows, and keeps the users row (C15,
// F-994-04).
func TestChanges_TC994_33_MovedAdministrator(t *testing.T) {
	h := newChangeHarness(t)
	handle := bytes.Repeat([]byte{0x43}, 16)
	moved := auth.MovedAccountID(handle)
	h.kc.add(person{sub: moved, name: "moved", email: "m@example.invalid", enabled: true, console: []string{"admin"}, directAdmin: true,
		creds: completeCreds, actions: []any{}})
	if err := h.auth.CreateUser(t.Context(), &auth.User{ID: handle, Name: "moved", DisplayName: "Moved", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.CreateSession(t.Context(), &auth.Session{Token: "tok", UserID: handle, CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), LastActiveAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r := h.run(t, adminSubmitter, KindRemoveSecondSteps, AccountSpec{AccountID: moved}, true, "")
	var out struct{ Sessions int64 }
	_ = json.Unmarshal(r.step(StepMovedRows).Result, &out)
	if r.job.Status != jobs.StatusSucceeded || out.Sessions != 1 || len(h.log.only("moved")) != 1 {
		t.Errorf("job %s %q, moved rows %s", r.job.Status, r.job.Error, r.step(StepMovedRows).Result)
	}
	if u, err := h.auth.GetUserByID(t.Context(), handle); err != nil || u == nil {
		t.Errorf("the users row went: %v", err)
	}
}

// TC-994-34: the one accounts lock is shared: while it is held, #992's
// set_temporary, grant_access, enable, unlock, set_email,
// remove_credential and the designated-role grant each wait, and write
// only once it is released.
func TestChanges_TC994_34_SharedLock(t *testing.T) {
	h := newChangeHarness(t)
	redes, err := NewRedesignator(RedesignatorDeps{Facts: h.ra, Designations: h.designations, Users: h.users, Lock: h.lock})
	if err != nil {
		t.Fatal(err)
	}
	reset, err := ResetPasswordWorkflow(ResetDeps{Users: h.users, Held: h.held, Checker: acceptAll{}, Revoker: h.rev, Redesignate: redes,
		Lock: h.lock, Log: slog.New(slog.DiscardHandler), StepTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	h.runner.Register(reset)
	h.kc.add(person{sub: "self", name: "self", email: "s@example.invalid", enabled: true, actions: []any{}, creds: []string{"password", "otp", "webauthn"}})
	h.kc.add(person{sub: "d", name: "d", email: "d@example.invalid", enabled: true, creds: completeCreds, actions: []any{}})
	if err := h.designations.Choose(t.Context(), "d", LevelConsole, "operator"); err != nil {
		t.Fatal(err)
	}
	h.lock.Lock()
	submit := func(by authz.Submitter, kind string, spec any, fresh bool, value string) {
		if _, err := h.runner.SubmitFor(t.Context(), by, kind, spec, func(id string) error {
			if fresh {
				h.fresh.Mark(id)
			}
			if value != "" {
				h.held.Put(id, secret.New([]byte(value)))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	submit(adminSubmitter, ResetKind, ResetSpec{AccountID: target}, false, "a long temporary passphrase")
	submit(adminSubmitter, KindGrantAccess, AccessSpec{AccountID: adminB, Level: "user"}, false, "")
	submit(adminSubmitter, KindEnable, AccountSpec{AccountID: target}, false, "")
	submit(adminSubmitter, KindUnlock, AccountSpec{AccountID: target}, false, "")
	submit(adminSubmitter, KindSetEmail, AccountSpec{AccountID: adminB}, false, "new-b@example.invalid")
	submit(who("self"), KindRemoveCredential, CredentialSpec{AccountID: "self", CredentialID: "id-otp-1"}, true, "")
	if _, err := h.runner.Submit(t.Context(), GrantKind, GrantSpec{AccountID: "d"}, grantSubmitter); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "seven changes waiting for the accounts lock", func() bool { return h.lock.waiting.Load() == 7 })
	for _, w := range []string{"reset-password", "set-attr", "enable", "unlock", "set-email", "delete-credential", "add-console"} {
		if index(h.log.all(), w) >= 0 {
			t.Errorf("%s was written while the lock was held", w)
		}
	}
	h.lock.Unlock()
	h.runner.Wait()
	js, err := h.jobs.ListJobs(t.Context(), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range js {
		if j.Status != jobs.StatusSucceeded {
			t.Errorf("%s: %s %q", j.Kind, j.Status, j.Error)
		}
	}
}

// acceptAll is a password policy that refuses nothing; set_temporary
// consults it only after a 500.
type acceptAll struct{}

func (acceptAll) Check(secret.Value, string, string) (pwpolicy.Refusal, error) {
	return pwpolicy.Refusal{}, nil
}

// F-994-18: set_roles admin applied to a complete account confirms its
// address, copying email into rasputin_email, so an administrator's app
// tokens carry it; operator, applied the same way, confirms nothing.
func TestChanges_F994_18_AdminConfirmsTheAddress(t *testing.T) {
	for _, c := range []struct{ role, want string }{
		{"admin", "full@example.invalid"},
		{"operator", ""},
	} {
		h := newChangeHarness(t)
		h.kc.add(person{sub: "full", name: "full", email: "full@example.invalid", enabled: true, creds: completeCreds, actions: []any{}})
		r := h.run(t, adminSubmitter, KindSetRoles, RoleSpec{AccountID: "full", Role: c.role}, true, "")
		if r.job.Status != jobs.StatusSucceeded || r.out(StepChange)["outcome"] != outcomeApplied || !slices.Contains(h.consoleOf("full"), c.role) {
			t.Fatalf("%s: job %s %q, outcome %v, console %v", c.role, r.job.Status, r.job.Error, r.out(StepChange), h.consoleOf("full"))
		}
		if got := h.attr("full", "rasputin_email"); got != c.want {
			t.Errorf("%s: rasputin_email %q, want %q", c.role, got, c.want)
		}
	}
}

// F-994-18 (F-994-09): grant_access admin, designated for a person with no
// app access, gives app access user at once and records admin.
func TestChanges_F994_18_DesignatedAppAdminGetsUser(t *testing.T) {
	h := newChangeHarness(t)
	h.kc.add(person{sub: "new", name: "new", email: "new@example.invalid", enabled: true, creds: []string{"password"}, actions: []any{}})
	r := h.run(t, adminSubmitter, KindGrantAccess, AccessSpec{AccountID: "new", Level: string(AppAdmin)}, true, "")
	if r.job.Status != jobs.StatusSucceeded || r.out(StepChange)["outcome"] != outcomeDesignated {
		t.Fatalf("job %s %q, outcome %v", r.job.Status, r.job.Error, r.out(StepChange))
	}
	if got := h.attr("new", AttrAppRole); got != string(AppUser) {
		t.Errorf("app access %q while designated, want %s", got, AppUser)
	}
	if x, ok := h.designation(t, "new"); !ok || x.AppRole != AppAdmin {
		t.Errorf("designation %+v, %v", x, ok)
	}
}
