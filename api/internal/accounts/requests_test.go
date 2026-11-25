package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-994-20 (the service's part): a kind the route does not take, and
// every malformed spec and value, are refused before anything is checked
// or submitted; the handler's part is in package api.
func TestRequests_TC994_20_Input(t *testing.T) {
	h := newChangeHarness(t)
	in := func(kind, spec string, value ...string) RequestInput {
		r := RequestInput{Kind: kind, Spec: json.RawMessage(spec)}
		if len(value) > 0 {
			r.Value, r.HasValue = secret.New([]byte(value[0])), true
		}
		return r
	}
	acct := `{"accountId":"` + target + `"}`
	cases := []struct {
		name  string
		in    RequestInput
		cause string
	}{
		{"unknown kind", in("accounts.grant_designated_role", acct), ""},
		{"unknown field", in(KindEnable, `{"accountId":"`+target+`","extra":1}`), "spec_not_json"},
		{"a field the kind does not take", in(KindEnable, `{"accountId":"`+target+`","role":"admin"}`), "spec_field"},
		{"a field the kind needs, missing", in(KindSetRoles, acct), "spec_field"},
		{"no spec", in(KindEnable, ``), "spec_missing"},
		{"a null spec", in(KindEnable, `null`), "spec_missing"},
		{"not JSON", in(KindEnable, `{"accountId":`), "spec_not_json"},
		{"two objects", in(KindEnable, acct+acct), "spec_not_json"},
		{"no account", in(KindEnable, `{"accountId":""}`), "spec_target"},
		{"a value it takes none of", in(KindEnable, acct, "x"), "value_unexpected"},
		{"set_email with no value", in(KindSetEmail, acct), "value_missing"},
		{"set_display_name with no value", in(KindSetDisplayName, acct), "value_missing"},
		{"rename_credential with no value", in(KindRenameCredential, `{"accountId":"`+target+`","credentialId":"c"}`), "value_missing"},
		{"an address with a name", in(KindSetEmail, acct, "Ana <a@example.test>"), "value_email"},
		{"not an address", in(KindSetEmail, acct, "nobody"), "value_email"},
		{"an address with spaces", in(KindSetEmail, acct, " a@example.test"), "value_email"},
		{"an empty name", in(KindSetDisplayName, acct, ""), "value_text"},
		{"256 characters", in(KindSetDisplayName, acct, strings.Repeat("é", 256)), "value_text"},
		{"a control character", in(KindSetDisplayName, acct, "Ana\nLopez"), "value_text"},
		{"not UTF-8", in(KindSetDisplayName, acct, "\xff"), "value_text"},
	}
	for _, c := range cases {
		v := c.in.Value
		_, err := h.requests.Request(t.Context(), adminSubmitter, "sid", c.in)
		var bad *InvalidRequest
		switch {
		case c.cause == "" && !errors.Is(err, ErrUnknownRequest):
			t.Errorf("%s: %v, want ErrUnknownRequest", c.name, err)
		case c.cause != "" && (!errors.As(err, &bad) || bad.Cause != c.cause):
			t.Errorf("%s: %v, want cause %s", c.name, err, c.cause)
		}
		if v.Len() != 0 {
			t.Errorf("%s: the refused value was not destroyed", c.name)
		}
	}
	for _, ok := range []RequestInput{in(KindSetDisplayName, acct, strings.Repeat("é", 255)), in(KindSetEmail, acct, "ana@example.test")} {
		if _, err := h.requests.Request(t.Context(), adminSubmitter, "sid", ok); err != nil {
			t.Errorf("a valid value was refused: %v", err)
		}
	}
	h.runner.Wait()
	if js, _ := h.jobs.ListJobs(t.Context(), 100); len(js) != 2 {
		t.Errorf("%d jobs, want only the two valid ones", len(js))
	}
}

// TC-994-21 (the service's part): a facts read that fails at request time
// asks for a fresh sign-in; a kind-table refusal is the table's.
func TestRequests_TC994_21_DependencyDown(t *testing.T) {
	h := newChangeHarness(t)
	h.factsC.err = errors.New("identity down")
	for _, c := range []struct{ kind, spec string }{
		{KindSetRoles, `{"accountId":"` + target + `","role":"operator"}`},
		{KindGrantAccess, `{"accountId":"` + target + `","level":"admin"}`},
		{KindSetNetwork, `{"accountId":"` + target + `","grants":["join"]}`},
	} {
		ans, err := h.requests.Request(t.Context(), adminSubmitter, "sid", RequestInput{Kind: c.kind, Spec: json.RawMessage(c.spec)})
		if err != nil || ans.Fresh == nil {
			t.Errorf("%s: %+v, %v, want a fresh sign-in", c.kind, ans, err)
		}
	}
	recs := h.clog.Matching(slog.LevelWarn, "fresh sign-in")
	if len(recs) != 3 {
		t.Errorf("%d facts_unreadable records", len(recs))
	}
	// Each record names its kind, the table's constant (F-994-15).
	for i, want := range []string{KindSetRoles, KindGrantAccess, KindSetNetwork} {
		if i >= len(recs) {
			break
		}
		got := ""
		recs[i].Attrs(func(a slog.Attr) bool {
			if a.Key == "kind" {
				got = a.Value.String()
			}
			return true
		})
		if got != want {
			t.Errorf("record %d names kind %q, want %q", i, got, want)
		}
	}
	_, err := h.requests.Request(t.Context(), who("viewer-sub", "viewer"), "sid",
		RequestInput{Kind: KindSetRoles, Spec: json.RawMessage(`{"accountId":"` + target + `","role":"viewer"}`)})
	var kr *authz.KindRefusal
	if !errors.As(err, &kr) || kr.Code != authz.CodeNotPermitted {
		t.Errorf("a viewer's set_roles: %v", err)
	}
	if _, err := NewRequests(RequestsDeps{}); err == nil {
		t.Error("NewRequests accepted no collaborators")
	}
	if _, err := NewChanges(ChangesDeps{}); err == nil {
		t.Error("NewChanges accepted no collaborators")
	}
	if _, err := NewFreshAction(nil, nil); err == nil {
		t.Error("NewFreshAction accepted no collaborators")
	}
}

// F-994-01: the Observer as a drain sink. A sign-in or a stored second
// step for a complete designated account submits the grant; an incomplete
// or absent designation, another event or a failed one submits nothing; a
// read error submits nothing and is one WARN.
func TestObserver_F994_01_UserEvent(t *testing.T) {
	cases := []struct {
		name   string
		des    *Designation
		facts  authz.AccountFacts
		readEr error
		event  events.UserEvent
		submit bool
		warn   bool
	}{
		{"complete, login", &Designation{Sub: "u", AppRole: AppAdmin, Reason: ReasonPrivileged}, complete, nil,
			events.UserEvent{Type: "LOGIN", UserID: "u"}, true, false},
		{"complete, totp stored", &Designation{Sub: "u", Network: "gear-admin", Reason: ReasonPrivileged}, complete, nil,
			events.UserEvent{Type: "UPDATE_TOTP", UserID: "u"}, true, false},
		{"complete, credential stored", &Designation{Sub: "u", ConsoleRole: "operator", Reason: ReasonPrivileged}, complete, nil,
			events.UserEvent{Type: "UPDATE_CREDENTIAL", UserID: "u"}, true, false},
		{"incomplete", &Designation{Sub: "u", AppRole: AppAdmin, Reason: ReasonPrivileged}, authz.AccountFacts{Sub: "u"}, nil,
			events.UserEvent{Type: "LOGIN", UserID: "u"}, false, false},
		{"absent", nil, complete, nil, events.UserEvent{Type: "LOGIN", UserID: "u"}, false, false},
		{"another event", &Designation{Sub: "u", AppRole: AppAdmin, Reason: ReasonPrivileged}, complete, nil,
			events.UserEvent{Type: "LOGOUT", UserID: "u"}, false, false},
		{"a failed login", &Designation{Sub: "u", AppRole: AppAdmin, Reason: ReasonPrivileged}, complete, nil,
			events.UserEvent{Type: "LOGIN", UserID: "u", Error: "invalid_user_credentials"}, false, false},
		{"a read error", &Designation{Sub: "u", AppRole: AppAdmin, Reason: ReasonPrivileged}, complete, errors.New("down"),
			events.UserEvent{Type: "LOGIN", UserID: "u"}, false, true},
	}
	for _, c := range cases {
		r := &grantRig{log: &callLog{}, fail: map[string]error{}, facts: c.facts, des: map[string]Designation{}}
		if c.des != nil {
			r.des["u"] = *c.des
		}
		if c.readEr != nil {
			r.fail["Facts"] = c.readEr
		}
		runner := &countRunner{}
		log, rec := logkittest.New()
		o, err := NewObserver(ObserverDeps{Designations: gDes{r}, Facts: gFacts{r}, Runner: runner, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		o.UserEvent(t.Context(), c.event)
		if (runner.n == 1) != c.submit || runner.n > 1 {
			t.Errorf("%s: %d submissions, want submit %v", c.name, runner.n, c.submit)
		}
		if warned := len(rec.Matching(slog.LevelWarn, "")) == 1; warned != c.warn {
			t.Errorf("%s: warned %v", c.name, warned)
		}
		if strings.Contains(rec.Text(), "\"u\"") || strings.Contains(rec.Text(), "=u ") {
			t.Errorf("%s: a record names the account: %s", c.name, rec.Text())
		}
	}
}

// countRunner counts the grants submitted.
type countRunner struct{ n int }

func (c *countRunner) Submit(context.Context, string, any, string) (*jobs.Job, error) {
	c.n++
	return &jobs.Job{ID: "j"}, nil
}
