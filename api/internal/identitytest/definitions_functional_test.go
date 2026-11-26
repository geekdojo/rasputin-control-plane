package identitytest

// Identity 4.12's definitions against the real identity service
// (geekdojo/geekdojo-brain#994 PR 2): inside TestConsole_AgainstPinnedKeycloak,
// on the accounts rig, with the definitions' workflows as main registers
// them. TC-994-44 and register rows T279 to T282.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// definitions registers the definitions' workflows on the rig's runner.
func (r *accountsRig) definitions(t *testing.T, changes *accounts.Changes) {
	t.Helper()
	wfs, err := changes.DefinitionWorkflows(r.users)
	if err != nil {
		t.Fatal(err)
	}
	for _, wf := range wfs {
		r.runner.Register(wf)
	}
}

// succeeded fails the test unless j succeeded.
func succeeded(t *testing.T, what string, j *jobs.Job) {
	t.Helper()
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("%s: %s %q", what, j.Status, j.Error)
	}
}

// attrValues is the account's attribute name at the identity service.
func (r *accountsRig) attrValues(t *testing.T, id, name string) []string {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var rep struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	return rep.Attributes[name]
}

// claimScope is the client scope name's mappers' types by user attribute,
// and whether the realm has the scope.
func (r *accountsRig) claimScope(t *testing.T, name string) (map[string]string, bool) {
	t.Helper()
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/client-scopes", nil)
	var scopes []struct{ ID, Name, Protocol string }
	if err := json.Unmarshal(out, &scopes); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(scopes, func(s struct{ ID, Name, Protocol string }) bool { return s.Name == name })
	if i < 0 {
		return nil, false
	}
	_, out = api.must(http.StatusOK, http.MethodGet, "/client-scopes/"+scopes[i].ID+"/protocol-mappers/models", nil)
	var ms []struct {
		ProtocolMapper string            `json:"protocolMapper"`
		Config         map[string]string `json:"config"`
	}
	if err := json.Unmarshal(out, &ms); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range ms {
		got[m.ProtocolMapper] = m.Config["user.attribute"]
	}
	return got, true
}

// TC-994-44: after define_claim and set_claims, the attribute holds the
// value; a value outside the allowed ones is refused (T281); a self profile
// update posting claim_<name> leaves it unchanged; and the scope exists
// with both mappers (T282). delete_claim then removes all of it.
func (r *accountsRig) tc44(t *testing.T) {
	const claim, attr, scope = "tc44_tier", "claim_tc44_tier", "claim-tc44_tier"
	succeeded(t, "define_claim", r.submitted(t, r.actor, accounts.KindDefineClaim,
		`{"name":"`+claim+`","kind":"text","values":["gold","silver"]}`, ""))
	mappers, ok := r.claimScope(t, scope)
	if !ok || mappers["oidc-usermodel-attribute-mapper"] != attr || mappers["saml-user-attribute-mapper"] != attr {
		t.Errorf("the scope %s: %v (present %v), want both mappers on %s", scope, mappers, ok, attr)
	}
	const name = "acct-claims"
	id, pw := r.household(t, name)
	succeeded(t, "set_claims", r.submitted(t, r.actor, accounts.KindSetClaims, spec("accountId", id), `{"`+claim+`":["gold"]}`))
	if got := r.attrValues(t, id, attr); !slices.Equal(got, []string{"gold"}) {
		t.Fatalf("after set_claims the attribute holds %v, want [gold]", got)
	}
	if j := r.submitted(t, r.actor, accounts.KindSetClaims, spec("accountId", id), `{"`+claim+`":["bronze"]}`); j.Status != jobs.StatusFailed ||
		!slices.Equal(r.attrValues(t, id, attr), []string{"gold"}) {
		t.Errorf("a value outside the allowed ones: %s %q, attribute %v", j.Status, j.Error, r.attrValues(t, id, attr))
	}

	// A self profile update: UPDATE_PROFILE enabled for this case, then put
	// back by converge, as TC-987-22 does.
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/authentication/required-actions/UPDATE_PROFILE", nil)
	var ra map[string]any
	if err := json.Unmarshal(out, &ra); err != nil {
		t.Fatal(err)
	}
	ra["enabled"] = true
	api.must(http.StatusNoContent, http.MethodPut, "/authentication/required-actions/UPDATE_PROFILE", ra)
	t.Cleanup(func() {
		if _, err := r.conv.Run(context.Background()); err != nil {
			t.Errorf("converge after the case: %v", err)
		}
	})
	_, out = api.must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	rep["requiredActions"] = []string{"UPDATE_PROFILE"}
	api.must(http.StatusNoContent, http.MethodPut, "/users/"+id, rep)
	g := r.fresh(t)
	r.settle(t)
	page := g.signIn(r.appAuth(doorTestApp, nil), name, pw)
	if page.pageID() != "login-login-update-profile" {
		t.Fatalf("the update action opened %q", page.pageID())
	}
	profile := map[string]string{"firstName": "Claims", "email": name + "@door.invalid"}
	upd := map[string]string{attr: "silver"}
	for k, v := range profile {
		upd[k] = v
	}
	// Keycloak either drops the admin-only field or refuses the post;
	// either way the value is unchanged.
	after := g.submit(page, "kc-update-profile-form", upd)
	t.Logf("the profile update posting %s led to %q (%d)", attr, after.pageID(), after.status)
	if after.pageID() == "login-login-update-profile" {
		after = g.submit(after, "kc-update-profile-form", profile)
	}
	after.code(t)
	if got := r.attrValues(t, id, attr); !slices.Equal(got, []string{"gold"}) {
		t.Errorf("after a self profile update posting %s the attribute holds %v, want [gold]", attr, got)
	}

	succeeded(t, "delete_claim", r.submitted(t, r.actor, accounts.KindDeleteClaim, spec("name", claim), ""))
	if _, ok := r.claimScope(t, scope); ok {
		t.Errorf("the scope %s is still there after delete_claim", scope)
	}
	if got := r.attrValues(t, id, attr); len(got) != 0 {
		t.Errorf("after delete_claim the account holds %v", got)
	}
	_, out = api.must(http.StatusOK, http.MethodGet, "/users/profile", nil)
	var up struct{ Attributes []struct{ Name string } }
	if err := json.Unmarshal(out, &up); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(up.Attributes, func(a struct{ Name string }) bool { return a.Name == attr }) {
		t.Errorf("the user profile still declares %s", attr)
	}
}

// groups is register rows T279 and T280 at the pinned identity service: a
// second define_group of one name meets the 409 and reads the same group
// back; set_groups joins and leaves through the membership PUT and DELETE;
// delete_group removes the group.
func (r *accountsRig) groups(t *testing.T) {
	define := func() string {
		j := r.submitted(t, r.actor, accounts.KindDefineGroup, spec("name", "TC44 Staff"), "")
		succeeded(t, "define_group", j)
		steps, err := r.ledger.ListSteps(t.Context(), j.ID)
		if err != nil || len(steps) != 1 {
			t.Fatalf("define_group's steps: %v, %v", steps, err)
		}
		var o struct{ Outcome, GroupID string }
		if err := json.Unmarshal(steps[0].Result, &o); err != nil || o.GroupID == "" {
			t.Fatalf("define_group's outcome %s", steps[0].Result)
		}
		return o.Outcome + " " + o.GroupID
	}
	first, second := define(), define()
	gid := first[len("defined "):]
	if first[:len("defined ")] != "defined " || second != "exists "+gid {
		t.Errorf("define_group twice: %q then %q", first, second)
	}
	id, _ := r.household(t, "acct-groups")
	member := func() []string {
		ids, err := r.users.GroupIDs(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	succeeded(t, "set_groups", r.submitted(t, r.actor, accounts.KindSetGroups, `{"accountId":"`+id+`","groupIds":["`+gid+`"]}`, ""))
	if got := member(); !slices.Equal(got, []string{gid}) {
		t.Errorf("after set_groups the account is in %v", got)
	}
	succeeded(t, "set_groups", r.submitted(t, r.actor, accounts.KindSetGroups, `{"accountId":"`+id+`","groupIds":[]}`, ""))
	if got := member(); len(got) != 0 {
		t.Errorf("after set_groups to none the account is in %v", got)
	}
	succeeded(t, "delete_group", r.submitted(t, r.actor, accounts.KindDeleteGroup, spec("groupId", gid), ""))
	if code, _, _ := r.admin(t).do(http.MethodGet, "/groups/"+gid, nil); code != http.StatusNotFound {
		t.Errorf("after delete_group the group answers %d", code)
	}
}
