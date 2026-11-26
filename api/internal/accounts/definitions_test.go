package accounts

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The definitions of Identity 4.12 (geekdojo/geekdojo-brain#994 PR 2) over
// #991's harness: the real Users and Changes over the fake Admin API, on a
// runner the kind table decides.

// lockWatch records every identity-service call a definition makes while
// the one accounts lock is free: the fact "each runs under the lock".
type lockWatch struct {
	mu   sync.Mutex
	free []string
}

func (c *changeHarness) watchLock() *lockWatch {
	w := &lockWatch{}
	c.kc.observe = func(method, rel string) {
		if c.lock.mu.TryLock() {
			c.lock.mu.Unlock()
			w.mu.Lock()
			w.free = append(w.free, method+" "+rel)
			w.mu.Unlock()
		}
	}
	return w
}

func (w *lockWatch) unlocked() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.free)
}

// memberOf is sub's groups in the fake.
func (c *changeHarness) memberOf(sub string) []string {
	c.kc.mu.Lock()
	defer c.kc.mu.Unlock()
	return slices.Sorted(slices.Values(c.kc.defs.members[sub]))
}

// TC-994-42: define_group takes 1 to 40 characters [A-Za-z0-9 _.-] and
// refuses other names; it creates the group, and an existing name reads the
// group back with no error. delete_group removes it. set_groups applies
// only the difference (PUT added, DELETE removed). Each runs under the
// lock, and its spec carries ids only.
func TestDefinitions_TC994_42_Groups(t *testing.T) {
	h := newChangeHarness(t)
	w := h.watchLock()
	for _, bad := range []string{"", strings.Repeat("a", 41), "a/b", "naïve", "tab\there"} {
		if r := h.run(t, adminSubmitter, KindDefineGroup, GroupSpec{Name: bad}, false, ""); r.job.Error != sentenceGroupName {
			t.Errorf("define_group %q: %s %q", bad, r.job.Status, r.job.Error)
		}
	}
	if n := len(h.log.only("define-group")); n != 0 {
		t.Fatalf("a refused name created %d groups", n)
	}
	define := func(name string) (string, string) {
		r := h.run(t, adminSubmitter, KindDefineGroup, GroupSpec{Name: name}, false, "")
		out := r.out(StepChange)
		if r.job.Status != jobs.StatusSucceeded {
			t.Fatalf("define_group %q: %s %q", name, r.job.Status, r.job.Error)
		}
		id, _ := out["groupId"].(string)
		return id, out["outcome"].(string)
	}
	staff, o := define("Staff 1.a_b-c")
	if staff == "" || o != outcomeDefined {
		t.Errorf("define_group: id %q, outcome %q", staff, o)
	}
	again, o := define("Staff 1.a_b-c")
	if again != staff || o != outcomeExists || len(h.log.only("define-group")) != 1 {
		t.Errorf("an existing name: id %q (want %q), outcome %q, creates %v", again, staff, o, h.log.only("define-group"))
	}
	kids, _ := define(strings.Repeat("k", 40))
	guests, _ := define("Guests")

	h.kc.mu.Lock()
	h.kc.defs.members = map[string][]string{target: {staff, guests}}
	h.kc.mu.Unlock()
	r := h.run(t, adminSubmitter, KindSetGroups, GroupsSpec{AccountID: target, GroupIDs: []string{staff, kids, kids}}, false, "")
	if r.job.Status != jobs.StatusSucceeded || !slices.Equal(h.log.only("join", "leave"), []string{"join:" + kids, "leave:" + guests}) ||
		!slices.Equal(h.memberOf(target), slices.Sorted(slices.Values([]string{staff, kids}))) {
		t.Errorf("set_groups: %s %q, writes %v, member of %v", r.job.Status, r.job.Error, h.log.only("join", "leave"), h.memberOf(target))
	}
	if !strings.Contains(string(r.job.Spec), kids) || strings.Contains(string(r.job.Spec), "Staff") {
		t.Errorf("set_groups' spec %s, want ids only", r.job.Spec)
	}
	before := len(h.log.only("join", "leave"))
	if r := h.run(t, adminSubmitter, KindSetGroups, GroupsSpec{AccountID: target, GroupIDs: []string{staff, "g-none"}}, false, ""); r.job.Error != sentenceUnknownGroup ||
		len(h.log.only("join", "leave")) != before {
		t.Errorf("an unknown group: %s %q, writes %v", r.job.Status, r.job.Error, h.log.only("join", "leave"))
	}
	if r := h.run(t, adminSubmitter, KindDeleteGroup, GroupIDSpec{GroupID: kids}, false, ""); r.job.Status != jobs.StatusSucceeded ||
		slices.Contains(h.memberOf(target), kids) || index(h.log.all(), "delete-group:"+kids) < 0 {
		t.Errorf("delete_group: %s %q", r.job.Status, r.job.Error)
	}
	if r := h.run(t, adminSubmitter, KindDeleteGroup, GroupIDSpec{GroupID: kids}, false, ""); r.job.Status != jobs.StatusSucceeded {
		t.Errorf("deleting a group already gone: %s %q", r.job.Status, r.job.Error)
	}
	if r := h.run(t, adminSubmitter, KindSetGroups, GroupsSpec{AccountID: target, GroupIDs: []string{}}, false, ""); r.job.Status != jobs.StatusSucceeded ||
		len(h.memberOf(target)) != 0 {
		t.Errorf("set_groups to none: %s %q, member of %v", r.job.Status, r.job.Error, h.memberOf(target))
	}
	if free := w.unlocked(); len(free) != 0 {
		t.Errorf("calls made with the accounts lock free: %v", free)
	}
}

// claimHarness is a harness with the claim tier defined: text, gold or
// silver.
func claimHarness(t *testing.T) *changeHarness {
	t.Helper()
	h := newChangeHarness(t)
	if r := h.run(t, adminSubmitter, KindDefineClaim, ClaimSpec{Name: "tier", Kind: ClaimText, Values: []string{"gold", "silver", "gold"}}, false, ""); r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("define_claim: %s %q", r.job.Status, r.job.Error)
	}
	return h
}

// TC-994-43: define_claim refuses names failing ^[a-z0-9_]{2,40}$,
// registered OIDC and JWT names, groups, roles, realm_access,
// resource_access and rasputin* (F-994-07). It writes an admin-only profile
// attribute claim_<name> with the kind's validators, and a client scope
// claim-<name> with a user-attribute mapper and a SAML attribute mapper.
// Any chosen client is refused while tiles carry no role-claim name.
// delete_claim removes all of it. set_claims values travel in Held and
// never in the spec.
func TestDefinitions_TC994_43_Claims(t *testing.T) {
	h := newChangeHarness(t)
	refused := map[string]string{
		"a": sentenceClaimName, strings.Repeat("a", 41): sentenceClaimName, "Tier": sentenceClaimName, "ti-er": sentenceClaimName,
		"sub": sentenceClaimReserved, "iss": sentenceClaimReserved, "email": sentenceClaimReserved, "preferred_username": sentenceClaimReserved,
		"azp": sentenceClaimReserved, "groups": sentenceClaimReserved, "roles": sentenceClaimReserved,
		"realm_access": sentenceClaimReserved, "resource_access": sentenceClaimReserved,
		"entitlements": sentenceClaimReserved, "authorization_details": sentenceClaimReserved, "upn": sentenceClaimReserved,
		"rasputin": sentenceClaimReserved, "rasputin_app_role": sentenceClaimReserved, "rasputinx": sentenceClaimReserved,
	}
	for name, want := range refused {
		if r := h.run(t, adminSubmitter, KindDefineClaim, ClaimSpec{Name: name, Kind: ClaimText}, false, ""); r.job.Error != want {
			t.Errorf("define_claim %q: %q, want %q", name, r.job.Error, want)
		}
	}
	others := []struct {
		spec ClaimSpec
		want string
	}{
		{ClaimSpec{Name: "tier", Kind: "date"}, sentenceClaimKind},
		{ClaimSpec{Name: "tier", Kind: ClaimText, Clients: []string{"mealie"}}, sentenceClaimClients},
		{ClaimSpec{Name: "tier", Kind: ClaimBoolean, Values: []string{"true"}}, sentenceClaimBoolean},
		{ClaimSpec{Name: "tier", Kind: ClaimNumber, Values: []string{"1.5"}}, sentenceClaimNumber},
		{ClaimSpec{Name: "tier", Kind: ClaimList, Values: []string{"a\nb"}}, sentenceClaimAllowed},
	}
	for _, c := range others {
		if r := h.run(t, adminSubmitter, KindDefineClaim, c.spec, false, ""); r.job.Error != c.want {
			t.Errorf("define_claim %+v: %q, want %q", c.spec, r.job.Error, c.want)
		}
	}
	if n := len(h.log.only("put-profile", "create-scope")); n != 0 {
		t.Fatalf("a refused claim wrote %d definitions", n)
	}

	h = claimHarness(t)
	w := h.watchLock()
	attr := h.kc.profileAttr("claim_tier")
	want := map[string]any{"name": "claim_tier", "displayName": "tier", "permissions": flows.AdminOnlyPermissions(), "multivalued": false,
		"validations": map[string]any{"length": map[string]any{"min": 1, "max": 255}, "options": map[string]any{"options": []any{"gold", "silver"}}}}
	if !flows.SameJSON(attr, want) {
		t.Errorf("the profile attribute %v, want %v", attr, want)
	}
	s := h.kc.scopeNamed("claim-tier")
	if s == nil || len(s.mappers) != 2 {
		t.Fatalf("the client scope %+v", s)
	}
	byType := map[string]map[string]any{}
	for _, m := range s.mappers {
		byType[m["protocolMapper"].(string)], _ = m["config"].(map[string]any)
	}
	if oidc := byType["oidc-usermodel-attribute-mapper"]; oidc["user.attribute"] != "claim_tier" || oidc["claim.name"] != "tier" ||
		oidc["id.token.claim"] != "true" || oidc["access.token.claim"] != "true" || oidc["userinfo.token.claim"] != "true" {
		t.Errorf("the user-attribute mapper %v", oidc)
	}
	if saml := byType["saml-user-attribute-mapper"]; saml["user.attribute"] != "claim_tier" || saml["attribute.name"] != "tier" {
		t.Errorf("the SAML attribute mapper %v", saml)
	}
	// The kinds' validators: a list holds many; a boolean is true or false;
	// a number is a whole number.
	kinds := map[string]map[string]any{
		ClaimList:    {"multivalued": true, "validations": map[string]any{"length": map[string]any{"min": 1, "max": 255}}},
		ClaimBoolean: {"multivalued": false, "validations": map[string]any{"options": map[string]any{"options": []any{"true", "false"}}}},
		ClaimNumber:  {"multivalued": false, "validations": map[string]any{"integer": map[string]any{}, "options": map[string]any{"options": []any{"1", "2"}}}},
	}
	for kind, wantK := range kinds {
		var vals []string
		if kind == ClaimNumber {
			vals = []string{"1", "2"}
		}
		if r := h.run(t, adminSubmitter, KindDefineClaim, ClaimSpec{Name: "k_" + kind, Kind: kind, Values: vals}, false, ""); r.job.Status != jobs.StatusSucceeded {
			t.Fatalf("define_claim %s: %q", kind, r.job.Error)
		}
		got := h.kc.profileAttr("claim_k_" + kind)
		if !flows.SameJSON(got["multivalued"], wantK["multivalued"]) || !flows.SameJSON(got["validations"], wantK["validations"]) {
			t.Errorf("%s: %v", kind, got)
		}
	}
	// Defined again, the claim's attribute and mappers are replaced, not
	// added beside.
	if r := h.run(t, adminSubmitter, KindDefineClaim, ClaimSpec{Name: "tier", Kind: ClaimList}, false, ""); r.job.Status != jobs.StatusSucceeded ||
		len(h.kc.scopeNamed("claim-tier").mappers) != 2 || len(h.log.only("put-mapper")) != 2 || h.kc.profileAttr("claim_tier")["multivalued"] != true {
		t.Errorf("a redefinition: %s %q, mappers %v", r.job.Status, r.job.Error, h.kc.scopeNamed("claim-tier").mappers)
	}

	r := h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: target}, false, `{"tier":["gold","silver"]}`)
	if r.job.Status != jobs.StatusSucceeded || h.attr(target, "claim_tier") != "gold,silver" || strings.Contains(string(r.job.Spec), "gold") {
		t.Errorf("set_claims: %s %q, value %q, spec %s", r.job.Status, r.job.Error, h.attr(target, "claim_tier"), r.job.Spec)
	}
	if h.attr(target, AttrAppRole) != "user" {
		t.Errorf("set_claims dropped app access: %q", h.attr(target, AttrAppRole))
	}
	if r := h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: target}, false, `{"nope":["x"]}`); r.job.Error != sentenceUnknownClaim {
		t.Errorf("an undefined claim: %q", r.job.Error)
	}
	if r := h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: target}, false, ""); r.job.Error != sentenceValueGone {
		t.Errorf("no held values: %q", r.job.Error)
	}
	h.kc.fail = func(method, path string) error {
		if method == http.MethodPut && path == "/users/"+target {
			return &idclient.Error{Op: "admin", Path: path, Status: http.StatusBadRequest, Kind: idclient.ErrProtocol}
		}
		return nil
	}
	if r := h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: target}, false, `{"tier":["bronze"]}`); r.job.Error != sentenceClaimRefused ||
		h.attr(target, "claim_tier") != "gold,silver" {
		t.Errorf("a value the validators refuse: %q, value %q", r.job.Error, h.attr(target, "claim_tier"))
	}
	h.kc.fail = nil
	if r := h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: target}, false, `{"tier":[]}`); r.job.Status != jobs.StatusSucceeded ||
		h.attr(target, "claim_tier") != "" {
		t.Errorf("an empty list: %s %q, value %q", r.job.Status, r.job.Error, h.attr(target, "claim_tier"))
	}
	h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: target}, false, `{"tier":["gold"]}`)
	h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: adminB}, false, `{"tier":["silver"]}`)

	r = h.run(t, adminSubmitter, KindDeleteClaim, ClaimNameSpec{Name: "tier"}, false, "")
	if r.job.Status != jobs.StatusSucceeded || h.kc.scopeNamed("claim-tier") != nil || h.kc.profileAttr("claim_tier") != nil ||
		h.attr(target, "claim_tier") != "" || h.attr(adminB, "claim_tier") != "" || r.out(StepChange)["values"] != float64(2) {
		t.Errorf("delete_claim: %s %q, out %v", r.job.Status, r.job.Error, r.out(StepChange))
	}
	if i, j := index(h.log.all(), "delete-scope:claim-tier"), len(h.log.all())-1; i < 0 || h.log.all()[j] != "put-profile" {
		t.Errorf("delete_claim's order: %v", h.log.all())
	}
	if r := h.run(t, adminSubmitter, KindDeleteClaim, ClaimNameSpec{Name: "tier"}, false, ""); r.job.Status != jobs.StatusSucceeded {
		t.Errorf("deleting a claim already gone: %s %q", r.job.Status, r.job.Error)
	}
	if free := w.unlocked(); len(free) != 0 {
		t.Errorf("calls made with the accounts lock free: %v", free)
	}
}

// F-994-25: a redefinition is refused, changing nothing, unless every
// account's values of the claim fit the new definition, since a value its
// validators refuse would make every later write of that whole account a
// 400. One every holder fits is written.
func TestDefinitions_F994_25_RedefinitionOverHeldValues(t *testing.T) {
	h := claimHarness(t)
	w := h.watchLock()
	if r := h.run(t, adminSubmitter, KindDefineClaim, ClaimSpec{Name: "tags", Kind: ClaimList}, false, ""); r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("define_claim tags: %s %q", r.job.Status, r.job.Error)
	}
	h.run(t, adminSubmitter, KindSetClaims, AccountSpec{AccountID: target}, false, `{"tags":["a","b"],"tier":["gold"]}`)
	if h.attr(target, "claim_tags") != "a,b" || h.attr(target, "claim_tier") != "gold" {
		t.Fatalf("the held values: tags %q, tier %q", h.attr(target, "claim_tags"), h.attr(target, "claim_tier"))
	}
	writes := func() int { return len(h.log.only("put-profile", "create-scope", "put-mapper", "add-mapper")) }
	refused := []struct {
		name string
		spec ClaimSpec
		attr string
	}{
		{"a list made single-valued over two values", ClaimSpec{Name: "tags", Kind: ClaimText}, "claim_tags"},
		{"an allowed value a holder holds dropped", ClaimSpec{Name: "tier", Kind: ClaimText, Values: []string{"silver"}}, "claim_tier"},
		{"text made a number over a word", ClaimSpec{Name: "tier", Kind: ClaimNumber}, "claim_tier"},
	}
	for _, c := range refused {
		before, attr := writes(), h.kc.profileAttr(c.attr)
		r := h.run(t, adminSubmitter, KindDefineClaim, c.spec, false, "")
		if r.job.Status == jobs.StatusSucceeded || r.job.Error != sentenceClaimHeld {
			t.Errorf("%s: %s %q, want %q", c.name, r.job.Status, r.job.Error, sentenceClaimHeld)
		}
		if writes() != before || !flows.SameJSON(h.kc.profileAttr(c.attr), attr) {
			t.Errorf("%s: wrote %d, attribute %v (was %v)", c.name, writes()-before, h.kc.profileAttr(c.attr), attr)
		}
	}
	if h.attr(target, "claim_tags") != "a,b" || h.attr(target, "claim_tier") != "gold" {
		t.Errorf("a refusal changed the values: tags %q, tier %q", h.attr(target, "claim_tags"), h.attr(target, "claim_tier"))
	}
	r := h.run(t, adminSubmitter, KindDefineClaim, ClaimSpec{Name: "tier", Kind: ClaimList, Values: []string{"gold", "bronze"}}, false, "")
	opts, _ := h.kc.profileAttr("claim_tier")["validations"].(map[string]any)["options"].(map[string]any)
	if r.job.Status != jobs.StatusSucceeded || h.kc.profileAttr("claim_tier")["multivalued"] != true ||
		!flows.SameJSON(opts["options"], []any{"gold", "bronze"}) || h.attr(target, "claim_tier") != "gold" {
		t.Errorf("a redefinition every holder fits: %s %q, attribute %v", r.job.Status, r.job.Error, h.kc.profileAttr("claim_tier"))
	}
	if free := w.unlocked(); len(free) != 0 {
		t.Errorf("calls made with the accounts lock free: %v", free)
	}
}

// The definitions through the request seam (TC-994-20's rules, for PR 2's
// kinds): each spec's fields are decoded strictly, a definition names no
// account, set_claims' values are a value, never a spec field, and a
// definition never needs a fresh sign-in.
func TestRequests_Definitions(t *testing.T) {
	h := claimHarness(t)
	in := func(kind, spec string, value ...string) RequestInput {
		r := RequestInput{Kind: kind, Spec: json.RawMessage(spec)}
		if len(value) > 0 {
			r.Value, r.HasValue = secret.New([]byte(value[0])), true
		}
		return r
	}
	acct := `{"accountId":"` + target + `"}`
	bad := []struct {
		name  string
		in    RequestInput
		cause string
	}{
		{"define_group naming an account", in(KindDefineGroup, `{"name":"a","accountId":"x"}`), "spec_field"},
		{"define_group with no name", in(KindDefineGroup, `{}`), "spec_field"},
		{"delete_group with an empty id", in(KindDeleteGroup, `{"groupId":""}`), "spec_target"},
		{"set_groups with no groups", in(KindSetGroups, acct), "spec_field"},
		{"set_groups with no account", in(KindSetGroups, `{"groupIds":[]}`), "spec_target"},
		{"define_claim with no kind", in(KindDefineClaim, `{"name":"tier"}`), "spec_field"},
		{"set_claims with values in the spec", in(KindSetClaims, `{"accountId":"`+target+`","values":["x"]}`, `{"tier":["x"]}`), "spec_field"},
		{"set_claims with no value", in(KindSetClaims, acct), "value_missing"},
		{"set_claims with a list", in(KindSetClaims, acct, `["x"]`), "value_claims"},
		{"set_claims with no claim", in(KindSetClaims, acct, `{}`), "value_claims"},
		{"set_claims with a bad name", in(KindSetClaims, acct, `{"Tier":["x"]}`), "value_claims"},
		{"set_claims with a reserved name", in(KindSetClaims, acct, `{"email":["x"]}`), "value_claims"},
		{"set_claims with a bare string", in(KindSetClaims, acct, `{"tier":"x"}`), "value_claims"},
		{"set_claims with a null", in(KindSetClaims, acct, `{"tier":null}`), "value_claims"},
		{"set_claims with a control character", in(KindSetClaims, acct, `{"tier":["a\nb"]}`), "value_claims"},
		{"define_claim with a value", in(KindDefineClaim, `{"name":"tier","kind":"text"}`, "x"), "value_unexpected"},
	}
	for _, c := range bad {
		var ir *InvalidRequest
		if _, err := h.requests.Request(t.Context(), adminSubmitter, "sid", c.in); !errors.As(err, &ir) || ir.Cause != c.cause {
			t.Errorf("%s: %v, want cause %s", c.name, err, c.cause)
		}
	}
	ok := []RequestInput{
		in(KindDefineGroup, `{"name":"Staff"}`),
		in(KindDefineClaim, `{"name":"tier","kind":"text","values":["gold"],"clients":[]}`),
		in(KindSetGroups, `{"accountId":"`+target+`","groupIds":[]}`),
		in(KindSetClaims, acct, `{"tier":["gold"]}`),
	}
	for _, x := range ok {
		ans, err := h.requests.Request(t.Context(), adminSubmitter, "sid", x)
		if err != nil || ans.Fresh != nil || ans.Job == nil {
			t.Errorf("%s: %+v, %v", x.Kind, ans, err)
			continue
		}
		if strings.Contains(string(ans.Job.Spec), "gold") && x.Kind == KindSetClaims {
			t.Errorf("set_claims' value is in its spec: %s", ans.Job.Spec)
		}
	}
	h.runner.Wait()
	if r := h.result(t, mustJob(t, h, KindSetClaims)); r.job.Status != jobs.StatusSucceeded || h.attr(target, "claim_tier") != "gold" {
		t.Errorf("set_claims through the seam: %s %q", r.job.Status, r.job.Error)
	}
	// A viewer may define nothing, and nobody sets their own claims.
	var kr *authz.KindRefusal
	if _, err := h.requests.Request(t.Context(), who("viewer-sub", "viewer"), "sid", in(KindDefineGroup, `{"name":"x"}`)); !errors.As(err, &kr) ||
		kr.Code != authz.CodeNotPermitted {
		t.Errorf("a viewer's define_group: %v", err)
	}
	if _, err := h.requests.Request(t.Context(), adminSubmitter, "sid", in(KindSetClaims, `{"accountId":"`+adminA+`"}`, `{"tier":["x"]}`)); !errors.As(err, &kr) ||
		kr.Code != authz.CodeOwnAccount {
		t.Errorf("one's own set_claims: %v", err)
	}
}

// mustJob is the one job of kind in the ledger.
func mustJob(t *testing.T, h *changeHarness, kind string) string {
	t.Helper()
	js, err := h.jobs.ListJobs(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range js {
		if j.Kind == kind {
			return j.ID
		}
	}
	t.Fatalf("no %s job", kind)
	return ""
}

// A definition the identity service fails part way fails its job with the
// definition's sentence, and set_groups a membership write it fails with
// the account's; nothing reports success.
func TestDefinitions_IdentityServiceFailures(t *testing.T) {
	down := func(m, p string) func(method, path string) error {
		return func(method, path string) error {
			if method == m && strings.HasPrefix(path, p) {
				return &idclient.Error{Op: "admin", Path: path, Status: http.StatusServiceUnavailable, Kind: idclient.ErrUnreachable}
			}
			return nil
		}
	}
	cases := []struct {
		name, method, path string
		kind               string
		spec               any
		want               string
	}{
		{"define_group", http.MethodPost, "/groups", KindDefineGroup, GroupSpec{Name: "Staff"}, sentenceDefinition},
		{"delete_group", http.MethodDelete, "/groups/", KindDeleteGroup, GroupIDSpec{GroupID: "g1"}, sentenceDefinition},
		{"define_claim's mappers", http.MethodPost, "/client-scopes/", KindDefineClaim, ClaimSpec{Name: "tier", Kind: ClaimText}, sentenceDefinition},
		{"delete_claim's profile", http.MethodPut, "/users/profile", KindDeleteClaim, ClaimNameSpec{Name: "tier"}, sentenceDefinition},
		{"set_groups' join", http.MethodPut, "/users/" + target + "/groups/", KindSetGroups, GroupsSpec{AccountID: target, GroupIDs: []string{"g1"}}, sentenceChange},
		{"set_groups' group list", http.MethodGet, "/groups", KindSetGroups, GroupsSpec{AccountID: target, GroupIDs: []string{"g1"}}, sentenceCheck},
	}
	for _, c := range cases {
		h := newChangeHarness(t)
		h.kc.mu.Lock()
		h.kc.defs.groups = []Group{{ID: "g1", Name: "Existing"}}
		h.kc.mu.Unlock()
		h.kc.fail = down(c.method, c.path)
		if r := h.run(t, adminSubmitter, c.kind, c.spec, false, ""); r.job.Status != jobs.StatusFailed || r.job.Error != c.want {
			t.Errorf("%s: %s %q, want %q", c.name, r.job.Status, r.job.Error, c.want)
		}
	}
	h := newChangeHarness(t)
	h.kc.mu.Lock()
	h.kc.defs.groups = []Group{{ID: "g1", Name: "Existing"}}
	h.kc.mu.Unlock()
	if r := h.run(t, adminSubmitter, KindDeleteGroup, GroupIDSpec{GroupID: ""}, false, ""); r.job.Error != sentenceNoGroup {
		t.Errorf("delete_group with no id: %q", r.job.Error)
	}
	if r := h.run(t, adminSubmitter, KindDeleteClaim, ClaimNameSpec{Name: "No"}, false, ""); r.job.Error != sentenceClaimName {
		t.Errorf("delete_claim with a bad name: %q", r.job.Error)
	}
}

// F-994-25: fits is the kinds' validators over one account's values.
func TestClaimDef_Fits(t *testing.T) {
	long := strings.Repeat("é", maxText)
	cases := []struct {
		d    ClaimDef
		vs   []string
		want bool
	}{
		{ClaimDef{Kind: ClaimText}, nil, true},
		{ClaimDef{Kind: ClaimText}, []string{long}, true},
		{ClaimDef{Kind: ClaimText}, []string{long + "e"}, false},
		{ClaimDef{Kind: ClaimText}, []string{""}, false},
		{ClaimDef{Kind: ClaimText}, []string{"a", "b"}, false},
		{ClaimDef{Kind: ClaimList}, []string{"a", "b"}, true},
		{ClaimDef{Kind: ClaimList, Values: []string{"a"}}, []string{"a", "b"}, false},
		{ClaimDef{Kind: ClaimBoolean}, []string{"true"}, true},
		{ClaimDef{Kind: ClaimBoolean}, []string{"false"}, true},
		{ClaimDef{Kind: ClaimBoolean}, []string{"yes"}, false},
		{ClaimDef{Kind: ClaimNumber}, []string{"-12"}, true},
		{ClaimDef{Kind: ClaimNumber}, []string{"1.5"}, false},
		{ClaimDef{Kind: ClaimNumber, Values: []string{"1", "2"}}, []string{"2"}, true},
		{ClaimDef{Kind: ClaimNumber, Values: []string{"1", "2"}}, []string{"3"}, false},
	}
	for _, c := range cases {
		if got := c.d.fits(c.vs); got != c.want {
			t.Errorf("%+v fits %q: %v, want %v", c.d, c.vs, got, c.want)
		}
	}
}
