package accounts

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// writes are the identity service's write requests, as "METHOD path".
func (k *fakeKC) writes() []request {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.reqs)
}

// TC-991-19: Access.Grant(user) records the app-access fact before it
// writes rasputin_app_role and adds the offline_access realm role, by
// name; remove_access removes the attribute and then deletes the mapping.
// The paths and bodies match. If the fact can't be recorded, no attribute
// is written.
func TestAccess_C10BothDirections(t *testing.T) {
	h := newHarness(t)
	h.world()
	h.kc.add(person{sub: target, name: "newcomer", email: "n@example.invalid", enabled: true})
	if err := h.access.Grant(t.Context(), target, AppUser); err != nil {
		t.Fatal(err)
	}
	if got := h.effects(); !slices.Equal(got, []string{"fact", "set-attr:user", "add-offline"}) {
		t.Errorf("grant calls %v", got)
	}
	w := h.kc.writes()
	if len(w) != 2 || w[0].method != http.MethodPut || w[0].path != "/users/"+target ||
		w[1].method != http.MethodPost || w[1].path != "/users/"+target+"/role-mappings/realm" {
		t.Fatalf("grant writes %+v", w)
	}
	var put map[string]any
	_ = json.Unmarshal(w[0].body, &put)
	attrs, _ := put["attributes"].(map[string]any)
	if roleOf(attrs) != "user" || attrs["rasputin_second_step_any"] == nil || put["username"] != "newcomer" ||
		put["requiredActions"] != nil || put["enabled"] != nil {
		t.Errorf("the PUT body %s: want the profile fields and the attributes as read, with the role", w[0].body)
	}
	var roles []map[string]string
	_ = json.Unmarshal(w[1].body, &roles)
	if len(roles) != 1 || roles[0]["name"] != offlineAccess {
		t.Errorf("the role body %s", w[1].body)
	}
	if held, _ := h.removed.Facts().Held(t.Context(), target); !held {
		t.Error("the fact is not held")
	}

	h.log.calls, h.kc.reqs = nil, nil
	if r := h.run(t, Spec{AccountID: target, Kind: RemoveAccess}, adminA); r.job.Status != jobs.StatusSucceeded {
		t.Fatal(r.job.Error)
	}
	if got := h.log.only("remove-attr", "remove-offline"); !slices.Equal(got, []string{"remove-attr", "remove-offline"}) {
		t.Errorf("remove calls %v", got)
	}
	var del *request
	for _, r := range h.kc.writes() {
		if r.method == http.MethodDelete && r.path == "/users/"+target+"/role-mappings/realm" {
			del = &r
		}
	}
	if del == nil || !strings.Contains(string(del.body), `"name":"offline_access"`) {
		t.Errorf("the mapping delete %+v", del)
	}

	h = newHarness(t)
	h.world()
	h.facts.err = errors.New("disk full")
	if err := h.access.Grant(t.Context(), target, AppAdmin); err == nil {
		t.Error("a grant whose fact failed succeeded")
	}
	if got := h.log.only("set-attr", "add-offline"); len(got) != 0 {
		t.Errorf("written after the fact failed: %v", got)
	}
}

// TC-991-19, F-991-06: a grant and a remove_access running at once never
// interleave their writes: the accounts lock holds each one's writes
// together.
func TestAccess_GrantAndRemoveNeverInterleave(t *testing.T) {
	for range 25 {
		h := newHarness(t)
		h.world()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); _ = h.access.Grant(t.Context(), target, AppUser) }()
		id := h.submit(t, Spec{AccountID: target, Kind: RemoveAccess}, adminA)
		wg.Wait()
		h.runner.Wait()
		if r := h.result(t, id); r.job.Status != jobs.StatusSucceeded {
			t.Fatal(r.job.Error)
		}
		got := h.log.only("fact", "set-attr", "add-offline", "remove-attr", "remove-offline")
		grant := slices.DeleteFunc(slices.Clone(got), func(c string) bool { return strings.HasPrefix(c, "remove") })
		removal := []string{"remove-attr", "remove-offline"}
		if !slices.Equal(got, slices.Concat(grant, removal)) && !slices.Equal(got, slices.Concat(removal, grant)) {
			t.Fatalf("interleaved writes %v", got)
		}
	}
}

// TC-991-23: Access.Grant(admin) for an account that is not an app
// administrator ends the online and then the offline sessions before the
// attribute is written; for an existing app administrator it ends none;
// when the session end fails, no attribute is written. F-991-05: lowering
// admin to user ends the sessions; giving user access to someone with none
// does not.
func TestAccess_C23Order(t *testing.T) {
	cases := []struct {
		name     string
		from     string
		to       AppLevel
		sessions bool
	}{
		{"raise user to admin", "user", AppAdmin, true},
		{"raise none to admin", "", AppAdmin, true},
		{"already admin", "admin", AppAdmin, false},
		{"lower admin to user", "admin", AppUser, true},
		{"give user to none", "", AppUser, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.kc.add(person{sub: target, name: "t", enabled: true, appRole: c.from, offlineRole: c.from != "",
				offline: map[string][]string{appUUID: {"s1"}}})
			if err := h.access.Grant(t.Context(), target, c.to); err != nil {
				t.Fatal(err)
			}
			want := []string{"fact"}
			if c.sessions {
				want = []string{"logout", "offline-delete:s1", "fact"}
			}
			if c.from != string(c.to) {
				want = append(want, "set-attr:"+string(c.to))
			}
			if c.from == "" {
				want = append(want, "add-offline")
			}
			if got := h.effects(); !slices.Equal(got, want) {
				t.Errorf("calls %v, want %v", got, want)
			}
		})
	}
	for _, failing := range []string{"/logout", "/offline-sessions/"} {
		h := newHarness(t)
		h.kc.add(person{sub: target, name: "t", enabled: true, appRole: "user", offlineRole: true})
		h.kc.fail = func(_, p string) error {
			if strings.Contains(p, failing) {
				return &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
			}
			return nil
		}
		if err := h.access.Grant(t.Context(), target, AppAdmin); !errors.Is(err, idclient.ErrUnreachable) {
			t.Errorf("%s failing: %v", failing, err)
		}
		if got := h.log.only("fact", "set-attr", "add-offline"); len(got) != 0 {
			t.Errorf("%s failing: written %v", failing, got)
		}
	}
	h := newHarness(t)
	if err := h.access.Grant(t.Context(), target, "owner"); err == nil {
		t.Error("an unknown level was granted")
	}
	if err := h.access.Grant(t.Context(), "nobody", AppUser); !errors.Is(err, idclient.ErrNotFound) {
		t.Errorf("a missing account: %v", err)
	}
}
