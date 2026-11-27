package accounts

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// The fake Admin API's definitions (geekdojo/geekdojo-brain#994 PR 2):
// realm groups and memberships, the user profile and client scopes with
// their mappers, as Keycloak 26.8.2 answers them. Each write is in the call
// log; the fake's lock is held.

type fakeScope struct {
	id, name string
	mappers  []map[string]any
}

type fakeDefs struct {
	n       int
	groups  []Group
	members map[string][]string
	profile map[string]any
	scopes  []*fakeScope
}

func (d *fakeDefs) next(prefix string) string {
	d.n++
	return prefix + strconv.Itoa(d.n)
}

func conflict(path string) error {
	return &idclient.Error{Op: "admin", Path: path, Status: http.StatusConflict, Kind: idclient.ErrConflict}
}

// isDefinition reports whether parts is a definitions path.
func (k *fakeKC) isDefinition(parts []string) bool {
	switch {
	case parts[0] == "groups", parts[0] == "client-scopes":
		return true
	case parts[0] != "users" || len(parts) < 2:
		return false
	}
	return parts[1] == "profile" || len(parts) >= 3 && parts[2] == "groups"
}

func (k *fakeKC) definitions(method, path string, parts []string, body []byte, out any) (idclient.Response, error) {
	d := &k.defs
	if d.members == nil {
		d.members = map[string][]string{}
	}
	if d.profile == nil {
		d.profile = map[string]any{"attributes": []any{map[string]any{"name": "username"}}, "groups": []any{}}
	}
	ok := idclient.Response{Status: http.StatusOK}
	scope := func(id string) *fakeScope {
		for _, s := range d.scopes {
			if s.id == id {
				return s
			}
		}
		return nil
	}
	switch {
	case parts[0] == "groups" && len(parts) == 1 && method == http.MethodGet:
		answer(out, d.groups)
	case parts[0] == "groups" && len(parts) == 1 && method == http.MethodPost:
		var g Group
		_ = json.Unmarshal(body, &g)
		if slices.ContainsFunc(d.groups, func(x Group) bool { return x.Name == g.Name }) {
			return idclient.Response{}, conflict(path)
		}
		g.ID = d.next("g")
		d.groups = append(d.groups, g)
		k.log.add("define-group:" + g.Name)
		return idclient.Response{Status: http.StatusCreated, Location: "https://kc.invalid/admin/realms/" + realm + "/groups/" + g.ID}, nil
	case parts[0] == "groups" && len(parts) == 2 && method == http.MethodDelete:
		i := slices.IndexFunc(d.groups, func(x Group) bool { return x.ID == parts[1] })
		if i < 0 {
			return idclient.Response{}, notFound(path)
		}
		d.groups = slices.Delete(d.groups, i, i+1)
		for sub, gs := range d.members {
			d.members[sub] = slices.DeleteFunc(gs, func(g string) bool { return g == parts[1] })
		}
		k.log.add("delete-group:" + parts[1])
	case parts[0] == "users" && parts[1] == "profile" && method == http.MethodGet:
		answer(out, d.profile)
	case parts[0] == "users" && parts[1] == "profile" && method == http.MethodPut:
		var p map[string]any
		_ = json.Unmarshal(body, &p)
		d.profile = p
		k.log.add("put-profile")
	case parts[0] == "users":
		if k.users[parts[1]] == nil {
			return idclient.Response{}, notFound(path)
		}
		sub := parts[1]
		switch {
		case len(parts) == 3 && method == http.MethodGet:
			var list []Group
			for _, g := range d.groups {
				if slices.Contains(d.members[sub], g.ID) {
					list = append(list, g)
				}
			}
			answer(out, list)
		case len(parts) == 4 && !slices.ContainsFunc(d.groups, func(x Group) bool { return x.ID == parts[3] }):
			return idclient.Response{}, notFound(path)
		case len(parts) == 4 && method == http.MethodPut:
			if !slices.Contains(d.members[sub], parts[3]) {
				d.members[sub] = append(d.members[sub], parts[3])
			}
			k.log.add("join:" + parts[3])
		case len(parts) == 4 && method == http.MethodDelete:
			d.members[sub] = slices.DeleteFunc(d.members[sub], func(g string) bool { return g == parts[3] })
			k.log.add("leave:" + parts[3])
		}
	case len(parts) == 1 && method == http.MethodGet:
		var list []map[string]string
		for _, s := range d.scopes {
			list = append(list, map[string]string{"id": s.id, "name": s.name})
		}
		answer(out, list)
	case len(parts) == 1 && method == http.MethodPost:
		var rep struct{ Name string }
		_ = json.Unmarshal(body, &rep)
		if slices.ContainsFunc(d.scopes, func(s *fakeScope) bool { return s.name == rep.Name }) {
			return idclient.Response{}, conflict(path)
		}
		d.scopes = append(d.scopes, &fakeScope{id: d.next("cs"), name: rep.Name})
		k.log.add("create-scope:" + rep.Name)
		return idclient.Response{Status: http.StatusCreated}, nil
	case scope(parts[1]) == nil:
		return idclient.Response{}, notFound(path)
	case len(parts) == 2 && method == http.MethodDelete:
		s := scope(parts[1])
		d.scopes = slices.DeleteFunc(d.scopes, func(x *fakeScope) bool { return x == s })
		k.log.add("delete-scope:" + s.name)
	case len(parts) == 4 && method == http.MethodGet:
		answer(out, scope(parts[1]).mappers)
	case len(parts) == 4 && method == http.MethodPost:
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		m["id"] = d.next("m")
		s := scope(parts[1])
		s.mappers = append(s.mappers, m)
		k.log.add("add-mapper:" + m["protocolMapper"].(string))
	case len(parts) == 5 && method == http.MethodPut:
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		s := scope(parts[1])
		i := slices.IndexFunc(s.mappers, func(x map[string]any) bool { return x["id"] == parts[4] })
		if i < 0 {
			return idclient.Response{}, notFound(path)
		}
		s.mappers[i] = m
		k.log.add("put-mapper:" + m["protocolMapper"].(string))
	default:
		return idclient.Response{}, notFound(path)
	}
	return ok, nil
}

// profileAttr is the user profile's attribute name, nil when it has none.
func (k *fakeKC) profileAttr(name string) map[string]any {
	k.mu.Lock()
	defer k.mu.Unlock()
	attrs, _ := k.defs.profile["attributes"].([]any)
	for _, a := range attrs {
		if m, _ := a.(map[string]any); m["name"] == name {
			return m
		}
	}
	return nil
}

// scopeNamed is the client scope name, nil when the realm has none.
func (k *fakeKC) scopeNamed(name string) *fakeScope {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, s := range k.defs.scopes {
		if s.name == name {
			return s
		}
	}
	return nil
}
