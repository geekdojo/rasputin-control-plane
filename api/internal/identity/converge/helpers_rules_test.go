package converge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// The fake's sign-in rules state: Keycloak's flows, executions and configs,
// required actions, user profile, client scopes, console roles and default
// role composites, applied as the Admin API applies them.

type fflow struct {
	id, alias string
	top       bool
	execs     []*fexec
}

type fexec struct {
	id, provider, sub, requirement, config string
	priority                               int
}

type fakeRules struct {
	flows        map[string]*fflow // by alias
	configs      map[string]authConfig
	actions      []requiredAction
	unregistered []map[string]any
	profile      map[string]any
	scopes       map[string]string // name → id
	consoleRoles []string
	defaultRoles []role
	nextID       int
}

func (r *fakeRules) id(kind string) string {
	r.nextID++
	return fmt.Sprintf("%s-%d", kind, r.nextID)
}

// newFakeRules is a freshly imported baseline's rules state: empty flow
// shells, Keycloak's stock required actions and profile, the stock default
// role composites.
func newFakeRules() *fakeRules {
	r := &fakeRules{flows: map[string]*fflow{}, configs: map[string]authConfig{}, scopes: map[string]string{}}
	for _, v := range append(flows.Variants, -1) {
		alias := "rasputin-reset"
		if v >= 0 {
			alias = v.Alias()
		}
		r.flows[alias] = &fflow{id: r.id("flow"), alias: alias, top: true}
	}
	for _, a := range []string{"TERMS_AND_CONDITIONS", "UPDATE_PROFILE", "VERIFY_EMAIL", "CONFIGURE_TOTP", "UPDATE_PASSWORD",
		"webauthn-register", "webauthn-register-passwordless", "VERIFY_PROFILE", "delete_credential", "CONFIGURE_RECOVERY_AUTHN_CODES"} {
		r.actions = append(r.actions, requiredAction{Alias: a, Name: a, ProviderID: a, Enabled: a != "TERMS_AND_CONDITIONS", Config: map[string]string{}})
	}
	r.profile = map[string]any{"attributes": []any{
		map[string]any{"name": "username", "displayName": "${username}", "validations": map[string]any{
			"length": map[string]any{"min": 3, "max": 255}, "username-prohibited-characters": map[string]any{}, "up-username-not-idn-homograph": map[string]any{}}},
		map[string]any{"name": "email", "displayName": "${email}"},
		map[string]any{"name": "firstName", "displayName": "${firstName}"},
		map[string]any{"name": "lastName", "displayName": "${lastName}"},
	}, "groups": []any{}}
	for _, s := range []string{"basic", "profile", "email", "roles", "web-origins", "acr", "kc-admin-api", "rasputin-console-roles", "offline_access"} {
		r.scopes[s] = "scope-" + s
	}
	r.consoleRoles = []string{"admin", "operator", "viewer"}
	r.defaultRoles = []role{{ID: "role-offline", Name: "offline_access"}, {ID: "role-uma", Name: "uma_authorization"}}
	return r
}

// flatten lists a flow's executions as the executions listing does.
func (r *fakeRules) flatten(f *fflow, level int, out *[]map[string]any) {
	for i, e := range f.execs {
		m := map[string]any{"id": e.id, "requirement": e.requirement, "level": level, "index": i, "priority": e.priority}
		if e.sub != "" {
			sub := r.flows[e.sub]
			m["displayName"], m["authenticationFlow"], m["flowId"] = sub.alias, true, sub.id
		} else {
			m["displayName"], m["providerId"] = e.provider, e.provider
		}
		if e.config != "" {
			m["authenticationConfig"] = e.config
		}
		*out = append(*out, m)
		if e.sub != "" {
			r.flatten(r.flows[e.sub], level+1, out)
		}
	}
}

// exec finds an execution and its flow.
func (r *fakeRules) exec(id string) (*fflow, int) {
	for _, f := range r.flows {
		for i, e := range f.execs {
			if e.id == id {
				return f, i
			}
		}
	}
	return nil, -1
}

// deepDelete removes an execution, its sub-flow's executions and every
// config among them.
func (r *fakeRules) deepDelete(e *fexec) {
	if e.config != "" {
		delete(r.configs, e.config)
	}
	if e.sub != "" {
		for _, c := range r.flows[e.sub].execs {
			r.deepDelete(c)
		}
		delete(r.flows, e.sub)
	}
}

func notFound(path string) error {
	return &idclient.Error{Op: "admin", Path: path, Status: 404, Kind: idclient.ErrNotFound}
}

// rules serves the rules' Admin API paths, holding f.mu. ok is false for a
// path it does not serve.
func (f *fakeKC) rules(method, path string, body []byte, out any) (idclient.Response, error, bool) {
	r := f.rulesState
	p, found := strings.CutPrefix(path, realmPath)
	if !found {
		return idclient.Response{}, nil, false
	}
	ok200 := func(v any) (idclient.Response, error, bool) {
		return idclient.Response{Status: 200}, roundTrip(v, out), true
	}
	done := func() (idclient.Response, error, bool) { return idclient.Response{Status: 204}, nil, true }
	write := !f.ignoreWrites
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case method == http.MethodGet && p == "/authentication/flows":
		var list []map[string]any
		for _, fl := range r.flows {
			if fl.top {
				list = append(list, map[string]any{"id": fl.id, "alias": fl.alias})
			}
		}
		return ok200(list)
	case len(parts) == 4 && parts[0] == "authentication" && parts[1] == "flows" && parts[3] == "executions":
		fl := r.flows[parts[2]]
		if fl == nil {
			return idclient.Response{}, notFound(path), true
		}
		switch method {
		case http.MethodGet:
			list := []map[string]any{}
			r.flatten(fl, 0, &list)
			return ok200(list)
		case http.MethodPut:
			if write {
				ef, i := r.exec(fmt.Sprint(in["id"]))
				if ef == nil {
					return idclient.Response{}, notFound(path), true
				}
				ef.execs[i].requirement = fmt.Sprint(in["requirement"])
			}
			return done()
		}
	case method == http.MethodPost && len(parts) == 5 && parts[1] == "flows" && parts[3] == "executions":
		fl := r.flows[parts[2]]
		if fl == nil {
			return idclient.Response{}, notFound(path), true
		}
		if !write {
			return done()
		}
		e := &fexec{id: r.id("exec"), requirement: "DISABLED", priority: 10 * (len(fl.execs) + 1)}
		if parts[4] == "flow" {
			alias := fmt.Sprint(in["alias"])
			if _, taken := r.flows[alias]; taken {
				return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Status: 409, Kind: idclient.ErrConflict}, true
			}
			r.flows[alias] = &fflow{id: r.id("flow"), alias: alias}
			e.sub = alias
		} else {
			e.provider = fmt.Sprint(in["provider"])
		}
		fl.execs = append(fl.execs, e)
		return idclient.Response{Status: 201}, nil, true
	case method == http.MethodDelete && len(parts) == 3 && parts[1] == "executions":
		if write {
			fl, i := r.exec(parts[2])
			if fl == nil {
				return idclient.Response{}, notFound(path), true
			}
			r.deepDelete(fl.execs[i])
			fl.execs = append(fl.execs[:i], fl.execs[i+1:]...)
		}
		return done()
	case method == http.MethodPost && len(parts) == 4 && parts[1] == "executions" && parts[3] == "config":
		if write {
			fl, i := r.exec(parts[2])
			if fl == nil {
				return idclient.Response{}, notFound(path), true
			}
			id := r.id("config")
			cfg := map[string]string{}
			_ = roundTrip(in["config"], &cfg)
			r.configs[id] = authConfig{ID: id, Alias: fmt.Sprint(in["alias"]), Config: cfg}
			fl.execs[i].config = id
		}
		return idclient.Response{Status: 201}, nil, true
	case method == http.MethodGet && len(parts) == 3 && parts[1] == "config":
		c, ok := r.configs[parts[2]]
		if !ok {
			return idclient.Response{}, notFound(path), true
		}
		return ok200(c)
	case method == http.MethodGet && p == "/authentication/required-actions":
		return ok200(r.actions)
	case method == http.MethodGet && p == "/authentication/unregistered-required-actions":
		return ok200(r.unregistered)
	case method == http.MethodPost && p == "/authentication/register-required-action":
		if write {
			id := fmt.Sprint(in["providerId"])
			r.actions = append(r.actions, requiredAction{Alias: id, ProviderID: id, Name: fmt.Sprint(in["name"]), Enabled: true, Config: map[string]string{}})
			r.unregistered = slices.DeleteFunc(r.unregistered, func(m map[string]any) bool { return m["providerId"] == id })
		}
		return done()
	case method == http.MethodPut && len(parts) >= 3 && parts[1] == "required-actions":
		i := slices.IndexFunc(r.actions, func(a requiredAction) bool { return a.Alias == parts[2] })
		if i < 0 {
			return idclient.Response{}, notFound(path), true
		}
		if write {
			if len(parts) == 4 {
				cfg := map[string]string{}
				_ = roundTrip(in["config"], &cfg)
				r.actions[i].Config = cfg
			} else {
				var a requiredAction
				_ = json.Unmarshal(body, &a)
				r.actions[i].Enabled, r.actions[i].DefaultAction = a.Enabled, a.DefaultAction
			}
		}
		return done()
	case p == "/users/profile":
		if method == http.MethodGet {
			return ok200(r.profile)
		}
		if write {
			r.profile = in
		}
		return done()
	case method == http.MethodGet && p == "/client-scopes":
		var list []map[string]any
		for n, id := range r.scopes {
			list = append(list, map[string]any{"id": id, "name": n})
		}
		return ok200(list)
	case p == "/roles/"+flows.DefaultRolesName+"/composites":
		if method == http.MethodGet {
			return ok200(r.defaultRoles)
		}
		if write {
			var gone []role
			_ = json.Unmarshal(body, &gone)
			r.defaultRoles = slices.DeleteFunc(r.defaultRoles, func(x role) bool {
				return slices.ContainsFunc(gone, func(g role) bool { return g.ID == x.ID })
			})
		}
		return done()
	case len(parts) == 3 && parts[0] == "clients" && parts[2] == "roles":
		if method == http.MethodGet {
			var list []role
			for _, n := range r.consoleRoles {
				list = append(list, role{ID: "role-" + n, Name: n})
			}
			return ok200(list)
		}
		if write {
			r.consoleRoles = append(r.consoleRoles, fmt.Sprint(in["name"]))
		}
		return idclient.Response{Status: 201}, nil, true
	case len(parts) == 4 && parts[0] == "clients" && strings.HasSuffix(parts[2], "-client-scopes"):
		c := f.clientByID(parts[1])
		if c == nil {
			return idclient.Response{}, notFound(path), true
		}
		if write {
			key := "defaultClientScopes"
			if strings.HasPrefix(parts[2], "optional") {
				key = "optionalClientScopes"
			}
			name := ""
			for n, id := range r.scopes {
				if id == parts[3] {
					name = n
				}
			}
			var have []string
			_ = roundTrip(c[key], &have)
			have = slices.DeleteFunc(have, func(s string) bool { return s == name })
			if method == http.MethodPut {
				have = append(have, name)
			}
			c[key] = have
		}
		return done()
	}
	return idclient.Response{}, nil, false
}

func (f *fakeKC) clientByID(id string) map[string]any {
	for _, c := range f.clients {
		if c["id"] == id {
			return c
		}
	}
	return nil
}
