package converge

// The sign-in rules (geekdojo/geekdojo-brain#987, Identity 4.5): converge
// reads, compares and writes the seven flows and the reset flow, the required actions, the user
// profile, the console roles, the default roles' composites and the own
// clients' scopes and bindings, all rendered by package flows.

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// errFlowRebuild is a flow rebuild that could not finish. The flow is left
// with its top level disabled, which admits nobody.
const errFlowRebuild = stepError("A sign-in rule could not be rebuilt; administrator tools stay locked until it is.")

// execution is one execution as the flow executions listing returns it.
type execution struct {
	ID                   string `json:"id"`
	Requirement          string `json:"requirement"`
	DisplayName          string `json:"displayName"`
	AuthenticationFlow   bool   `json:"authenticationFlow"`
	FlowID               string `json:"flowId"`
	ProviderID           string `json:"providerId"`
	Level                int    `json:"level"`
	Index                int    `json:"index"`
	AuthenticationConfig string `json:"authenticationConfig"`
	Priority             int    `json:"priority"`
}

// authConfig is an authenticator config.
type authConfig struct {
	ID     string            `json:"id"`
	Alias  string            `json:"alias"`
	Config map[string]string `json:"config"`
}

// requiredAction is a required action as listed.
type requiredAction struct {
	Alias         string            `json:"alias"`
	Name          string            `json:"name"`
	ProviderID    string            `json:"providerId"`
	Enabled       bool              `json:"enabled"`
	DefaultAction bool              `json:"defaultAction"`
	Priority      int               `json:"priority"`
	Config        map[string]string `json:"config"`
}

// role is a role as listed.
type role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// observedRules is one reading of what the rules own.
type observedRules struct {
	// flowIDs are the top-level flows' ids, by alias.
	flowIDs map[string]string
	// steps are each owned flow's executions, flattened, by alias; execs the
	// same as listed.
	steps map[string][]flows.Step
	execs map[string][]execution
	// actions are the listed required actions; unregistered the ones the
	// server can register.
	actions      []requiredAction
	unregistered []map[string]any
	profile      json.RawMessage
	consoleRoles []string
	defaultRoles []role
	// scopeIDs are the realm's client scopes' ids, by name.
	scopeIDs map[string]string
}

// observeRules reads what the rules own.
func (c *Converger) observeRules(ctx context.Context) (observedRules, error) {
	o := observedRules{flowIDs: map[string]string{}, steps: map[string][]flows.Step{}, execs: map[string][]execution{}, scopeIDs: map[string]string{}}
	var top []struct{ ID, Alias string }
	if err := c.get(ctx, "/authentication/flows", &top); err != nil {
		return o, err
	}
	for _, f := range top {
		o.flowIDs[f.Alias] = f.ID
	}
	for _, alias := range flows.Aliases() {
		var execs []execution
		if err := c.get(ctx, "/authentication/flows/"+url.PathEscape(alias)+"/executions", &execs); err != nil {
			return o, err
		}
		steps := make([]flows.Step, 0, len(execs))
		for _, e := range execs {
			s := flows.Step{Level: e.Level, Index: e.Index, Requirement: flows.Requirement(e.Requirement)}
			if e.AuthenticationFlow {
				s.Alias = e.DisplayName
			} else {
				s.Provider = e.ProviderID
			}
			if e.AuthenticationConfig != "" {
				var cfg authConfig
				if err := c.get(ctx, "/authentication/config/"+url.PathEscape(e.AuthenticationConfig), &cfg); err != nil {
					return o, err
				}
				s.ConfigAlias, s.Config = cfg.Alias, cfg.Config
			}
			steps = append(steps, s)
		}
		o.steps[alias], o.execs[alias] = steps, execs
	}
	if err := c.get(ctx, "/authentication/required-actions", &o.actions); err != nil {
		return o, err
	}
	if err := c.get(ctx, "/authentication/unregistered-required-actions", &o.unregistered); err != nil {
		return o, err
	}
	if err := c.get(ctx, "/users/profile", &o.profile); err != nil {
		return o, err
	}
	var scopes []struct{ ID, Name string }
	if err := c.get(ctx, "/client-scopes", &scopes); err != nil {
		return o, err
	}
	for _, s := range scopes {
		o.scopeIDs[s.Name] = s.ID
	}
	if err := c.get(ctx, "/roles/"+url.PathEscape(flows.DefaultRolesName)+"/composites", &o.defaultRoles); err != nil {
		return o, err
	}
	return o, nil
}

// observeConsoleRoles reads the console client's roles once its internal id
// is known.
func (c *Converger) observeConsoleRoles(ctx context.Context, o *observed) error {
	cl, ok := o.clients[flows.ConsoleClient]
	if !ok {
		return nil // reported as client.rasputin-console.missing
	}
	var roles []role
	if err := c.get(ctx, "/clients/"+url.PathEscape(cl.ID)+"/roles", &roles); err != nil {
		return err
	}
	for _, r := range roles {
		o.rules.consoleRoles = append(o.rules.consoleRoles, r.Name)
	}
	return nil
}

func (c *Converger) get(ctx context.Context, path string, out any) error {
	_, err := c.d.Admin.Admin(ctx, http.MethodGet, c.realmPath()+path, nil, out)
	return err
}

// ruleWrites are the writes the rules call for, besides the realm and
// client PUT bodies, which diff merges into writes.realm and writes.clients.
type ruleWrites struct {
	// rebuild are the variants whose flow is rebuilt, by alias.
	rebuild []string
	// register are the owned actions to register first, as the server
	// offers them.
	register []map[string]any
	// actions are the required-action PUT bodies, by alias; configs the
	// config PUT bodies.
	actions     map[string]requiredAction
	actionOrder []string
	configs     map[string]map[string]string
	configOrder []string
	// profile is the profile PUT body, nil for none.
	profile map[string]any
	// roles are the console roles to create.
	roles []string
	// composites are the default role's composites to remove.
	composites []role
	// scopes are the scope additions and removals.
	scopes []scopeWrite
}

// scopeWrite adds (or removes) a default or optional scope on a client.
type scopeWrite struct {
	clientID, scopeID, kind string
	remove                  bool
}

// diffRules compares the rules part of o with d and adds what it calls for
// to w, naming each drifted field.
func diffRules(d Desired, o observed, w *writes) {
	r := d.Rules
	// Flows: each owned flow whose executions differ is rebuilt whole.
	for _, alias := range flows.Aliases() {
		if _, ok := o.rules.flowIDs[alias]; !ok {
			w.fields = append(w.fields, "flow."+alias+".missing")
			continue
		}
		if !flows.SameSteps(flows.Flatten(alias, r.Flows[alias]), o.rules.steps[alias]) {
			w.fields = append(w.fields, "flow."+alias)
			w.rules.rebuild = append(w.rules.rebuild, alias)
		}
	}

	// Required actions.
	listed := make([]string, 0, len(o.rules.actions))
	byAlias := map[string]requiredAction{}
	for _, a := range o.rules.actions {
		listed = append(listed, a.Alias)
		byAlias[a.Alias] = a
	}
	w.rules.actions, w.rules.configs = map[string]requiredAction{}, map[string]map[string]string{}
	for _, want := range flows.RequiredActions(d.flowsIn, listed) {
		got, ok := byAlias[want.Alias]
		if !ok {
			// Only an owned action can be missing: register it as the
			// server offers it, then write it as wanted.
			reg := unregisteredAction(o.rules.unregistered, want.Alias)
			if reg == nil {
				w.fields = append(w.fields, "action."+want.Alias+".missing")
				continue
			}
			w.fields = append(w.fields, "action."+want.Alias+".registered")
			w.rules.register = append(w.rules.register, reg)
			got = requiredAction{Alias: want.Alias, ProviderID: want.Alias, Name: str2(reg, "name"), Enabled: true}
		}
		put := got
		changed := false
		if got.Enabled != want.Enabled {
			w.fields = append(w.fields, "action."+want.Alias+".enabled")
			put.Enabled, changed = want.Enabled, true
		}
		if want.DefaultAction != nil && got.DefaultAction != *want.DefaultAction {
			w.fields = append(w.fields, "action."+want.Alias+".defaultAction")
			put.DefaultAction, changed = *want.DefaultAction, true
		}
		if changed || !ok {
			put.Config = nil
			w.rules.actions[want.Alias] = put
			w.rules.actionOrder = append(w.rules.actionOrder, want.Alias)
		}
		if want.Config != nil && !configHolds(got.Config, want.Config) {
			w.fields = append(w.fields, "action."+want.Alias+".config")
			cfg := map[string]string{}
			for k, v := range got.Config {
				cfg[k] = v
			}
			for k, v := range want.Config {
				cfg[k] = v
			}
			w.rules.configs[want.Alias] = cfg
			w.rules.configOrder = append(w.rules.configOrder, want.Alias)
		}
	}

	// The user profile.
	if p, diffs, err := flows.ApplyProfile(o.rules.profile); err != nil {
		w.fields = append(w.fields, "profile.unreadable")
	} else if len(diffs) > 0 {
		for _, df := range diffs {
			w.fields = append(w.fields, df.Field)
		}
		w.rules.profile = p
	}

	// The console roles and the default roles' composites.
	if _, ok := o.clients[flows.ConsoleClient]; ok {
		for _, name := range r.ConsoleRoles {
			if !slices.Contains(o.rules.consoleRoles, name) {
				w.fields = append(w.fields, "role."+flows.ConsoleClient+"."+name)
				w.rules.roles = append(w.rules.roles, name)
			}
		}
	}
	for _, cr := range o.rules.defaultRoles {
		w.fields = append(w.fields, "defaultRoles."+cr.Name)
		w.rules.composites = append(w.rules.composites, cr)
	}

	// The own clients: switches, scopes and the browser binding.
	for _, own := range r.Clients {
		cl, ok := o.clients[own.ClientID]
		if !ok {
			continue // client.<id>.missing, from the redirect URIs
		}
		for _, s := range flows.ClientSwitches() {
			want, owned := own.Switches[s]
			if !owned {
				continue
			}
			got, present := cl.switches[s]
			if !present || got != want {
				w.addClient(cl, s, want)
			}
		}
		w.scopeDiff(cl, "default", own.DefaultScopes, cl.DefaultClientScopes, o.rules.scopeIDs)
		w.scopeDiff(cl, "optional", own.OptionalScopes, cl.OptionalClientScopes, o.rules.scopeIDs)
	}
	for _, id := range slices.Sorted(maps.Keys(r.Bindings)) {
		v := r.Bindings[id]
		cl, ok := o.clients[id]
		if !ok {
			w.fields = append(w.fields, "client."+id+".binding")
			continue
		}
		flowID := o.rules.flowIDs[v.Alias()]
		if flowID == "" || cl.Bindings["browser"] != flowID {
			if flowID == "" {
				w.fields = append(w.fields, "client."+id+".binding")
				continue
			}
			w.addClient(cl, "authenticationFlowBindingOverrides", map[string]string{"browser": flowID})
			// addClient named it by the body field; the field is the binding.
			w.fields[len(w.fields)-1] = "client." + id + ".binding"
		}
	}
}

// scopeDiff adds the scope writes that make got equal want.
func (w *writes) scopeDiff(cl client, kind string, want, got []string, ids map[string]string) {
	for _, name := range want {
		if !slices.Contains(got, name) {
			w.fields = append(w.fields, "client."+cl.ClientID+".scope."+kind+"."+name)
			w.rules.scopes = append(w.rules.scopes, scopeWrite{clientID: cl.ID, scopeID: ids[name], kind: kind})
		}
	}
	for _, name := range got {
		if !slices.Contains(want, name) {
			w.fields = append(w.fields, "client."+cl.ClientID+".scope."+kind+"."+name)
			w.rules.scopes = append(w.rules.scopes, scopeWrite{clientID: cl.ID, scopeID: ids[name], kind: kind, remove: true})
		}
	}
}

// configHolds reports whether got holds every key of want with its value.
func configHolds(got, want map[string]string) bool {
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// unregisteredAction is the server's offer to register alias, nil for none.
func unregisteredAction(offers []map[string]any, alias string) map[string]any {
	for _, o := range offers {
		if str2(o, "providerId") == alias {
			return map[string]any{"providerId": alias, "name": str2(o, "name")}
		}
	}
	return nil
}

func str2(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// writeRules makes the rules' writes other than the realm and client PUTs:
// flow rebuilds first, then required actions, the profile, roles,
// composites and scopes. A rebuild failure is errFlowRebuild.
func (c *Converger) writeRules(ctx context.Context, d Desired, o observed, w ruleWrites) error {
	for _, alias := range w.rebuild {
		if err := c.rebuild(ctx, alias, d.Rules.Flows[alias], o.rules.execs[alias]); err != nil {
			return &rebuildError{alias: alias, err: err}
		}
	}
	for _, reg := range w.register {
		if err := c.send(ctx, http.MethodPost, "/authentication/register-required-action", reg); err != nil {
			return err
		}
	}
	for _, alias := range w.actionOrder {
		if err := c.send(ctx, http.MethodPut, "/authentication/required-actions/"+url.PathEscape(alias), w.actions[alias]); err != nil {
			return err
		}
	}
	for _, alias := range w.configOrder {
		if err := c.send(ctx, http.MethodPut, "/authentication/required-actions/"+url.PathEscape(alias)+"/config",
			map[string]any{"config": w.configs[alias]}); err != nil {
			return err
		}
	}
	if w.profile != nil {
		if err := c.send(ctx, http.MethodPut, "/users/profile", w.profile); err != nil {
			return err
		}
	}
	if cl, ok := o.clients[flows.ConsoleClient]; ok {
		for _, name := range w.roles {
			if err := c.send(ctx, http.MethodPost, "/clients/"+url.PathEscape(cl.ID)+"/roles", map[string]any{"name": name}); err != nil {
				return err
			}
		}
	}
	if len(w.composites) > 0 {
		if err := c.send(ctx, http.MethodDelete, "/roles/"+url.PathEscape(flows.DefaultRolesName)+"/composites", w.composites); err != nil {
			return err
		}
	}
	for _, s := range w.scopes {
		if s.scopeID == "" {
			return fmt.Errorf("converge: client scope missing for client %s", s.clientID)
		}
		method := http.MethodPut
		if s.remove {
			method = http.MethodDelete
		}
		if err := c.send(ctx, method, "/clients/"+url.PathEscape(s.clientID)+"/"+s.kind+"-client-scopes/"+url.PathEscape(s.scopeID), nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *Converger) send(ctx context.Context, method, path string, body any) error {
	_, err := c.d.Admin.Admin(ctx, method, c.realmPath()+path, body, nil)
	return err
}

// rebuildError is a flow rebuild that failed part-way.
type rebuildError struct {
	alias string
	err   error
}

func (e *rebuildError) Error() string { return "converge: rebuild " + e.alias + ": " + e.err.Error() }
func (e *rebuildError) Unwrap() error { return e.err }

// rebuild replaces alias's executions with want. It deletes the top-level
// executions (each sub-flow with its children and configs), adds every
// execution DISABLED, sets each nested execution's requirement and config,
// and last enables the top level from the end: the access gate before
// authenticate, so a flow left half-built by a failure admits nobody.
func (c *Converger) rebuild(ctx context.Context, alias string, want []flows.Node, old []execution) error {
	for _, e := range old {
		if e.Level != 0 {
			continue
		}
		if err := c.send(ctx, http.MethodDelete, "/authentication/executions/"+url.PathEscape(e.ID), nil); err != nil {
			return err
		}
	}
	added, err := c.addChildren(ctx, alias, want)
	if err != nil {
		return err
	}
	for i := len(want) - 1; i >= 0; i-- {
		if err := c.setRequirement(ctx, alias, added[i], want[i].Requirement); err != nil {
			return err
		}
	}
	return nil
}

// addChildren adds nodes under parent, all DISABLED, then configures each
// and recurses into sub-flows, enabling every execution below parent. It
// returns the added top executions, in order.
func (c *Converger) addChildren(ctx context.Context, parent string, nodes []flows.Node) ([]execution, error) {
	base := "/authentication/flows/" + url.PathEscape(parent) + "/executions"
	for _, n := range nodes {
		var err error
		if n.IsFlow() {
			err = c.send(ctx, http.MethodPost, base+"/flow", map[string]any{
				"alias": n.Alias, "type": "basic-flow", "provider": "registration-page-form", "description": "",
			})
		} else {
			err = c.send(ctx, http.MethodPost, base+"/execution", map[string]any{"provider": n.Provider})
		}
		if err != nil {
			return nil, err
		}
	}
	var listed []execution
	if err := c.get(ctx, base, &listed); err != nil {
		return nil, err
	}
	var direct []execution
	for _, e := range listed {
		if e.Level == 0 {
			direct = append(direct, e)
		}
	}
	if len(direct) != len(nodes) {
		return nil, fmt.Errorf("converge: %s holds %d executions after the rebuild added %d", parent, len(direct), len(nodes))
	}
	for i, n := range nodes {
		e := direct[i]
		if n.IsFlow() {
			if e.DisplayName != n.Alias {
				return nil, fmt.Errorf("converge: %s's execution %d is %s, want %s", parent, i, e.DisplayName, n.Alias)
			}
			children, err := c.addChildren(ctx, n.Alias, n.Children)
			if err != nil {
				return nil, err
			}
			for j := range children {
				if err := c.setRequirement(ctx, n.Alias, children[j], n.Children[j].Requirement); err != nil {
					return nil, err
				}
			}
			continue
		}
		if e.ProviderID != n.Provider {
			return nil, fmt.Errorf("converge: %s's execution %d is %s, want %s", parent, i, e.ProviderID, n.Provider)
		}
		if n.Config != nil {
			if err := c.send(ctx, http.MethodPost, "/authentication/executions/"+url.PathEscape(e.ID)+"/config",
				map[string]any{"alias": n.ConfigAlias, "config": n.Config}); err != nil {
				return nil, err
			}
		}
	}
	return direct, nil
}

// setRequirement sets e's requirement under parent; DISABLED is already set.
func (c *Converger) setRequirement(ctx context.Context, parent string, e execution, r flows.Requirement) error {
	if r == flows.Disabled {
		return nil
	}
	return c.send(ctx, http.MethodPut, "/authentication/flows/"+url.PathEscape(parent)+"/executions",
		map[string]any{"id": e.ID, "requirement": string(r), "level": e.Level, "index": e.Index, "priority": e.Priority})
}

// integrityFields are the fields among fields that are integrity
// differences.
func integrityFields(fields []string) []string {
	var out []string
	for _, f := range fields {
		if flows.IsIntegrity(f) {
			out = append(out, f)
		}
	}
	return out
}
