package converge

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

const (
	resetHome = "https://sso-ci.local/realms/rasputin/login-actions/reset-credentials?client_id=rasputin-reset-home&redirect_uri=x"
	resetApp  = "https://signin.ci.internal/realms/rasputin/login-actions/reset-credentials?client_id=rasputin-reset-app&redirect_uri=y"
)

// emptyResetFlow leaves the fake's rasputin-reset flow as the baseline
// imports it: no executions.
func emptyResetFlow(kc *fakeKC) {
	r := kc.rulesState
	f := r.flows[flows.ResetAlias]
	for _, e := range f.execs {
		r.deepDelete(e)
	}
	f.execs = nil
}

// resetFlowWrites are the indexes of the calls that write the reset flow's
// executions, and realmPut the index of the realm PUT, or -1.
func resetFlowWrites(kc *fakeKC) (flowWrites []int, realmPut int) {
	realmPut = -1
	for i, c := range kc.writes() {
		switch {
		case strings.Contains(c.path, "/authentication/flows/"+flows.ResetAlias):
			flowWrites = append(flowWrites, i)
		case c.method == http.MethodPut && c.path == realmPath:
			realmPut = i
		}
	}
	return flowWrites, realmPut
}

// TC-992-03: a rasputin-reset flow that is empty, or differs by one
// execution, is listed for rebuild and rebuilt before the realm PUT; a
// matching flow is left alone.
func TestRun_TC992_03_ResetFlow(t *testing.T) {
	t.Run("empty is rebuilt", func(t *testing.T) {
		r := newRig(t)
		emptyResetFlow(r.kc)
		fields, err := r.c.Run(t.Context())
		if err != nil || !slices.Contains(fields, "flow."+flows.ResetAlias) {
			t.Fatalf("Run = %v, %v; want flow.%s", fields, err, flows.ResetAlias)
		}
		if w, _ := resetFlowWrites(r.kc); len(w) == 0 {
			t.Error("the reset flow was not written")
		}
	})
	t.Run("one execution differs", func(t *testing.T) {
		r := newRig(t)
		f := r.kc.rulesState.flows[flows.ResetAlias]
		f.execs[0].requirement = "DISABLED"
		fields, err := r.c.Run(t.Context())
		if err != nil || !slices.Equal(fields, []string{"flow." + flows.ResetAlias}) {
			t.Fatalf("Run = %v, %v; want only flow.%s", fields, err, flows.ResetAlias)
		}
	})
	t.Run("matching is left alone", func(t *testing.T) {
		r := newRig(t)
		fields, err := r.c.Run(t.Context())
		if err != nil || len(fields) != 0 {
			t.Fatalf("Run = %v, %v; want nothing repaired", fields, err)
		}
		if w, _ := resetFlowWrites(r.kc); len(w) != 0 {
			t.Errorf("%d reset flow writes, want none", len(w))
		}
	})
}

// TC-992-04: the console, home reset and app reset links are each written
// when absent, corrected when wrong, and held absent when the desired value
// is empty; every other attribute goes back as read; the hash changes with
// either reset URL.
func TestRun_TC992_04_LinkAttributes(t *testing.T) {
	sent := func(t *testing.T, r *rig) map[string]string {
		t.Helper()
		var m map[string]string
		if err := json.Unmarshal(realmPUT(t, r.kc)["attributes"], &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	attrs := func(r *rig) map[string]any { return r.kc.realm["attributes"].(map[string]any) }
	t.Run("absent is written", func(t *testing.T) {
		r := newRig(t)
		r.inputs.ResetHomeURL, r.inputs.ResetAppURL = resetHome, resetApp
		fields, err := r.c.Run(t.Context())
		want := []string{"realm.attributes." + attrResetHomeURL, "realm.attributes." + attrResetAppURL}
		if err != nil || !slices.Equal(fields, want) {
			t.Fatalf("Run = %v, %v; want %v", fields, err, want)
		}
		m := sent(t, r)
		if m[attrResetHomeURL] != resetHome || m[attrResetAppURL] != resetApp || m["cibaExpiresIn"] != "120" || m["CreateDefaultClientScopes"] != "true" {
			t.Errorf("attributes sent = %v", m)
		}
	})
	t.Run("wrong is corrected", func(t *testing.T) {
		r := newRig(t)
		r.inputs.ResetHomeURL, r.inputs.ResetAppURL = resetHome, resetApp
		attrs(r)[attrResetHomeURL] = "https://old.local/reset"
		attrs(r)[attrResetAppURL] = resetApp
		fields, err := r.c.Run(t.Context())
		if err != nil || !slices.Equal(fields, []string{"realm.attributes." + attrResetHomeURL}) {
			t.Fatalf("Run = %v, %v", fields, err)
		}
		if m := sent(t, r); m[attrResetHomeURL] != resetHome || m[attrResetAppURL] != resetApp {
			t.Errorf("attributes sent = %v", m)
		}
	})
	t.Run("present while empty is removed", func(t *testing.T) {
		r := newRig(t)
		attrs(r)[attrResetHomeURL] = resetHome
		attrs(r)[attrResetAppURL] = resetApp
		attrs(r)[attrConsoleURL] = "https://old.local"
		fields, err := r.c.Run(t.Context())
		want := []string{"realm.attributes." + attrConsoleURL, "realm.attributes." + attrResetHomeURL, "realm.attributes." + attrResetAppURL}
		if err != nil || !slices.Equal(fields, want) {
			t.Fatalf("Run = %v, %v; want %v", fields, err, want)
		}
		m := sent(t, r)
		for _, k := range []string{attrConsoleURL, attrResetHomeURL, attrResetAppURL} {
			if _, ok := m[k]; ok {
				t.Errorf("%s sent, want it held absent", k)
			}
		}
		if m["cibaExpiresIn"] != "120" {
			t.Errorf("attributes sent = %v, want the others kept", m)
		}
	})
	t.Run("hash follows each URL", func(t *testing.T) {
		base := NewDesired(Inputs{InstallName: "x"}).Hash()
		home := NewDesired(Inputs{InstallName: "x", ResetHomeURL: resetHome}).Hash()
		app := NewDesired(Inputs{InstallName: "x", ResetAppURL: resetApp}).Hash()
		if base == home || base == app || home == app {
			t.Errorf("hashes %s %s %s, want three different", base, home, app)
		}
	})
}

// TC-992-05: the upgrade. A realm as the previous release leaves it (an
// empty reset flow, no reset attributes, resets not allowed, the stock reset
// flow bound) converges in one run: the flow is built first, then the realm
// PUT carries resetCredentialsFlow, resetPasswordAllowed and both
// attributes, and nothing differs afterwards.
func TestRun_TC992_05_Upgrade(t *testing.T) {
	r := newRig(t)
	emptyResetFlow(r.kc)
	r.kc.realm["resetCredentialsFlow"] = "reset credentials"
	r.kc.realm["resetPasswordAllowed"] = false
	r.inputs.ResetHomeURL, r.inputs.ResetAppURL = resetHome, resetApp
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	flowW, put := resetFlowWrites(r.kc)
	if len(flowW) == 0 || put < 0 || flowW[len(flowW)-1] > put {
		t.Fatalf("reset flow writes %v and the realm PUT at %d, want the flow first", flowW, put)
	}
	body := realmPUT(t, r.kc)
	var m map[string]string
	_ = json.Unmarshal(body["attributes"], &m)
	if string(body["resetCredentialsFlow"]) != `"rasputin-reset"` || string(body["resetPasswordAllowed"]) != "true" ||
		m[attrResetHomeURL] != resetHome || m[attrResetAppURL] != resetApp {
		t.Errorf("realm PUT resetCredentialsFlow %s resetPasswordAllowed %s attributes %v",
			body["resetCredentialsFlow"], body["resetPasswordAllowed"], m)
	}
	o, err := r.c.observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if left := diff(NewDesired(r.inputs), o); len(left.fields) != 0 {
		t.Errorf("still differs after the run: %v", left.fields)
	}
}
