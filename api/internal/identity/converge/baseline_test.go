package converge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// The guard on the unarmed realm baseline (F-1012-18). Keycloak's import
// skips a realm that exists, so a cluster updated from a stable release keeps
// the realm that release's baseline created, and only converge changes it
// afterwards. The oldest baseline a shipped stable imported is v2026.11.3's
// (v2026.11.2's hashes the same; v2026.11.0 and v2026.11.1 ship none), kept
// byte for byte in identity/testdata.

// shippedBaselineSHA is v2026.11.3's identity/realm-baseline.lock sha256.
const shippedBaselineSHA = "63e70ceedc3cd496f29f3b54c3787a1efba01706790f32804ad9a9d2c4046470"

// notConverged are the top-level baseline keys that changed since v2026.11.3
// and that converge does not write, each with the sha256 of the key's current
// canonical value and why an updated realm can go without the change. A
// further change to the key, or a key that stops differing, fails the guard
// until the entry is revisited.
var notConverged = map[string]struct{ sha, why string }{
	"clientScopes": {
		sha: "c992c6dbe75e0ec743de92d74a4c343518a2639a8c24fc2984d3a044b0dc990f",
		why: "rasputin-app-email and its confirmed email mapper: no client binds the scope until Identity 7.3 " +
			"(geekdojo/geekdojo-brain#1027), whose plan must create it on updated realms; " +
			"TestBaseline_EveryBoundScopeExistsOnAShippedRealm fails the day one does",
	},
}

// convergeCreatesScopes are the client scopes converge creates on a realm
// that lacks one. It creates none today: a bound scope it cannot find fails
// the run (rules.go, "client scope missing"), and a scope is an integrity
// field, so the failure locks the control gate.
var convergeCreatesScopes = map[string]bool{}

// readRealm is the realm representation at path, by top-level key, and its
// bytes.
func readRealm(t *testing.T, path string) (map[string]json.RawMessage, []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m, b
}

// shippedRealm is the v2026.11.3 baseline, checked against its lock's hash.
func shippedRealm(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	old, b := readRealm(t, filepath.Join("..", "..", "..", "..", "identity", "testdata", "realm-baseline-v2026.11.3.json"))
	if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != shippedBaselineSHA {
		t.Fatalf("identity/testdata/realm-baseline-v2026.11.3.json has sha256 %x, want v2026.11.3's lock hash %s", s, shippedBaselineSHA)
	}
	return old
}

// canonicalSHA is the sha256 of raw re-encoded with its object keys sorted,
// so formatting never changes it.
func canonicalSHA(raw json.RawMessage) string {
	var v any
	_ = json.Unmarshal(raw, &v) // absent (nil) reads as null
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TC-988-43: every top-level key of the realm baseline that differs from
// v2026.11.3's is either written by converge, with the tree baseline's value,
// to a realm imported from v2026.11.3's, or recorded in notConverged with its
// current value pinned.
func TestBaseline_ChangesSinceShippedConverge(t *testing.T) {
	old := shippedRealm(t)
	cur, _ := readRealm(t, filepath.Join("..", "..", "..", "..", "identity", "realm-baseline.json"))
	w := diff(NewDesired(Inputs{InstallName: "Test Home"}), observed{realm: old})

	keys := slices.Collect(maps.Keys(cur))
	for k := range old {
		if _, ok := cur[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		changed := !flows.SameJSON(old[k], cur[k])
		got, written := w.realm[k]
		converged := written && flows.SameJSON(cur[k], got)
		entry, recorded := notConverged[k]
		switch {
		case recorded && !changed:
			t.Errorf("notConverged[%s] is stale: the key no longer differs from v2026.11.3's; remove the entry", k)
		case recorded && converged:
			t.Errorf("notConverged[%s] is stale: converge now writes the baseline's value; remove the entry", k)
		case recorded && canonicalSHA(cur[k]) != entry.sha:
			t.Errorf("baseline key %s changed again (sha256 %s, notConverged pins %s): decide whether an updated realm needs the change, then make converge write it or re-pin the entry",
				k, canonicalSHA(cur[k]), entry.sha)
		case recorded && entry.why == "":
			t.Errorf("notConverged[%s] gives no reason", k)
		case changed && !recorded && !converged:
			t.Errorf("baseline key %s changed since v2026.11.3 but converge writes %v (written %t) to a realm imported from it, so an updated cluster never gets the change: make converge own it, or record it in notConverged with a reason",
				k, got, written)
		}
	}
	for k := range notConverged {
		if !slices.Contains(keys, k) {
			t.Errorf("notConverged[%s] names a key in neither baseline", k)
		}
	}
}

// F-988-33: every client scope the desired state binds, with an app client
// bound to each variant, exists on a realm imported from v2026.11.3's
// baseline, or converge creates it. A scope binding added in Go (Identity
// 7.3's app clients) changes no baseline key, so the guard above cannot see
// it; this one does.
func TestBaseline_EveryBoundScopeExistsOnAShippedRealm(t *testing.T) {
	old := shippedRealm(t)
	var realm struct {
		ClientScopes []struct {
			Name string `json:"name"`
		} `json:"clientScopes"`
		Clients []struct {
			DefaultClientScopes  []string `json:"defaultClientScopes"`
			OptionalClientScopes []string `json:"optionalClientScopes"`
		} `json:"clients"`
	}
	b, _ := json.Marshal(old)
	if err := json.Unmarshal(b, &realm); err != nil {
		t.Fatal(err)
	}
	// On the shipped realm: the scopes its baseline defines, and those its
	// own clients were imported bound to (the identity service's built-in
	// basic, profile, email and kc-admin-api). Converge already binds each
	// of those on every updated realm without a "client scope missing"
	// (TestIdentity_UpgradeFromStableTheme).
	exists := map[string]bool{}
	for _, s := range realm.ClientScopes {
		exists[s.Name] = true
	}
	for _, cl := range realm.Clients {
		for _, s := range slices.Concat(cl.DefaultClientScopes, cl.OptionalClientScopes) {
			exists[s] = true
		}
	}

	app := map[string]flows.Variant{}
	for _, v := range flows.Variants {
		app["app-"+v.Alias()] = v
	}
	d := NewDesired(Inputs{InstallName: "Test Home", AppBindings: app})
	for _, cl := range d.Rules.Clients {
		for _, s := range slices.Concat(cl.DefaultScopes, cl.OptionalScopes) {
			if !exists[s] && !convergeCreatesScopes[s] {
				t.Errorf("client %s binds scope %s, which a realm imported from v2026.11.3's baseline does not have and converge does not create: converge would fail every updated cluster with \"client scope missing\" and lock the control gate",
					cl.ClientID, s)
			}
		}
	}
}
