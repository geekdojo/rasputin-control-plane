package converge

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

const backchannelA = "https://127.0.0.1/api/identity/backchannel/rasputin-console"

// TC-989-28: the console's redirect URI makes the console origin, and its
// back-channel URL is desired with the session flag; with empty inputs the
// origin and the URL are held absent and the session flag is not owned.
func TestNewDesired_ConsoleBackchannel(t *testing.T) {
	d := NewDesired(Inputs{
		RedirectURIs:          map[string][]string{"rasputin-console": {"https://ci.local/api/auth/callback"}},
		BackchannelLogoutURLs: map[string]string{"rasputin-console": backchannelA},
	})
	if d.ConsoleURL != "https://ci.local" {
		t.Errorf("ConsoleURL = %q, want https://ci.local", d.ConsoleURL)
	}
	want := map[string]string{AttrBackchannelURL: backchannelA, AttrBackchannelSession: "true"}
	if got := d.ClientAttributes["rasputin-console"]; !equalMaps(got, want) {
		t.Errorf("console attributes = %v, want %v", got, want)
	}
	if got := d.ClientAttributes["rasputin-account"]; !equalMaps(got, map[string]string{AttrBackchannelURL: ""}) {
		t.Errorf("an unnamed client's attributes = %v, want the URL held absent", got)
	}

	empty := NewDesired(Inputs{})
	if empty.ConsoleURL != "" {
		t.Errorf("empty inputs: ConsoleURL = %q, want absent", empty.ConsoleURL)
	}
	if got := empty.ClientAttributes["rasputin-console"]; !equalMaps(got, map[string]string{AttrBackchannelURL: ""}) {
		t.Errorf("empty inputs: console attributes = %v, want only the URL, held absent", got)
	}
	if d.Hash() == empty.Hash() {
		t.Error("the back-channel URL does not change the desired state's hash")
	}
}

// TC-989-28: a back-channel URL set by hand on a cluster whose inputs name
// none is removed.
func TestRun_BackchannelHeldAbsent(t *testing.T) {
	r := newRig(t)
	r.kc.client("rasputin-console")["attributes"] = map[string]any{AttrBackchannelURL: "https://evil.example/bc", "pkce.code.challenge.method": "S256"}
	fields, err := r.c.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fields, "client.rasputin-console.attributes") {
		t.Errorf("fields %v lack the console's attributes", fields)
	}
	attrs := r.kc.client("rasputin-console")["attributes"].(map[string]any)
	if _, ok := attrs[AttrBackchannelURL]; ok || attrs["pkce.code.challenge.method"] != "S256" {
		t.Errorf("attributes after = %v, want the URL gone and PKCE kept", attrs)
	}
}

// TC-989-29 (F-989-03): the client write that sets the back-channel
// attributes sends the client's whole attribute map, so the PKCE method and
// the certificate subject the baseline carries are written back unchanged.
func TestRun_BackchannelKeepsOtherAttributes(t *testing.T) {
	r := newRig(t)
	r.inputs.RedirectURIs = map[string][]string{"rasputin-console": {"https://ci.local/api/auth/callback"}}
	r.inputs.BackchannelLogoutURLs = map[string]string{"rasputin-console": backchannelA}
	console := r.kc.client("rasputin-console")
	console["attributes"] = map[string]any{"pkce.code.challenge.method": "S256", "x509.subjectdn": "CN=rasputin-api,O=Rasputin"}
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	path := realmPath + "/clients/" + console["id"].(string)
	var sent map[string]any
	for _, c := range r.kc.writes() {
		if c.method != http.MethodPut || c.path != path {
			continue
		}
		var b map[string]json.RawMessage
		if err := json.Unmarshal(c.body, &b); err != nil {
			t.Fatal(err)
		}
		if raw, ok := b["attributes"]; ok {
			if err := json.Unmarshal(raw, &sent); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := map[string]any{"pkce.code.challenge.method": "S256", "x509.subjectdn": "CN=rasputin-api,O=Rasputin",
		AttrBackchannelURL: backchannelA, AttrBackchannelSession: "true"}
	if len(sent) != len(want) {
		t.Fatalf("the attribute PUT carried %v, want the whole map %v", sent, want)
	}
	for k, v := range want {
		if sent[k] != v {
			t.Errorf("PUT attributes[%s] = %v, want %v", k, sent[k], v)
		}
	}
	// The read-back finds nothing left to write.
	fields, err := r.c.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(fields, "client.rasputin-console.attributes") {
		t.Errorf("a second run still wrote the attributes: %v", fields)
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
