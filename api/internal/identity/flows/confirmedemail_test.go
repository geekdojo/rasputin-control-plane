package flows

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TC-994-35: the confirmed email is an admin-only single-valued attribute
// the profile diff adds to a realm that lacks it, and the realm baseline
// declares rasputin-app-email, one user-attribute mapper giving it to app
// tokens as email (ID token, access token and userinfo). The lock's hash
// is checked by scripts/pack-identity.sh (TC-980-01).
func TestConfirmedEmail_TC994_35(t *testing.T) {
	if multi, ok := AdminOnlyAttributes[AttrConfirmedEmail]; !ok || multi {
		t.Fatalf("AdminOnlyAttributes[%s] = %v, %v; want single-valued", AttrConfirmedEmail, multi, ok)
	}
	p, diffs, err := ApplyProfile([]byte(`{"attributes":[{"name":"username"},{"name":"email"},{"name":"firstName","displayName":"Name"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range diffs {
		found = found || (d.Field == "profile.attribute."+AttrConfirmedEmail && d.Integrity)
	}
	if !found {
		t.Errorf("the profile diff %v does not add %s", diffs, AttrConfirmedEmail)
	}
	added := false
	for _, a := range p["attributes"].([]any) {
		m := a.(map[string]any)
		if m["name"] == AttrConfirmedEmail {
			added = SameJSON(m["permissions"], AdminOnlyPermissions()) && m["multivalued"] == false
		}
	}
	if !added {
		t.Errorf("the applied profile lacks an admin-only %s", AttrConfirmedEmail)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "identity", "realm-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		ClientScopes []struct {
			Name            string `json:"name"`
			Protocol        string `json:"protocol"`
			ProtocolMappers []struct {
				ProtocolMapper string            `json:"protocolMapper"`
				Config         map[string]string `json:"config"`
			} `json:"protocolMappers"`
		} `json:"clientScopes"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	for _, s := range b.ClientScopes {
		if s.Name != "rasputin-app-email" {
			continue
		}
		if s.Protocol != "openid-connect" || len(s.ProtocolMappers) != 1 {
			t.Fatalf("rasputin-app-email: %+v", s)
		}
		m := s.ProtocolMappers[0]
		c := m.Config
		if m.ProtocolMapper != "oidc-usermodel-attribute-mapper" || c["user.attribute"] != AttrConfirmedEmail || c["claim.name"] != "email" ||
			c["id.token.claim"] != "true" || c["access.token.claim"] != "true" || c["userinfo.token.claim"] != "true" {
			t.Errorf("rasputin-app-email's mapper: %+v", m)
		}
		return
	}
	t.Error("the realm baseline declares no rasputin-app-email client scope")
}
