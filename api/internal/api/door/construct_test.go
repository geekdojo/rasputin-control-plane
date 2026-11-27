package door

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest"
)

// TC-985-34: New and Build refuse a missing collaborator.
func TestNew_FailsClosed(t *testing.T) {
	f := newFixture(t)
	s := f.shared(t)
	good := Config{Door: f.table.Home, Kind: Home, ConsoleOrigin: s.ConsoleOrigin, Policy: s.Policy, Throttle: s.Throttle,
		Transport: s.Transport, Upstream: s.Upstream, Theme: s.Theme, Assets: s.Assets, Version: s.Version, InstallName: s.InstallName,
		Dirty: s.Dirty, IDs: s.IDs, Breach: s.Breach, ResetDone: s.ResetDone, Log: s.Log}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"Door":          func(c *Config) { c.Door.Host = "" },
		"Clients":       func(c *Config) { c.Door.Clients = nil },
		"Kind":          func(c *Config) { c.Kind = 0 },
		"ConsoleOrigin": func(c *Config) { c.ConsoleOrigin = "" },
		"Policy":        func(c *Config) { c.Policy = nil },
		"Throttle":      func(c *Config) { c.Throttle = nil },
		"Transport":     func(c *Config) { c.Transport = nil },
		"Upstream":      func(c *Config) { c.Upstream = nil },
		"Upstream http": func(c *Config) { u := *c.Upstream; u.Scheme = "http"; c.Upstream = &u },
		"Theme":         func(c *Config) { c.Theme = Allowlist{} },
		"Assets":        func(c *Config) { c.Assets = nil },
		"Assets empty":  func(c *Config) { c.Assets = fstest.MapFS{"css/tokens.css": {}} },
		"Assets type": func(c *Config) {
			c.Assets = fstest.MapFS{"css/tokens.css": {}, "css/components.css": {}, "css/signin.css": {}, "css/x.exe": {}}
		},
		"Version":     func(c *Config) { c.Version = nil },
		"InstallName": func(c *Config) { c.InstallName = nil },
		"Dirty":       func(c *Config) { c.Dirty = nil },
		"IDs":         func(c *Config) { c.IDs = nil },
		"Breach":      func(c *Config) { c.Breach = nil },
		"ResetDone":   func(c *Config) { c.ResetDone = nil }, // TC-992-16
		"Log":         func(c *Config) { c.Log = nil },
	} {
		c := good
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("New with %s missing succeeded", name)
		}
	}
	bad := s
	bad.Policy = nil
	if _, _, err := Build(f.table, bad); err == nil {
		t.Error("Build with no policy succeeded")
	}
	noApp := f.table
	noApp.App.Clients = nil
	if _, _, err := Build(noApp, s); err == nil {
		t.Error("Build with an app door holding no clients succeeded")
	}
	if _, err := policy.New(policy.Deps{}); err == nil {
		t.Error("policy.New with nothing succeeded")
	}
}

// TC-985-34: ParseAllowlist refuses an empty, malformed or wrong-pin file.
func TestParseAllowlist_Refuses(t *testing.T) {
	for name, b := range map[string]string{
		"empty":       ``,
		"malformed":   `{"keycloak":`,
		"wrong pin":   `{"keycloak":"26.9.0","login":["css/signin.css"]}`,
		"no login":    `{"keycloak":"26.8.2","login":[]}`,
		"climbs":      `{"keycloak":"26.8.2","login":["../admin/x.js"]}`,
		"absolute":    `{"keycloak":"26.8.2","login":["/etc/passwd"]}`,
		"empty entry": `{"keycloak":"26.8.2","login":[""]}`,
		"escaped":     `{"keycloak":"26.8.2","login":["css%2Fx"]}`,
	} {
		if _, err := ParseAllowlist([]byte(b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, err := ParseAllowlist([]byte(testAllowlist))
	if err != nil || !a.allows(false, "css/signin.css") || !a.allows(true, "vendor/rfc4648/rfc4648.js") || a.allows(true, "css/signin.css") {
		t.Fatalf("the good allowlist: %v", err)
	}
}

// The theme pin is the harness's Keycloak release.
func TestKeycloakPin_IsTheHarnessPin(t *testing.T) {
	if !strings.HasSuffix(identitytest.KeycloakRelease, ":"+KeycloakPin) {
		t.Fatalf("KeycloakPin %s, the harness pins %s", KeycloakPin, identitytest.KeycloakRelease)
	}
}

// The info page renders.
func TestInfoPage(t *testing.T) {
	f := newFixture(t)
	w := httptest.NewRecorder()
	f.app.InfoPage(w, "Password changed", "Your password is changed. Sign in with it and your second step.", "c9")
	if !strings.Contains(w.Body.String(), "Your password is changed.") || !strings.Contains(w.Body.String(), "c9") {
		t.Errorf("info page: %s", w.Body.String())
	}
	if f.app.Kind() != App || f.home.Counts(f.th, f.now).Door != Home {
		t.Error("Kind or Counts names the wrong door")
	}
}
