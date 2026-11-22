package identitytest

import (
	"strings"
	"testing"
)

// TC-988-19: the walk's page table, built from the theme's coverage record,
// holds a row for every page a base template renders: walked, deferred to the
// issue that builds its flow, binding or door, or never rendered with its
// reason. A rendered id the table does not hold fails the walk, and so does a
// deferred or never-rendered one.
func TestThemeWalk_PageTable(t *testing.T) {
	table, err := buildPageTable(coverageTemplates(t))
	if err != nil {
		t.Fatalf("the page table: %v", err)
	}
	if _, err := classify(table, "login-login"); err != nil {
		t.Errorf("login-login: %v", err)
	}
	if _, err := classify(table, "login-unknown-fixture-page"); err == nil || !strings.Contains(err.Error(), "not in the page table") {
		t.Errorf("an unknown page id gave %v, want a failure naming it", err)
	}
	if _, err := classify(table, "login-webauthn-authenticate"); err == nil || !strings.Contains(err.Error(), "geekdojo/geekdojo-brain#987") {
		t.Errorf("a deferred page rendered gave %v, want a failure naming its issue", err)
	}
	if _, err := buildPageTable(append(coverageTemplates(t), "brand-new-page.ftl")); err == nil || !strings.Contains(err.Error(), "login-brand-new-page") {
		t.Errorf("a template with no row gave %v, want a failure naming its page id", err)
	}
}

// The Go copy of the forbidden-words rule matches ui/lib/forbidden-words.ts's
// cases (TC-988-05).
func TestThemeWalk_ForbiddenWords(t *testing.T) {
	f := loadForbiddenWords(t)
	for text, want := range map[string]int{
		"Keycloak is down": 1, "two REALMS": 1, "restart tailscaled": 1, "use Google \n Authenticator": 1,
		"RASPUTIN_HEADSCALE_URL": 0, "myrealm": 0, "Sign in to Hoodoo Home": 0,
	} {
		if got := f.hits(text); len(got) != want {
			t.Errorf("hits(%q) = %v, want %d", text, got, want)
		}
	}
}

// The TOTP helper reproduces RFC 6238 appendix B's SHA-1 vector at T=59
// (counter 1), as the walk computes the app's code.
func TestThemeWalk_TOTP(t *testing.T) {
	// "12345678901234567890" in base32.
	got, err := totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1)
	if err != nil || got != "287082" {
		t.Errorf("totp = %q, %v; want 287082", got, err)
	}
}
