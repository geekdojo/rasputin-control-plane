package pwpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

func checker(t *testing.T, lines ...string) (*Checker, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, flows.DenylistFile), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(dir, flows.PasswordPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func check(t *testing.T, c *Checker, pw, username, email string) Refusal {
	t.Helper()
	v := secret.New([]byte(pw))
	defer v.Destroy()
	r, err := c.Check(v, username, email)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TC-992-17: the policy's rules, as Keycloak 26.8.2 applies them.
func TestCheck_TC992_17(t *testing.T) {
	c, dir := checker(t, "correcthorsebattery", "MixedCaseListedPassword")
	cases := []struct {
		name, pw, rule, sentence string
	}{
		{"14 characters", strings.Repeat("a", 14), "length", "Use at least 15 characters."},
		{"15 characters", strings.Repeat("a", 15), "", ""},
		// 14 BMP characters and one astral one count 16 UTF-16 units.
		{"an astral character counts 2", strings.Repeat("é", 13) + "😀", "", ""},
		{"13 plus an astral is 15", strings.Repeat("b", 13) + "😀", "", ""},
		{"12 plus an astral is 14", strings.Repeat("b", 12) + "😀", "length", "Use at least 15 characters."},
		{"128 characters", strings.Repeat("c", 128), "", ""},
		{"129 characters", strings.Repeat("c", 129), "maxLength", "Use at most 128 characters."},
		{"the username in another case", "Alice-Longname-123", "notUsername", "Don't use your sign-in name as your password."},
		{"the email in another case", "ALICE@EXAMPLE.ORG.HOME", "notEmail", "Don't use your email as your password."},
		{"listed, another case", "CorrectHorseBattery", "passwordBlacklist", "That password is too common. Choose another."},
		{"listed line in mixed case", "mixedcaselistedpassword", "passwordBlacklist", "That password is too common. Choose another."},
		{"unlisted", "an unlisted passphrase of words", "", ""},
	}
	for _, tc := range cases {
		r := check(t, c, tc.pw, "alice-longname-123", "alice@example.org.home")
		if r.Rule != tc.rule || r.Sentence != tc.sentence || r.Refused() != (tc.rule != "") {
			t.Errorf("%s: %+v, want %s %q", tc.name, r, tc.rule, tc.sentence)
		}
	}
	if err := os.Remove(filepath.Join(dir, flows.DenylistFile)); err != nil {
		t.Fatal(err)
	}
	v := secret.New([]byte("an unlisted passphrase of words"))
	if _, err := c.Check(v, "a", "b"); !errors.Is(err, ErrListUnreadable) {
		t.Errorf("an unreadable list: %v, want ErrListUnreadable", err)
	}
}

// TC-992-17, parity: flows.PasswordPolicy parses, and a policy naming a rule
// this does not implement is refused, so the two cannot drift apart.
func TestNew_TC992_17_Parity(t *testing.T) {
	if _, err := New(t.TempDir(), flows.PasswordPolicy); err != nil {
		t.Fatalf("the realm's policy: %v", err)
	}
	for _, p := range []string{
		flows.PasswordPolicy + " and digits(1)",
		"length(x)",
		"length(15",
		"passwordBlacklist(../etc/passwd)",
	} {
		if _, err := New(t.TempDir(), p); err == nil {
			t.Errorf("New accepted %q", p)
		}
	}
	if _, err := New("", flows.PasswordPolicy); err == nil {
		t.Error("New accepted a deny list with no directory")
	}
}
