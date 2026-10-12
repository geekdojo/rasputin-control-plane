package storepolicy

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// These tests read the policy text statically. What the store does with it is
// policy_functional_test.go, against the real pinned store. A regexp over our
// own files is enough here (no HCL parser dependency, #685): the parser below
// refuses anything that is not a comment, a blank line or a path stanza of the
// one shape these files use, so a construct it cannot read fails rather than
// passing unread.

// stanza is one `path "P" { capabilities = [...] }` block.
type stanza struct {
	path string
	caps []string
}

var (
	stanzaRE  = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}`)
	capRE     = regexp.MustCompile(`^"([a-z]+)"$`)
	commentRE = regexp.MustCompile(`(?m)^\s*#.*$`)
)

// parse reads text as path stanzas. Anything left once the comments and the
// stanzas are removed is an error naming it.
func parse(text []byte) ([]stanza, error) {
	body := commentRE.ReplaceAllString(string(text), "")
	var out []stanza
	for _, m := range stanzaRE.FindAllStringSubmatch(body, -1) {
		s := stanza{path: m[1]}
		for _, c := range strings.Split(m[2], ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			cm := capRE.FindStringSubmatch(c)
			if cm == nil {
				return nil, fmt.Errorf("path %q: capability %s is not a quoted lowercase word", s.path, c)
			}
			s.caps = append(s.caps, cm[1])
		}
		out = append(out, s)
	}
	if rest := strings.TrimSpace(stanzaRE.ReplaceAllString(body, "")); rest != "" {
		return nil, fmt.Errorf("text that is not a path stanza: %q", rest)
	}
	return out, nil
}

// apiAllow is the api policy's allow-list (plan, rasputin-api.hcl): each
// path and the only capabilities it may carry.
var apiAllow = map[string][]string{
	"rasputin-secrets/data/apps/*":        {"create", "read", "update", "delete"},
	"rasputin-secrets/data/devices/*":     {"create", "read", "update", "delete"},
	"rasputin-secrets/metadata/apps/*":    {"read", "delete"},
	"rasputin-secrets/metadata/devices/*": {"read", "delete"},
	"auth/token/lookup-self":              {"read"},
}

// checkAPI holds text to the allow-list: every stanza's path is on it, its
// capabilities are exactly the allowed ones, no stanza carries sudo, and
// every allowed path is granted once. The error names the stanza.
func checkAPI(text []byte) error {
	stanzas, err := parse(text)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range stanzas {
		if slices.Contains(s.caps, "sudo") {
			return fmt.Errorf("path %q grants sudo", s.path)
		}
		want, ok := apiAllow[s.path]
		if !ok {
			return fmt.Errorf("path %q is not on the allow-list", s.path)
		}
		if seen[s.path] {
			return fmt.Errorf("path %q is granted twice", s.path)
		}
		seen[s.path] = true
		if !reflect.DeepEqual(s.caps, want) {
			return fmt.Errorf("path %q grants %v, want exactly %v", s.path, s.caps, want)
		}
	}
	for p := range apiAllow {
		if !seen[p] {
			return fmt.Errorf("path %q on the allow-list is not granted", p)
		}
	}
	return nil
}

// TC-804-01: Names is exactly the two policies, Text returns the embedded
// bytes (the files in this directory, byte for byte), and an unknown name is
// refused with a message naming it.
//
// #805 PINS: this test pins two policies. geekdojo-brain#805 adds
// rasputin-provisioner.hcl here and updates the list to three
// (geekdojo-brain#804, F-804-11).
func TestNamesAndText(t *testing.T) {
	want := []string{APIPolicy, SealRotatePolicy}
	if got := Names(); !reflect.DeepEqual(got, want) {
		t.Errorf("Names() = %v, want exactly %v", got, want)
	}
	if Mount != "rasputin-secrets" || APIPolicy != "rasputin-api" || SealRotatePolicy != "rasputin-seal-rotate" {
		t.Errorf("Mount, APIPolicy, SealRotatePolicy = %q, %q, %q", Mount, APIPolicy, SealRotatePolicy)
	}
	for _, name := range want {
		got, err := Text(name)
		if err != nil {
			t.Fatalf("Text(%q): %v", name, err)
		}
		disk, err := os.ReadFile(name + ".hcl")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, disk) || len(got) == 0 {
			t.Errorf("Text(%q) is not %s.hcl byte for byte (%d vs %d bytes)", name, name, len(got), len(disk))
		}
	}
	for _, bad := range []string{"nope", "", "../storepolicy", "rasputin-api.hcl"} {
		got, err := Text(bad)
		if got != nil || err == nil {
			t.Errorf("Text(%q) = %q, %v; want a refusal", bad, got, err)
			continue
		}
		if want := fmt.Sprintf("storepolicy: no policy named %q", bad); err.Error() != want {
			t.Errorf("Text(%q) error = %q, want %q", bad, err, want)
		}
	}
}

// TC-804-02: the shipped api policy passes the allow-list check, and each
// injected stanza (sys/, identity/, auth/token/create, a list, a sudo and a
// patch capability) is refused with a message naming the stanza.
func TestAPIPolicy_AllowList(t *testing.T) {
	text, err := Text(APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAPI(text); err != nil {
		t.Fatalf("the shipped %s.hcl fails the allow-list: %v", APIPolicy, err)
	}
	cases := []struct {
		name, inject, needle string
	}{
		{"sys/", `path "sys/x" { capabilities = ["read"] }`, `"sys/x"`},
		{"identity/", `path "identity/x" { capabilities = ["read"] }`, `"identity/x"`},
		{"auth/token/create", `path "auth/token/create" { capabilities = ["update"] }`, `"auth/token/create"`},
		{"list", "path \"rasputin-secrets/metadata/apps/*\" {\n  capabilities = [\"read\", \"delete\", \"list\"]\n}", `"rasputin-secrets/metadata/apps/*" grants [read delete list]`},
		{"sudo", `path "rasputin-secrets/data/apps/*" { capabilities = ["create", "read", "update", "delete", "sudo"] }`, `"rasputin-secrets/data/apps/*" grants sudo`},
		{"patch", `path "rasputin-secrets/data/devices/*" { capabilities = ["create", "read", "update", "delete", "patch"] }`, `"rasputin-secrets/data/devices/*" grants [create read update delete patch]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The injection replaces the stanza on its path, or is added when
			// its path is not granted, so each case changes exactly one stanza.
			injected := replaceStanza(t, text, tc.inject)
			err := checkAPI(injected)
			if err == nil {
				t.Fatalf("the allow-list passed with %s injected:\n%s", tc.name, injected)
			}
			if !strings.Contains(err.Error(), tc.needle) {
				t.Errorf("refusal %q does not name the stanza (%s)", err, tc.needle)
			}
		})
	}
}

// replaceStanza returns text with the stanza on inject's path swapped for
// inject, or inject appended when no stanza has that path.
func replaceStanza(t *testing.T, text []byte, inject string) []byte {
	t.Helper()
	m := stanzaRE.FindStringSubmatch(inject)
	if m == nil {
		t.Fatalf("the injection %q is not a stanza", inject)
	}
	replaced := false
	out := stanzaRE.ReplaceAllStringFunc(string(text), func(s string) string {
		if stanzaRE.FindStringSubmatch(s)[1] == m[1] {
			replaced = true
			return inject
		}
		return s
	})
	if !replaced {
		out += "\n" + inject + "\n"
	}
	return []byte(out)
}

// The parser refuses what it cannot read, so the allow-list never passes over
// text it skipped.
func TestParse_RefusesUnreadText(t *testing.T) {
	for name, text := range map[string]string{
		"a bare key":         "max_ttl = \"1h\"\n",
		"allowed_parameters": "path \"a\" {\n  capabilities = [\"read\"]\n  allowed_parameters = {}\n}\n",
		"an unquoted cap":    "path \"a\" { capabilities = [read] }\n",
		"a // comment":       "// note\npath \"a\" { capabilities = [\"read\"] }\n",
	} {
		if _, err := parse([]byte(text)); err == nil {
			t.Errorf("parse accepted %s:\n%s", name, text)
		}
	}
}

// TC-804-03: the rotation policy is exactly one stanza, sys/rotate/root with
// update and sudo, and no never-grant path appears in either file.
func TestSealRotatePolicy_AndNeverGrantPaths(t *testing.T) {
	text, err := Text(SealRotatePolicy)
	if err != nil {
		t.Fatal(err)
	}
	stanzas, err := parse(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []stanza{{path: "sys/rotate/root", caps: []string{"update", "sudo"}}}
	if !reflect.DeepEqual(stanzas, want) {
		t.Errorf("%s.hcl = %+v, want exactly %+v", SealRotatePolicy, stanzas, want)
	}
	for _, name := range Names() {
		text, err := Text(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, never := range []string{"sys/rotate/recovery/init", "sys/generate-root", "sys/storage/raft"} {
			if bytes.Contains(text, []byte(never)) {
				t.Errorf("%s.hcl names the never-grant path %s", name, never)
			}
		}
	}
}
