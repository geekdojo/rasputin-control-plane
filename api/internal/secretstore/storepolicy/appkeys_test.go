package storepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The two policies geekdojo/geekdojo-brain#1084 adds: the api's key identity
// (rasputin-app-keys) and the identity a later release authors through
// (rasputin-author). Read statically here; what the store does with them is
// policy_functional_test.go.

// appKeysWant is rasputin-app-keys.hcl's whole shape (plan, F-1084-01,
// F-1084-13): four stanzas on the one mount, each exactly one segment deep.
var appKeysWant = []stanza{
	{
		path:    AppKeysMount + "/keys/+",
		caps:    []string{"update", "delete"},
		allowed: map[string][]string{"type": {"aes256-gcm96"}},
	},
	{
		path:    AppKeysMount + "/keys/+/config",
		caps:    []string{"update"},
		allowed: map[string][]string{"deletion_allowed": {"true"}},
	},
	{path: AppKeysMount + "/encrypt/+", caps: []string{"update"}},
	{path: AppKeysMount + "/decrypt/+", caps: []string{"update"}},
}

// appKeysNever are path parts no key stanza may name.
var appKeysNever = []string{"export", "backup", "restore", "datakey", "rewrap", "rotate", "trim", "import", "auth/", "sys/"}

// checkAppKeys holds text to appKeysWant. The named faults come first, each
// with a message naming it; any other difference fails the exact comparison,
// naming the stanza.
func checkAppKeys(text []byte) error {
	stanzas, err := parseFull(text)
	if err != nil {
		return err
	}
	want := map[string]stanza{}
	for _, s := range appKeysWant {
		want[s.path] = s
	}
	seen := map[string]bool{}
	for _, s := range stanzas {
		switch {
		case strings.HasSuffix(s.path, "*"):
			return fmt.Errorf("path %q ends in a glob, which reaches a key's sub-paths", s.path)
		case !strings.HasPrefix(s.path, AppKeysMount+"/"):
			return fmt.Errorf("path %q is outside the mount %s", s.path, AppKeysMount)
		case s.path == AppKeysMount+"/keys/" || s.path == AppKeysMount+"/keys":
			return fmt.Errorf("path %q names the key list itself", s.path)
		}
		for _, never := range appKeysNever {
			if strings.Contains(s.path, never) {
				return fmt.Errorf("path %q names %s", s.path, strings.TrimSuffix(never, "/"))
			}
		}
		if strings.Contains(s.path, "/encrypt/") && slices.Contains(s.caps, "create") {
			return fmt.Errorf("path %q grants create, so an encrypt could make a key the index lacks", s.path)
		}
		w, ok := want[s.path]
		if !ok {
			return fmt.Errorf("path %q is not on the allow-list", s.path)
		}
		if seen[s.path] {
			return fmt.Errorf("path %q is granted twice", s.path)
		}
		seen[s.path] = true
		if !reflect.DeepEqual(s.allowed, w.allowed) {
			return fmt.Errorf("path %q allowed_parameters = %v, want exactly %v", s.path, s.allowed, w.allowed)
		}
		if !reflect.DeepEqual(s, w) {
			return fmt.Errorf("path %q is %+v, want exactly %+v", s.path, s, w)
		}
	}
	for _, s := range appKeysWant {
		if !seen[s.path] {
			return fmt.Errorf("path %q on the allow-list is not granted", s.path)
		}
	}
	return nil
}

// TC-1084-01: the key policy is exactly the four stanzas on mount
// rasputin-app-keys, with the key type pinned at create (F-1084-13) and
// deletion_allowed the only config parameter; each injected fault is refused
// with a message naming it.
func TestAppKeysPolicy_Shape(t *testing.T) {
	if AppKeysMount != "rasputin-app-keys" || AppKeysPolicy != "rasputin-app-keys" {
		t.Errorf("AppKeysMount, AppKeysPolicy = %q, %q; want rasputin-app-keys for both", AppKeysMount, AppKeysPolicy)
	}
	raw := text(t, AppKeysPolicy)
	if err := checkAppKeys(raw); err != nil {
		t.Fatalf("the shipped %s.hcl fails the check: %v", AppKeysPolicy, err)
	}
	shipped := string(raw)
	const encOpen = `path "rasputin-app-keys/encrypt/+" {`
	cases := []struct {
		name, old, new, needle string
	}{
		{"rotate added", encOpen, `path "rasputin-app-keys/keys/+/rotate" { capabilities = ["update"] }` + "\n" + encOpen, `"rasputin-app-keys/keys/+/rotate" names rotate`},
		{"a trailing *", `path "rasputin-app-keys/decrypt/+" {`, `path "rasputin-app-keys/decrypt/*" {`, `"rasputin-app-keys/decrypt/*" ends in a glob`},
		{"create on encrypt", "path \"rasputin-app-keys/encrypt/+\" {\n  capabilities = [\"update\"]", "path \"rasputin-app-keys/encrypt/+\" {\n  capabilities = [\"create\", \"update\"]", `"rasputin-app-keys/encrypt/+" grants create`},
		{"the type pin removed", "  allowed_parameters = {\n    \"type\" = [\"aes256-gcm96\"]\n  }\n", "", `"rasputin-app-keys/keys/+" allowed_parameters = map[], want exactly map[type:[aes256-gcm96]]`},
		{"a second key type", `"type" = ["aes256-gcm96"]`, `"type" = ["aes256-gcm96", "rsa-2048"]`, `allowed_parameters = map[type:[aes256-gcm96 rsa-2048]]`},
		{"a sys/ stanza", encOpen, `path "sys/mounts" { capabilities = ["read"] }` + "\n" + encOpen, `"sys/mounts" is outside the mount`},
		{"export", encOpen, `path "rasputin-app-keys/export/+" { capabilities = ["read"] }` + "\n" + encOpen, `"rasputin-app-keys/export/+" names export`},
		{"a second config parameter", `"deletion_allowed" = ["true"]`, `"deletion_allowed" = ["true"]` + "\n    \"exportable\" = [\"true\"]", `"rasputin-app-keys/keys/+/config" allowed_parameters`},
		{"read on a key", `capabilities = ["update", "delete"]`, `capabilities = ["read", "update", "delete"]`, `"rasputin-app-keys/keys/+" is {`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(shipped, tc.old) != 1 {
				t.Fatalf("the injection anchor %q is not in the shipped text exactly once", tc.old)
			}
			injected := strings.Replace(shipped, tc.old, tc.new, 1)
			err := checkAppKeys([]byte(injected))
			if err == nil {
				t.Fatalf("the check passed with %s injected:\n%s", tc.name, injected)
			}
			if !strings.Contains(err.Error(), tc.needle) {
				t.Errorf("refusal %q does not name the fault (%s)", err, tc.needle)
			}
		})
	}
}

// fixedNames are the policy names the store holds from first boot or by
// itself: no author glob may reach one.
var fixedNames = []string{APIPolicy, SealRotatePolicy, ProvisionerPolicy, BindablePolicy, AuthorPolicy, "root", "default"}

// authorWant is rasputin-author.hcl's whole shape (plan, #806's pinned
// disjoint-namespace shape inside rasputin-app-*).
var authorWant = []stanza{
	{
		path:    "sys/mounts/" + AuthorNamespace + "*",
		caps:    []string{"read", "update"},
		allowed: map[string][]string{"type": {"transit"}},
	},
	{
		path: "sys/policies/acl/" + AuthorNamespace + "*",
		caps: []string{"read", "create", "update"},
	},
	{
		path:     "auth/cert/certs/" + AuthorNamespace + "*",
		caps:     []string{"update"},
		required: []string{"certificate", "allowed_common_names", "token_policies", "token_no_default_policy", "token_ttl"},
		allowed: map[string][]string{
			"certificate":             {},
			"allowed_common_names":    {AuthorNamespace + "*"},
			"token_policies":          {AuthorNamespace + "*"},
			"policies":                {AuthorNamespace + "*"},
			"token_no_default_policy": {"true"},
			"token_ttl":               {"1h"},
		},
		denied: map[string][]string{
			"allowed_common_names": {"*,*"},
			"token_policies":       {"*,*"},
			"policies":             {"*,*"},
		},
	},
}

// authorNeverCaps are the capabilities the author never holds: it removes
// nothing, and nothing it reaches needs sudo, list or patch.
var authorNeverCaps = []string{"delete", "sudo", "list", "patch"}

// authorSysPaths are the only sys/ paths the author may name.
var authorSysPaths = []string{"sys/mounts/" + AuthorNamespace + "*", "sys/policies/acl/" + AuthorNamespace + "*"}

// globReachesFixed reports the fixed name a path's trailing glob reaches, if
// any: the glob's literal prefix after the last '/' is a prefix of it.
func globReachesFixed(path string) (string, bool) {
	if !strings.HasSuffix(path, "*") {
		return "", false
	}
	lit := strings.TrimSuffix(path, "*")
	lit = lit[strings.LastIndex(lit, "/")+1:]
	for _, f := range fixedNames {
		if strings.HasPrefix(f, lit) {
			return f, true
		}
	}
	return "", false
}

// checkAuthor holds text to authorWant. The named faults come first, each
// with a message naming it; any other difference fails the exact comparison,
// naming the stanza.
func checkAuthor(text []byte) error {
	stanzas, err := parseFull(text)
	if err != nil {
		return err
	}
	want := map[string]stanza{}
	for _, s := range authorWant {
		want[s.path] = s
	}
	seen := map[string]bool{}
	for _, s := range stanzas {
		for _, c := range s.caps {
			if slices.Contains(authorNeverCaps, c) {
				return fmt.Errorf("path %q grants %s", s.path, c)
			}
		}
		if f, ok := globReachesFixed(s.path); ok {
			return fmt.Errorf("path %q reaches the fixed name %s", s.path, f)
		}
		if strings.HasPrefix(s.path, "sys/") && !slices.Contains(authorSysPaths, s.path) {
			return fmt.Errorf("path %q is a sys/ path outside the author's mounts and policies", s.path)
		}
		for _, m := range []map[string][]string{s.allowed, s.denied} {
			if _, star := m["*"]; star {
				return fmt.Errorf("path %q has a \"*\" parameter key, which admits every parameter", s.path)
			}
		}
		for k, v := range s.allowed {
			for _, val := range v {
				f, ok := globReachesFixed("x/" + val)
				if !ok && slices.Contains(fixedNames, val) {
					f, ok = val, true
				}
				if ok && k != "certificate" {
					return fmt.Errorf("path %q allowed_parameters %q = %q reaches the fixed name %s", s.path, k, v, f)
				}
			}
		}
		w, ok := want[s.path]
		if !ok {
			return fmt.Errorf("path %q is not on the allow-list", s.path)
		}
		if seen[s.path] {
			return fmt.Errorf("path %q is granted twice", s.path)
		}
		seen[s.path] = true
		for _, r := range w.required {
			if !slices.Contains(s.required, r) {
				return fmt.Errorf("path %q required_parameters lacks %q", s.path, r)
			}
		}
		for k, v := range w.allowed {
			if !slices.Equal(s.allowed[k], v) {
				return fmt.Errorf("path %q allowed_parameters %q = %q, want exactly %q", s.path, k, s.allowed[k], v)
			}
		}
		if !reflect.DeepEqual(s.denied, w.denied) {
			return fmt.Errorf("path %q denied_parameters = %v, want exactly %v", s.path, s.denied, w.denied)
		}
		if !reflect.DeepEqual(s, w) {
			return fmt.Errorf("path %q is %+v, want exactly %+v", s.path, s, w)
		}
	}
	for _, s := range authorWant {
		if !seen[s.path] {
			return fmt.Errorf("path %q on the allow-list is not granted", s.path)
		}
	}
	return nil
}

// TC-1084-29: the author policy is exactly the three stanzas, with no delete,
// no "*" key, every role parameter required or pinned with "*,*" denied, no
// sys/ path outside its two, and no glob reaching a fixed name; each injected
// fault is refused with a message naming it. The never-grant paths check
// (TestSealRotatePolicy_AndNeverGrantPaths) runs over every file Names lists,
// both new ones included.
func TestAuthorPolicy_Shape(t *testing.T) {
	raw := text(t, AuthorPolicy)
	if err := checkAuthor(raw); err != nil {
		t.Fatalf("the shipped %s.hcl fails the check: %v", AuthorPolicy, err)
	}
	for _, f := range fixedNames {
		if strings.HasPrefix(f, AuthorNamespace) {
			t.Errorf("the fixed name %q is inside the namespace %q", f, AuthorNamespace)
		}
	}
	if !strings.HasPrefix(AppKeysPolicy, AuthorNamespace) || !strings.HasPrefix(AppKeysMount, AuthorNamespace) {
		t.Errorf("%s and %s must sit inside %s, where the author writes them", AppKeysPolicy, AppKeysMount, AuthorNamespace)
	}
	shipped := string(raw)
	const roleOpen = `path "auth/cert/certs/rasputin-app-*" {`
	cases := []struct {
		name, old, new, needle string
	}{
		{"delete added", `capabilities = ["read", "update"]`, `capabilities = ["read", "update", "delete"]`, `"sys/mounts/rasputin-app-*" grants delete`},
		{"the type unpinned", `"type" = ["transit"]`, `"type" = []`, `"sys/mounts/rasputin-app-*" allowed_parameters "type" = [], want exactly ["transit"]`},
		{"a * key", `"token_ttl"               = ["1h"]`, `"token_ttl"               = ["1h"]` + "\n    \"*\" = []", `has a "*" parameter key`},
		{"the CN unpinned", `"allowed_common_names"    = ["rasputin-app-*"]`, `"allowed_common_names"    = []`, `allowed_parameters "allowed_common_names" = [], want exactly ["rasputin-app-*"]`},
		{"the CN reaching rasputin-provisioner", `"allowed_common_names"    = ["rasputin-app-*"]`, `"allowed_common_names"    = ["rasputin-*"]`, `reaches the fixed name`},
		{"*,* removed", "    \"token_policies\"       = [\"*,*\"]\n", "", `denied_parameters = map[allowed_common_names:[*,*] policies:[*,*]]`},
		{"the policies alias unpinned", `"policies"                = ["rasputin-app-*"]`, `"policies"                = []`, `allowed_parameters "policies" = [], want exactly ["rasputin-app-*"]`},
		{"the policies alias binding rasputin-api", `"policies"                = ["rasputin-app-*"]`, `"policies"                = ["rasputin-api"]`, `"policies" = ["rasputin-api"] reaches the fixed name rasputin-api`},
		{"a namespace that reaches rasputin-api", `path "sys/policies/acl/rasputin-app-*" {`, `path "sys/policies/acl/rasputin-a*" {`, `"sys/policies/acl/rasputin-a*" reaches the fixed name rasputin-api`},
		{"an extra sys/ stanza", roleOpen, `path "sys/rotate/root" { capabilities = ["update"] }` + "\n" + roleOpen, `"sys/rotate/root" is a sys/ path outside`},
		{"a missing required parameter", `"token_no_default_policy", "token_ttl"]`, `"token_ttl"]`, `required_parameters lacks "token_no_default_policy"`},
		{"a longer ttl", `"token_ttl"               = ["1h"]`, `"token_ttl"               = ["24h"]`, `"token_ttl" = ["24h"], want exactly ["1h"]`},
		{"an auth/token path", roleOpen, `path "auth/token/create" { capabilities = ["update"] }` + "\n" + roleOpen, `"auth/token/create" is not on the allow-list`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(shipped, tc.old) != 1 {
				t.Fatalf("the injection anchor %q is not in the shipped text exactly once", tc.old)
			}
			injected := strings.Replace(shipped, tc.old, tc.new, 1)
			err := checkAuthor([]byte(injected))
			if err == nil {
				t.Fatalf("the check passed with %s injected:\n%s", tc.name, injected)
			}
			if !strings.Contains(err.Error(), tc.needle) {
				t.Errorf("refusal %q does not name the fault (%s)", err, tc.needle)
			}
		})
	}
}

// firstBootSHA256 is each first-boot policy file's sha256 at origin/main
// 0ba301f7, before geekdojo/geekdojo-brain#1084. ADR-0010 S9 (ruled
// 2026-11-15): a release never edits a policy created at first boot, so a
// change to any of these is a refusal, not an update to this table.
var firstBootSHA256 = map[string]string{
	APIPolicy:         "3c380b2a6eb87a387ab6afad1d800e79702e9abdb25628971da47102e87bf51b",
	SealRotatePolicy:  "4c23732f5889724db3a885c00262bad7e3a26e5520ab5b47731aae584b4572f2",
	ProvisionerPolicy: "d09e71c5a169ff03d469ea4e0311a5f03cd7253ee5aed7e12565f3c0ec4329c8",
	BindablePolicy:    "9d12d8f7e3684a8f1e91936fa3acee452283a29267fc85529e93c242dfa02ef1",
}

// TC-1084-30: every first-boot policy is byte-equal to origin/main 0ba301f7,
// and the new constants hold their stated values. Names is exactly the six
// policies (TestNamesAndText); the pack script's test checks both new files
// arrive (scripts/test-pack-store-policy.sh).
func TestFirstBootPolicies_Unchanged(t *testing.T) {
	for name, want := range firstBootSHA256 {
		sum := sha256.Sum256(text(t, name))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s.hcl sha256 = %s, want %s: a first-boot policy is never edited (ADR-0010 S9)", name, got, want)
		}
	}
	if AuthorPolicy != "rasputin-author" || AuthorNamespace != "rasputin-app-" {
		t.Errorf("AuthorPolicy, AuthorNamespace = %q, %q", AuthorPolicy, AuthorNamespace)
	}
}
