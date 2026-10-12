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
// policy_functional_test.go, against the real pinned store. A small parser
// over our own files is enough here (no HCL parser dependency, #685): it reads
// only the shape these files use, path stanzas holding capabilities and the
// three parameter constraints, and refuses anything else, so a construct it
// cannot read fails rather than passing unread.

// stanza is one `path "P" { ... }` block. The parameter fields are nil when
// the stanza does not set them.
type stanza struct {
	path     string
	caps     []string
	allowed  map[string][]string
	required []string
	denied   map[string][]string
}

var (
	// stanzaRE matches a capabilities-only stanza; replaceStanza uses it.
	stanzaRE = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}`)
	capRE    = regexp.MustCompile(`^[a-z]+$`)
	identRE  = regexp.MustCompile(`^[a-z_]+$`)
)

// token is one lexical item: a quoted string (str set) or anything else.
type token struct {
	text string
	str  bool
}

// lex splits text into tokens: "#" comments to the end of the line are
// dropped; a quoted string may hold no backslash or newline; a bare word is
// lowercase letters and underscores; the punctuation is { } [ ] = and ,.
// Anything else is an error naming it.
func lex(text []byte) ([]token, error) {
	var out []token
	s := string(text)
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '"':
			j := strings.IndexAny(s[i+1:], "\"\\\n")
			if j < 0 || s[i+1+j] != '"' {
				return nil, fmt.Errorf("an unterminated or escaped string at byte %d", i)
			}
			out = append(out, token{text: s[i+1 : i+1+j], str: true})
			i += j + 2
		case strings.IndexByte("{}[]=,", c) >= 0:
			out = append(out, token{text: string(c)})
			i++
		case c >= 'a' && c <= 'z' || c == '_':
			j := i
			for j < len(s) && (s[j] >= 'a' && s[j] <= 'z' || s[j] == '_') {
				j++
			}
			out = append(out, token{text: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected %q at byte %d", c, i)
		}
	}
	return out, nil
}

// parser walks the tokens of one file.
type parser struct {
	toks []token
	pos  int
}

func (p *parser) next() (token, bool) {
	if p.pos >= len(p.toks) {
		return token{}, false
	}
	t := p.toks[p.pos]
	p.pos++
	return t, true
}

// expect consumes the punctuation or bare word want.
func (p *parser) expect(want string) error {
	t, ok := p.next()
	if !ok || t.str || t.text != want {
		return fmt.Errorf("want %q, got %q", want, t.text)
	}
	return nil
}

// list reads [ "a", "b" ]; an empty list is a non-nil empty slice.
func (p *parser) list() ([]string, error) {
	if err := p.expect("["); err != nil {
		return nil, err
	}
	out := []string{}
	for {
		t, ok := p.next()
		if !ok {
			return nil, fmt.Errorf("an unterminated list")
		}
		if !t.str && t.text == "]" {
			return out, nil
		}
		if !t.str {
			return nil, fmt.Errorf("a list item %q that is not a quoted string", t.text)
		}
		out = append(out, t.text)
		t, ok = p.next()
		if !ok {
			return nil, fmt.Errorf("an unterminated list")
		}
		if !t.str && t.text == "]" {
			return out, nil
		}
		if t.str || t.text != "," {
			return nil, fmt.Errorf("want , or ] in a list, got %q", t.text)
		}
	}
}

// object reads { "key" = [ ... ] ... }, refusing a repeated key.
func (p *parser) object() (map[string][]string, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for {
		t, ok := p.next()
		if !ok {
			return nil, fmt.Errorf("an unterminated object")
		}
		if !t.str && t.text == "}" {
			return out, nil
		}
		if _, dup := out[t.text]; dup {
			return nil, fmt.Errorf("the key %q is given twice", t.text)
		}
		if err := p.expect("="); err != nil {
			return nil, err
		}
		v, err := p.list()
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", t.text, err)
		}
		out[t.text] = v
	}
}

// parseFull reads text as path stanzas, each holding capabilities and any of
// allowed_parameters, required_parameters and denied_parameters, once each.
// Anything else is an error naming it.
func parseFull(text []byte) ([]stanza, error) {
	toks, err := lex(text)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	var out []stanza
	for p.pos < len(p.toks) {
		if err := p.expect("path"); err != nil {
			return nil, fmt.Errorf("text that is not a path stanza: %w", err)
		}
		t, ok := p.next()
		if !ok || !t.str {
			return nil, fmt.Errorf("a path stanza with no quoted path")
		}
		s := stanza{path: t.text}
		if err := p.expect("{"); err != nil {
			return nil, fmt.Errorf("path %q: %w", s.path, err)
		}
		seen := map[string]bool{}
		for {
			t, ok := p.next()
			if !ok {
				return nil, fmt.Errorf("path %q: an unterminated stanza", s.path)
			}
			if !t.str && t.text == "}" {
				break
			}
			if t.str || !identRE.MatchString(t.text) || seen[t.text] {
				return nil, fmt.Errorf("path %q: %q is not a key this parser reads, or is given twice", s.path, t.text)
			}
			seen[t.text] = true
			if err := p.expect("="); err != nil {
				return nil, fmt.Errorf("path %q: %w", s.path, err)
			}
			var err error
			switch t.text {
			case "capabilities":
				s.caps, err = p.list()
				for _, c := range s.caps {
					if err == nil && !capRE.MatchString(c) {
						err = fmt.Errorf("capability %q is not a lowercase word", c)
					}
				}
			case "required_parameters":
				s.required, err = p.list()
			case "allowed_parameters":
				s.allowed, err = p.object()
			case "denied_parameters":
				s.denied, err = p.object()
			default:
				err = fmt.Errorf("%q is not a key this parser reads", t.text)
			}
			if err != nil {
				return nil, fmt.Errorf("path %q: %w", s.path, err)
			}
		}
		if len(s.caps) == 0 {
			return nil, fmt.Errorf("path %q grants no capability", s.path)
		}
		out = append(out, s)
	}
	return out, nil
}

// parse reads text as capabilities-only path stanzas: the api, seal-rotate
// and bindable policies carry no parameter constraint, so one there is an
// error naming its stanza.
func parse(text []byte) ([]stanza, error) {
	stanzas, err := parseFull(text)
	if err != nil {
		return nil, err
	}
	for _, s := range stanzas {
		if s.allowed != nil || s.required != nil || s.denied != nil {
			return nil, fmt.Errorf("path %q sets a parameter constraint", s.path)
		}
	}
	return stanzas, nil
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

// TC-804-01, TC-805-01: Names is exactly the four policies, Text returns the
// embedded bytes (the files in this directory, byte for byte), and an unknown
// name is refused with a message naming it.
func TestNamesAndText(t *testing.T) {
	want := []string{APIPolicy, BindablePolicy, ProvisionerPolicy, SealRotatePolicy}
	if got := Names(); !reflect.DeepEqual(got, want) {
		t.Errorf("Names() = %v, want exactly %v", got, want)
	}
	if Mount != "rasputin-secrets" || APIPolicy != "rasputin-api" || SealRotatePolicy != "rasputin-seal-rotate" ||
		ProvisionerPolicy != "rasputin-provisioner" || BindablePolicy != "rasputin-bindable" || Namespace != "rasputin-rel-" {
		t.Errorf("Mount, APIPolicy, SealRotatePolicy, ProvisionerPolicy, BindablePolicy, Namespace = %q, %q, %q, %q, %q, %q",
			Mount, APIPolicy, SealRotatePolicy, ProvisionerPolicy, BindablePolicy, Namespace)
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

// TC-804-03, TC-805-04: the rotation policy is exactly one stanza,
// sys/rotate/root with update and sudo, and no never-grant path appears in any
// of the four files.
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

// TC-805-04 (D-805-A): the bindable policy is exactly a read of the token's own
// lookup, the one policy a provisioned role may bind.
func TestBindablePolicy_LookupSelfOnly(t *testing.T) {
	stanzas, err := parse(text(t, BindablePolicy))
	if err != nil {
		t.Fatal(err)
	}
	want := []stanza{{path: "auth/token/lookup-self", caps: []string{"read"}}}
	if !reflect.DeepEqual(stanzas, want) {
		t.Errorf("%s.hcl = %+v, want exactly %+v", BindablePolicy, stanzas, want)
	}
}

// provisionerWant is rasputin-provisioner.hcl's whole shape (plan, #805):
// three stanzas, binding-only, every parameter pinned.
var provisionerWant = []stanza{
	{
		path:    "sys/mounts/" + Namespace + "*",
		caps:    []string{"read", "update"},
		allowed: map[string][]string{"type": {"kv-v2"}},
	},
	{path: "auth/cert/certs/", caps: []string{"list"}},
	{
		path:     "auth/cert/certs/" + Namespace + "*",
		caps:     []string{"update"},
		required: []string{"certificate", "allowed_common_names", "token_policies", "token_no_default_policy", "token_ttl"},
		allowed: map[string][]string{
			"certificate":             {},
			"allowed_common_names":    {Namespace + "*"},
			"token_policies":          {BindablePolicy},
			"policies":                {BindablePolicy},
			"token_no_default_policy": {"true"},
			"token_ttl":               {"1h"},
		},
		denied: map[string][]string{"allowed_common_names": {"*,*"}},
	},
}

// forbiddenCaps are the capabilities the provisioner never holds: it creates
// through update on paths with no existence check, and removes nothing.
var forbiddenCaps = []string{"create", "delete", "patch", "sudo"}

// checkProvisioner holds text to provisionerWant. The named faults come first,
// each with a message naming it; any other difference fails the exact
// comparison, naming the stanza.
func checkProvisioner(text []byte) error {
	stanzas, err := parseFull(text)
	if err != nil {
		return err
	}
	want := map[string]stanza{}
	for _, s := range provisionerWant {
		want[s.path] = s
	}
	seen := map[string]bool{}
	for _, s := range stanzas {
		for _, c := range s.caps {
			if slices.Contains(forbiddenCaps, c) {
				return fmt.Errorf("path %q grants %s", s.path, c)
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
		for _, m := range []map[string][]string{s.allowed, s.denied} {
			if _, star := m["*"]; star {
				return fmt.Errorf("path %q has a \"*\" parameter key, which admits every parameter", s.path)
			}
		}
		for _, k := range []string{"token_policies", "policies"} {
			if v, ok := s.allowed[k]; ok && !slices.Equal(v, []string{BindablePolicy}) {
				return fmt.Errorf("path %q allowed_parameters %q = %q, want exactly [%q] (an empty list admits any policy)", s.path, k, v, BindablePolicy)
			}
		}
		for _, r := range w.required {
			if !slices.Contains(s.required, r) {
				return fmt.Errorf("path %q required_parameters lacks %q", s.path, r)
			}
		}
		if !reflect.DeepEqual(s.denied, w.denied) {
			return fmt.Errorf("path %q denied_parameters = %v, want exactly %v", s.path, s.denied, w.denied)
		}
		if !reflect.DeepEqual(s, w) {
			return fmt.Errorf("path %q is %+v, want exactly %+v", s.path, s, w)
		}
	}
	for _, s := range provisionerWant {
		if !seen[s.path] {
			return fmt.Errorf("path %q on the allow-list is not granted", s.path)
		}
	}
	return nil
}

// TC-805-02 (D-805-A): the shipped provisioner policy is binding-only with
// string pins: exactly provisionerWant, no "*" key and no create, delete,
// patch or sudo; both policy pins are BindablePolicy and never a fixed or
// built-in policy; and the namespace prefixes no fixed name.
func TestProvisionerPolicy_BindingOnly(t *testing.T) {
	raw := text(t, ProvisionerPolicy)
	if err := checkProvisioner(raw); err != nil {
		t.Fatalf("the shipped %s.hcl fails the check: %v", ProvisionerPolicy, err)
	}
	stanzas, err := parseFull(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stanzas, provisionerWant) {
		t.Errorf("%s.hcl = %+v, want exactly %+v", ProvisionerPolicy, stanzas, provisionerWant)
	}
	for _, s := range stanzas {
		for _, m := range []map[string][]string{s.allowed, s.denied} {
			if _, star := m["*"]; star {
				t.Errorf("path %q has a \"*\" parameter key", s.path)
			}
		}
		for _, c := range forbiddenCaps {
			if slices.Contains(s.caps, c) {
				t.Errorf("path %q grants %s", s.path, c)
			}
		}
	}
	role := stanzas[2].allowed
	for _, k := range []string{"token_policies", "policies"} {
		if !slices.Equal(role[k], []string{BindablePolicy}) {
			t.Errorf("%s pins %v, want exactly [%s]", k, role[k], BindablePolicy)
		}
	}
	for _, never := range []string{APIPolicy, SealRotatePolicy, ProvisionerPolicy, "root", "default"} {
		if BindablePolicy == never {
			t.Errorf("the bindable policy is %q", never)
		}
	}
	// The fixed names: every policy, each policy's role (same name) and the mount.
	for _, fixed := range append(Names(), Mount) {
		if strings.HasPrefix(fixed, Namespace) {
			t.Errorf("the fixed name %q is inside the namespace %q", fixed, Namespace)
		}
	}
}

// TC-805-03: the checker refuses each injected fault, with a message naming it.
func TestProvisionerPolicy_CheckerRefusesFaults(t *testing.T) {
	shipped := string(text(t, ProvisionerPolicy))
	const roleOpen = `path "auth/cert/certs/rasputin-rel-*" {`
	cases := []struct {
		name, old, new, needle string
	}{
		{"a \"*\" key", `"token_ttl"               = ["1h"]`, `"token_ttl"               = ["1h"]` + "\n    \"*\" = []", `has a "*" parameter key`},
		{"an empty token_policies", `"token_policies"          = ["rasputin-bindable"]`, `"token_policies"          = []`, `"token_policies" = [], want exactly ["rasputin-bindable"]`},
		{"a second pinned policy", `"policies"                = ["rasputin-bindable"]`, `"policies"                = ["rasputin-bindable", "rasputin-api"]`, `"policies" = ["rasputin-bindable" "rasputin-api"]`},
		{"sys/policies/acl/x", roleOpen, `path "sys/policies/acl/x" { capabilities = ["update"] }` + "\n" + roleOpen, `path "sys/policies/acl/x" is not on the allow-list`},
		{"auth/cert/certs/*", roleOpen, `path "auth/cert/certs/*" { capabilities = ["update"] }` + "\n" + roleOpen, `path "auth/cert/certs/*" is not on the allow-list`},
		{"auth/cert/certs/rasputin-api", roleOpen, `path "auth/cert/certs/rasputin-api" { capabilities = ["update"] }` + "\n" + roleOpen, `path "auth/cert/certs/rasputin-api" is not on the allow-list`},
		{"sudo", `capabilities = ["update"]`, `capabilities = ["update", "sudo"]`, `"auth/cert/certs/rasputin-rel-*" grants sudo`},
		{"delete", `capabilities = ["read", "update"]`, `capabilities = ["read", "update", "delete"]`, `"sys/mounts/rasputin-rel-*" grants delete`},
		{"create", `capabilities = ["update"]`, `capabilities = ["create", "update"]`, `"auth/cert/certs/rasputin-rel-*" grants create`},
		{"a missing required_parameters entry", `"token_no_default_policy", "token_ttl"]`, `"token_ttl"]`, `required_parameters lacks "token_no_default_policy"`},
		{"a missing denied_parameters", "  denied_parameters = {\n    \"allowed_common_names\" = [\"*,*\"]\n  }\n", "", `denied_parameters = map[], want exactly map[allowed_common_names:[*,*]]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(shipped, tc.old) != 1 {
				t.Fatalf("the injection anchor %q is not in the shipped text exactly once", tc.old)
			}
			injected := strings.Replace(shipped, tc.old, tc.new, 1)
			err := checkProvisioner([]byte(injected))
			if err == nil {
				t.Fatalf("the check passed with %s injected:\n%s", tc.name, injected)
			}
			if !strings.Contains(err.Error(), tc.needle) {
				t.Errorf("refusal %q does not name the fault (%s)", err, tc.needle)
			}
		})
	}
}

func text(t *testing.T, name string) []byte {
	t.Helper()
	b, err := Text(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
