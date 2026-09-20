package proto

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func baseSeed() Seed {
	return Seed{
		Role:      RoleCompute,
		NodeID:    "home1-compute1",
		ClusterID: "home1",
		NATSURL:   "nats://home1.local:4222",
		JoinToken: "tok-abc",
		BusPin:    BusPinPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Origin:    "rasputin-provision",
	}
}

func TestRenderSeed_KeyOrderAndRequiredLines(t *testing.T) {
	got, err := RenderSeed(baseSeed())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{SeedKeyRole, SeedKeyNodeID, SeedKeyClusterID, SeedKeyNATSURL, SeedKeyJoinToken, SeedKeyBusPin}
	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, _, _ := strings.Cut(line, "=")
		keys = append(keys, k)
	}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("keys = %v, want %v\n%s", keys, want, got)
	}
	if !strings.HasPrefix(got, "# "+SeedFileNameOS) {
		t.Errorf("header does not name the file the image looks for:\n%s", got)
	}
	if !strings.Contains(got, "rasputin-provision") {
		t.Errorf("header does not name the origin:\n%s", got)
	}
}

// Empty optional lines are omitted, not written blank: an absent key and an
// empty one mean different things to both images (the fallback address is the
// standing example).
func TestRenderSeed_OmitsEmptyOptionalLines(t *testing.T) {
	s := baseSeed()
	s.JoinToken, s.BusPin, s.SSHAuthorizedKey, s.NATSURL = "", "", "", ""
	got, err := RenderSeed(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{SeedKeyJoinToken, SeedKeyBusPin, SeedKeySSHKey, SeedKeyNATSURL, SeedKeyBusAuth, SeedKeyBusKey} {
		if strings.Contains(got, k) {
			t.Errorf("%s written for an empty value:\n%s", k, got)
		}
	}
	for _, k := range []string{SeedKeyRole, SeedKeyNodeID, SeedKeyClusterID} {
		if !strings.Contains(got, k) {
			t.Errorf("%s missing:\n%s", k, got)
		}
	}
}

func TestRenderSeed_ClusterIDDefaults(t *testing.T) {
	s := baseSeed()
	s.ClusterID = "  "
	got, err := RenderSeed(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, SeedKeyClusterID+"='"+DefaultClusterID+"'") {
		t.Errorf("a blank cluster id did not fall back to %q:\n%s", DefaultClusterID, got)
	}
}

func TestRenderSeed_RequiresRoleAndNodeID(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Seed)
		want string
	}{
		{"no role", func(s *Seed) { s.Role = "" }, SeedKeyRole},
		{"unknown role", func(s *Seed) { s.Role = "router" }, "router"},
		{"no node id", func(s *Seed) { s.NodeID = "" }, SeedKeyNodeID},
		{"upper-case node id", func(s *Seed) { s.NodeID = "Compute1" }, SeedKeyNodeID},
		{"node id ending in a hyphen", func(s *Seed) { s.NodeID = "compute1-" }, SeedKeyNodeID},
		{"node id with a dot", func(s *Seed) { s.NodeID = "compute1.home" }, SeedKeyNodeID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSeed()
			tc.mut(&s)
			got, err := RenderSeed(s)
			if err == nil {
				t.Fatalf("rendered %q with no error:\n%s", tc.name, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// A value that cannot be one line of an env file is an error, never something
// escaped into a shape whose meaning depends on the reader.
func TestRenderSeed_RefusesUnwritableValues(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"newline", "ssh-ed25519 AAAA me\nssh-ed25519 BBBB them"},
		{"carriage return", "ssh-ed25519 AAAA me\r"},
		{"NUL", "ssh-ed25519 AAAA me\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSeed()
			s.SSHAuthorizedKey = tc.value
			if got, err := RenderSeed(s); err == nil {
				t.Fatalf("rendered a value with a %s:\n%s", tc.name, got)
			} else if !strings.Contains(err.Error(), SeedKeySSHKey) {
				t.Errorf("error %q does not name the field", err)
			}
		})
	}
}

// THE invariant: whatever Render writes, a POSIX shell reads back byte for
// byte. Every value is quoted, so nothing in a seed is ever script.
func TestRenderSeed_SourcedByShellRoundTrips(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on this machine: %v", err)
	}
	hostile := []struct{ name, value string }{
		{"plain", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI me@laptop"},
		{"spaces", "ssh-ed25519 AAAA my laptop, at home"},
		{"a command substitution", "ssh-ed25519 AAAA $(id)"},
		{"backticks", "ssh-ed25519 AAAA `id`"},
		{"a semicolon", "ssh-ed25519 AAAA x; id"},
		{"a double quote", `ssh-ed25519 AAAA "quoted"`},
		{"a single quote", "ssh-ed25519 AAAA it's mine"},
		{"backslashes", `ssh-ed25519 AAAA C:\Users\me`},
		{"a dollar variable", "ssh-ed25519 AAAA $HOME"},
		{"an ampersand and a pipe", "ssh-ed25519 AAAA a & b | c"},
		{"a newline in a quote", "ssh-ed25519 AAAA '"},
	}
	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSeed()
			s.SSHAuthorizedKey = tc.value
			// Hostile in the other fields too, where the format allows it.
			s.ClusterID = "home1"
			rendered, err := RenderSeed(s)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "seed.env")
			if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			// Source it the way both images do, then print the value with a
			// sentinel either side so trailing whitespace is visible.
			script := ". '" + path + "'; printf '<%s>' \"$" + SeedKeySSHKey + "\""
			out, err := exec.Command(sh, "-c", script).Output() // #nosec G204 -- the script is this test's, the path is t.TempDir()'s
			if err != nil {
				t.Fatalf("sourcing the seed failed: %v\n%s", err, rendered)
			}
			if got, want := string(out), "<"+tc.value+">"; got != want {
				t.Errorf("sh read %q, want %q\nrendered:\n%s", got, want, rendered)
			}
		})
	}
}

// Nothing in a seed runs. The canary is a file the script would create if the
// shell ever evaluated a value.
func TestRenderSeed_SourcingRunsNothing(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on this machine: %v", err)
	}
	dir := t.TempDir()
	canary := filepath.Join(dir, "canary")
	s := baseSeed()
	s.SSHAuthorizedKey = "ssh-ed25519 AAAA $(touch " + canary + ")`touch " + canary + "`"
	rendered, err := RenderSeed(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "seed.env")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-c", ". '"+path+"'").CombinedOutput(); err != nil { // #nosec G204 -- this test's own script and temp dir
		t.Fatalf("sourcing failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatal("sourcing the seed executed a value")
	}
}

func TestParseSeed_RoundTripsEveryField(t *testing.T) {
	s := baseSeed()
	s.Role = RoleControlPlane
	s.JoinToken = ""
	s.SSHAuthorizedKey = "ssh-ed25519 AAAA it's me"
	s.BusAuth = "enforce"
	// Base64-SHAPED, but deliberately low-entropy and repetitive: the field
	// carries a bus PRIVATE key on a real controlplane seed, and a realistic
	// stand-in here is a value a secret scanner has to be told to ignore.
	// Nothing in the renderer reads it, so the shape is all this needs.
	s.BusKey = strings.Repeat("A", 40) + "=="
	rendered, err := RenderSeed(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSeed(strings.NewReader(rendered))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Extra) != 0 {
		t.Errorf("extra = %v, want none", got.Extra)
	}
	s.Origin = "" // not a field of the file
	got.Origin = ""
	if !reflect.DeepEqual(got, s) {
		t.Errorf("round trip:\n got %+v\nwant %+v\nrendered:\n%s", got, s, rendered)
	}
}

// Every seed minted before this change is unquoted, and those files are still
// on the FAT volumes of nodes that have not been reflashed.
func TestParseSeed_ReadsTheOlderUnquotedAndDoubleQuotedForms(t *testing.T) {
	old := "# rasputin-seed.env — generated by rasputin-provision\n" +
		"RASPUTIN_NODE_ROLE=compute\n" +
		"RASPUTIN_NODE_ID=compute1\n" +
		"RASPUTIN_CLUSTER_ID=home1\n" +
		"RASPUTIN_NATS_URL=nats://home1.local:4222\n" +
		"RASPUTIN_CP_JOIN_TOKEN=tok-abc\n" +
		"RASPUTIN_SSH_AUTHORIZED_KEY=\"ssh-ed25519 AAAA me@laptop\"\n"
	got, err := ParseSeed(strings.NewReader(old))
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != RoleCompute || got.NodeID != "compute1" || got.JoinToken != "tok-abc" {
		t.Errorf("parsed %+v", got)
	}
	if got.SSHAuthorizedKey != "ssh-ed25519 AAAA me@laptop" {
		t.Errorf("ssh key = %q", got.SSHAuthorizedKey)
	}
}

// Unknown keys are kept rather than dropped: a seed from a newer control plane
// must not be silently truncated by an older reader.
func TestParseSeed_KeepsUnknownKeys(t *testing.T) {
	got, err := ParseSeed(strings.NewReader("RASPUTIN_NODE_ROLE='compute'\nRASPUTIN_SOMETHING_NEW='x y'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Extra["RASPUTIN_SOMETHING_NEW"] != "x y" {
		t.Errorf("extra = %v", got.Extra)
	}
}

// A value whose meaning would depend on the reader is refused, not guessed at.
func TestParseSeed_RefusesAmbiguousValues(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"unquoted command substitution", "RASPUTIN_NODE_ID=$(id)"},
		{"unquoted backticks", "RASPUTIN_NODE_ID=`id`"},
		{"an expansion inside double quotes", `RASPUTIN_NODE_ID="$HOME"`},
		{"an unclosed single quote", "RASPUTIN_NODE_ID='compute1"},
		{"an unclosed double quote", `RASPUTIN_NODE_ID="compute1`},
		{"a bare quote inside single quotes", "RASPUTIN_NODE_ID='a'b'"},
		{"not KEY=VALUE", "rm -rf /"},
		{"a name that is not a variable", "2FOO='x'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSeed(strings.NewReader(tc.line + "\n")); err == nil {
				t.Errorf("parsed %q with no error", tc.line)
			}
		})
	}
}

func TestParseSeed_SkipsCommentsAndBlanks(t *testing.T) {
	got, err := ParseSeed(strings.NewReader("# a comment\n\n   \nRASPUTIN_NODE_ID='compute1'\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != "compute1" {
		t.Errorf("node id = %q", got.NodeID)
	}
}

func TestValidSeedNodeID(t *testing.T) {
	for _, ok := range []string{"a", "compute1", "home1-compute1", "a-b-c", strings.Repeat("a", 63)} {
		if !ValidSeedNodeID(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a_b", "a.b", "a b", strings.Repeat("a", 64)} {
		if ValidSeedNodeID(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestSeedFileName(t *testing.T) {
	if got := SeedFileName(RoleFirewall); got != SeedFileNameFirewall {
		t.Errorf("firewall seed file = %q", got)
	}
	for _, r := range []NodeRole{RoleCompute, RoleStorage, RoleControlPlane} {
		if got := SeedFileName(r); got != SeedFileNameOS {
			t.Errorf("%s seed file = %q", r, got)
		}
	}
}

// Extra carries the keys Seed does not name — both images read several — and
// they survive a render/parse round trip, sorted and quoted like the rest.
func TestRenderSeed_ExtraKeys(t *testing.T) {
	s := baseSeed()
	s.Extra = map[string]string{
		"RASPUTIN_NTP_SERVER":       "ntp1.example 10.0.0.1",
		"RASPUTIN_FALLBACK_ADDRESS": "",
		"RASPUTIN_BMC_HOST":         "bmc1",
	}
	rendered, err := RenderSeed(s)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted, and after the named fields.
	want := "RASPUTIN_BMC_HOST='bmc1'\nRASPUTIN_FALLBACK_ADDRESS=''\nRASPUTIN_NTP_SERVER='ntp1.example 10.0.0.1'\n"
	if !strings.HasSuffix(rendered, want) {
		t.Errorf("extras:\n%s\nwant it to end with:\n%s", rendered, want)
	}
	// An extra whose value is EMPTY is still written: for the fallback
	// address, set-but-empty is the operator's explicit "take none", and
	// dropping the line would silently restore the default.
	got, err := ParseSeed(strings.NewReader(rendered))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Extra) != 3 || got.Extra["RASPUTIN_NTP_SERVER"] != "ntp1.example 10.0.0.1" {
		t.Errorf("extra = %v", got.Extra)
	}
	if _, present := got.Extra["RASPUTIN_FALLBACK_ADDRESS"]; !present {
		t.Error("an explicitly empty extra was dropped")
	}
}

// A named field must not also arrive through Extra: two lines for one key
// would leave the file's meaning up to which one a shell read last.
func TestRenderSeed_ExtraCannotShadowANamedField(t *testing.T) {
	s := baseSeed()
	s.Extra = map[string]string{SeedKeyNodeID: "someone-else"}
	if _, err := RenderSeed(s); err == nil {
		t.Error("an Extra key shadowing a named field rendered without error")
	}
}

// The mutation gate found four changes to this file that every test above
// still passed on, and a handful of lines nothing executed. Each case below
// fails for exactly one of them; they are grouped here rather than scattered
// because what they have in common is that they are the EDGES — the first
// byte, the last byte, the empty value, the one-character string — which is
// where a hand-rolled parser goes wrong.

// A forbidden byte at index 0. `i >= 0` and `i > 0` behave identically for
// every value where the newline is in the middle, which is what the cases
// above use.
func TestRenderSeed_RefusesAForbiddenByteAtTheStart(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"a leading newline", "\nssh-ed25519 AAAA me"},
		{"a leading carriage return", "\rssh-ed25519 AAAA me"},
		{"a leading NUL", "\x00ssh-ed25519 AAAA me"},
		{"nothing but a newline", "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSeed()
			s.SSHAuthorizedKey = tc.value
			if got, err := RenderSeed(s); err == nil {
				t.Fatalf("rendered a value starting with a forbidden byte:\n%s", got)
			}
		})
	}
}

// The line number in a parse error is the whole value of the message: it is
// read off a console beside a file the operator has to edit. Nothing above
// asserted it, so a counter that stopped counting would have gone unnoticed.
func TestParseSeed_ErrorNamesTheLineNumber(t *testing.T) {
	for _, tc := range []struct {
		name, seed, want string
	}{
		{"the first line", "rm -rf /\n", "line 1"},
		{"a later line", "# a comment\n\nRASPUTIN_NODE_ID='n1'\nrm -rf /\n", "line 4"},
		{"blank lines still count", "\n\n\n\nRASPUTIN_NODE_ID=$(id)\n", "line 5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSeed(strings.NewReader(tc.seed))
			if err == nil {
				t.Fatal("parsed without error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// The edges of the quoting the renderer itself produces: a quote as the FIRST
// byte of a single-quoted body, and as the last.
func TestSeed_QuoteAtTheEdgesOfAValue(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"a value that is one quote", "'"},
		{"a value that starts with a quote", "'me"},
		{"a value that ends with a quote", "me'"},
		{"a value that is two quotes", "''"},
		{"quotes either side", "'me'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSeed()
			s.SSHAuthorizedKey = tc.value
			rendered, err := RenderSeed(s)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseSeed(strings.NewReader(rendered))
			if err != nil {
				t.Fatalf("the renderer's own output did not parse: %v\n%s", err, rendered)
			}
			if got.SSHAuthorizedKey != tc.value {
				t.Errorf("round trip gave %q, want %q\nrendered:\n%s", got.SSHAuthorizedKey, tc.value, rendered)
			}
		})
	}
}

// One-character values, where a length check is the only thing standing
// between a parse and an index out of range.
func TestParseSeed_OneCharacterValues(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		wantErr    bool
		want       string
	}{
		{name: "a bare double quote", line: `RASPUTIN_NODE_ID="`, wantErr: true},
		{name: "a bare single quote", line: "RASPUTIN_NODE_ID='", wantErr: true},
		{name: "an empty double-quoted value", line: `RASPUTIN_NODE_ID=""`, want: ""},
		{name: "an empty single-quoted value", line: "RASPUTIN_NODE_ID=''", want: ""},
		{name: "no value at all", line: "RASPUTIN_NODE_ID=", want: ""},
		{name: "only whitespace after the =", line: "RASPUTIN_NODE_ID=   ", want: ""},
		{name: "an unterminated double-quoted value", line: `RASPUTIN_NODE_ID="me\`, wantErr: true},
		// The body's LAST byte is the backslash, and the value does close —
		// so this reaches the escape handling rather than being turned away
		// by the closing-quote check, and is the only input that does.
		{name: "a backslash as the last byte inside double quotes", line: `RASPUTIN_NODE_ID="me\"`, wantErr: true},
		{name: "an escaped quote at the end", line: `RASPUTIN_NODE_ID="me\""`, want: `me"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSeed(strings.NewReader(tc.line + "\n"))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsed %q without error", tc.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsing %q: %v", tc.line, err)
			}
			if got.NodeID != tc.want {
				t.Errorf("node id = %q, want %q", got.NodeID, tc.want)
			}
		})
	}
}

// NATSURLFor decides the bus every seeded node dials. Getting it wrong is the
// silent failure the one-renderer change exists to end: a node that boots,
// resolves nothing and never joins (control-plane #70).
func TestNATSURLFor(t *testing.T) {
	for _, tc := range []struct{ name, hostname, want string }{
		{"a named cluster", "home1.local", "nats://home1.local:4222"},
		{"surrounding whitespace is trimmed", "  home1.local  ", "nats://home1.local:4222"},
		{"no hostname falls back to the dev-box name", "", DefaultNATSURL},
		{"whitespace only is no hostname", "   ", DefaultNATSURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NATSURLFor(tc.hostname); got != tc.want {
				t.Errorf("NATSURLFor(%q) = %q, want %q", tc.hostname, got, tc.want)
			}
		})
	}
	// The fallback is a real bus URL, not a placeholder, and it names the
	// port the bus listens on.
	if !strings.HasPrefix(DefaultNATSURL, "nats://") || !strings.HasSuffix(DefaultNATSURL, ":4222") {
		t.Errorf("DefaultNATSURL = %q", DefaultNATSURL)
	}
}
