package bus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// mentionsRetiredVariable reports whether s names the retired
// RASPUTIN_CP_JOIN_TOKEN on its own. The file variable's name begins with the
// retired one, so its occurrences are removed before looking.
func mentionsRetiredVariable(s string) bool {
	return strings.Contains(strings.ReplaceAll(s, EnvJoinTokenFile, ""), EnvJoinToken)
}

// TC-539-01 to TC-539-05: the resolver over role × named file × whether the
// retired variable is set. The signature takes no token value, so no row can
// hand the resolver an inline token: the retired variable can only change the
// description, never the source (TC-539-03).
func TestResolveTokenSource(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env.token")
	defFile := filepath.Join(dir, "default.token")
	for path, tok := range map[string]string{envFile: "from-env-file\n", defFile: "from-default\n"} {
		if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roles := []proto.NodeRole{proto.RoleCompute, proto.RoleFirewall, proto.RoleControlPlane}
	type row struct {
		name      string
		file      string
		legacySet bool
		role      proto.NodeRole
		// want is the token the source yields; "" with wantNone.
		want     string
		wantNone bool
		// wantContain are substrings the description must carry.
		wantContain []string
		// wantRetired: the description must (true) or must not (false)
		// mention the retired variable.
		wantRetired bool
	}
	var cases []row
	for _, r := range roles {
		// TC-539-01: the file is the source on every role.
		cases = append(cases, row{"TC-539-01 file on " + string(r), envFile, false, r,
			"from-env-file", false, []string{EnvJoinTokenFile, envFile}, false})
		// TC-539-02: the file plus the retired variable: the file is used,
		// and the description says the variable is not read.
		cases = append(cases, row{"TC-539-02 file and the retired variable on " + string(r), envFile, true, r,
			"from-env-file", false, []string{EnvJoinTokenFile, envFile, "not read"}, true})
	}
	for _, r := range []proto.NodeRole{proto.RoleCompute, proto.RoleFirewall} {
		// TC-539-03: the retired variable alone grants nothing.
		cases = append(cases, row{"TC-539-03 the retired variable alone on " + string(r), "", true, r,
			"", true, []string{EnvJoinTokenFile, "no longer read"}, true})
		// TC-539-05: neither: no token, and no word of the retired variable.
		cases = append(cases, row{"TC-539-05 neither on " + string(r), "", false, r,
			"", true, []string{EnvJoinTokenFile}, false})
	}
	// TC-539-04: a controlplane with the retired variable alone uses its
	// default file, never an env value.
	cases = append(cases, row{"TC-539-04 the retired variable alone on a controlplane", "", true, proto.RoleControlPlane,
		"from-default", false, []string{"controlplane default", "not read"}, true})
	// TC-539-05: a controlplane with neither uses its default file.
	cases = append(cases, row{"TC-539-05 neither on a controlplane", "", false, proto.RoleControlPlane,
		"from-default", false, []string{"controlplane default"}, false})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, from, none := ResolveTokenSource(tc.file, tc.legacySet, tc.role, defFile)
			if none != tc.wantNone {
				t.Errorf("none = %v, want %v", none, tc.wantNone)
			}
			got, err := src()
			if err != nil {
				t.Fatalf("source: %v", err)
			}
			if got != tc.want {
				t.Errorf("token = %q, want %q", got, tc.want)
			}
			for _, sub := range tc.wantContain {
				if !strings.Contains(from, sub) {
					t.Errorf("description %q does not mention %q", from, sub)
				}
			}
			if got := mentionsRetiredVariable(from); got != tc.wantRetired {
				t.Errorf("description %q mentions %s = %v, want %v", from, EnvJoinToken, got, tc.wantRetired)
			}
			if strings.Contains(from, EnvJoinToken+"=") {
				t.Errorf("description %q carries an assignment of %s", from, EnvJoinToken)
			}
			for _, secret := range []string{"from-env-file", "from-default"} {
				if strings.Contains(from, secret) {
					t.Errorf("description %q contains the token %q", from, secret)
				}
			}
		})
	}
}

// TC-539-06: a named token file decides every attempt, and the retired
// variable being set changes nothing: the file is re-read each time, and a
// file that is missing or empty is an error for that attempt with no fallback.
// Falling back would make a token that has been rotated or revoked on disk
// keep working for the life of the process, which is the whole reason the file
// exists.
func TestResolveTokenSource_FileIsRereadNeverFallenBackFrom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "join.token")
	src, from, none := ResolveTokenSource(path, true, proto.RoleCompute, filepath.Join(dir, "unused.token"))
	if none {
		t.Fatal("none = true for a named file, want false")
	}
	if !strings.Contains(from, EnvJoinTokenFile) || !strings.Contains(from, "not read") {
		t.Fatalf("description %q should name the file source and say the retired variable is not read", from)
	}

	// The file is not there yet: no token for this attempt.
	if got, err := src(); err == nil {
		t.Fatalf("a missing token file returned %q, want an error", got)
	}

	// It appears, and the very next attempt uses it — no restart.
	if err := os.WriteFile(path, []byte("from-the-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err != nil || got != "from-the-file" {
		t.Fatalf("source = (%q, %v), want from-the-file", got, err)
	}

	// It is rewritten (a re-mint, an identity restore): the next attempt sees
	// the new value.
	if err := os.WriteFile(path, []byte("re-minted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err != nil || got != "re-minted" {
		t.Fatalf("source after the re-mint = (%q, %v), want re-minted", got, err)
	}

	// It is emptied: an error again, with nothing to fall back to.
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err == nil {
		t.Fatalf("an empty token file returned %q, want an error", got)
	}
}

func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.token")
	src := TokenFile(path)

	if _, err := src(); err == nil || !strings.Contains(err.Error(), "does not exist yet") {
		t.Fatalf("missing file = %v, want a does-not-exist error", err)
	}
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := src(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("blank file = %v, want an empty error", err)
	}
	if err := os.WriteFile(path, []byte("tok-A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err != nil || got != "tok-A" {
		t.Fatalf("source = (%q, %v), want tok-A", got, err)
	}
	// Read again on every call: a re-minted file is seen at once.
	if err := os.WriteFile(path, []byte("tok-B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err != nil || got != "tok-B" {
		t.Fatalf("source after the rewrite = (%q, %v), want tok-B", got, err)
	}
	if _, err := TokenFile(dir)(); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("a directory as the token file = %v, want a cannot-be-read error", err)
	}
}

// busEvent is a non-blocking "it happened" signal from a nats callback.
func busEvent(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func waitBusEvent(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not happen within 10s", what)
	}
}

// The Client asks its token source on EVERY connection attempt:
//
//  1. the token file does not exist yet — the attempt presents no token and
//     is refused, and nothing about the refusal is permanent;
//  2. the file appears — the next attempt, with no restart, is admitted;
//  3. the server comes back demanding a different token (a controlplane that
//     re-minted its agent's token at start) and the file is rewritten — the
//     SAME connection reconnects with the new token, subscriptions intact.
func TestClient_ReadsTheTokenFileOnEveryConnect(t *testing.T) {
	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	path := filepath.Join(t.TempDir(), "agent.token")

	connected := make(chan struct{}, 1)
	c := mustNew(t, Config{
		URL: natsURL(t, s1), NodeID: testNode, Pin: StaticPin(testPin(t)), Token: TokenFile(path),
		OnConn: func(nc *nats.Conn) error {
			_, err := nc.Subscribe(testSubj, func(m *nats.Msg) { _ = m.Respond([]byte("pong")) })
			return err
		},
		OnConnected:   func(*nats.Conn) { busEvent(connected) },
		ReconnectWait: 50 * time.Millisecond,
	})
	t.Cleanup(c.Close)

	// 1.
	if err := c.Dial(); err == nil {
		t.Fatal("Dial succeeded with no token file")
	} else if !strings.Contains(strings.ToLower(err.Error()), "authorization") {
		t.Fatalf("Dial with no token file = %v, want an authorization violation", err)
	}

	// 2.
	if err := os.WriteFile(path, []byte("tok-A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Dial(); err != nil {
		t.Fatalf("Dial once the token file exists: %v", err)
	}
	waitBusEvent(t, connected, "the first connection")
	first := c.Conn()
	ping(t, c, s1, "tok-A")

	// 3.
	stopServer(s1)
	s2 := startBus(t, port, testNode, "tok-B")
	if err := os.WriteFile(path, []byte("tok-B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitBusEvent(t, connected, "the reconnect with the re-minted token")
	if c.Conn() != first || !first.IsConnected() {
		t.Fatalf("recovery replaced the conn or left it down (redials=%d, status %v)", c.Redials(), first.Status())
	}
	ping(t, c, s2, "tok-B")
}

// The static token source is presented unchanged on every attempt, as
// before token sources existed.
func TestClient_StaticTokenIsPresented(t *testing.T) {
	s := startBus(t, -1, testNode, "tok-A")
	c := mustNew(t, Config{URL: natsURL(t, s), NodeID: testNode, Pin: StaticPin(testPin(t)), Token: StaticToken("tok-A")})
	t.Cleanup(c.Close)
	if err := c.Dial(); err != nil {
		t.Fatalf("Dial with the static token: %v", err)
	}
	wrong := mustNew(t, Config{URL: natsURL(t, s), NodeID: testNode, Pin: StaticPin(testPin(t)), Token: StaticToken("tok-B")})
	t.Cleanup(wrong.Close)
	if err := wrong.Dial(); err == nil {
		t.Fatal("Dial with the wrong static token succeeded")
	}
}
