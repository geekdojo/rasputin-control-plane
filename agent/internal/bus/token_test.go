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

func TestResolveTokenSource(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env.token")
	defFile := filepath.Join(dir, "default.token")
	for path, tok := range map[string]string{envFile: "from-env-file\n", defFile: "from-default\n"} {
		if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name            string
		token, file     string
		role            proto.NodeRole
		want            string
		wantFromContain string
		// wantKind is the proto.TokenSource* value the agent reports in its
		// registration metadata. It must name the source this call actually
		// returned: the deletion of the environment fallback waits on every
		// node reporting "file" (geekdojo/geekdojo-brain#536, §7 4.1), so a
		// node counted as migrated while still reading the variable would
		// stop joining when the fallback goes.
		wantKind string
	}{
		// The legacy inline token, still honoured for a new agent on an image
		// whose firstboot/init.d names no token file.
		{"compute with only a seeded token", "seeded", "", proto.RoleCompute, "seeded", EnvJoinToken, proto.TokenSourceEnv},
		{"firewall with only a seeded token", "seeded", "", proto.RoleFirewall, "seeded", EnvJoinToken, proto.TokenSourceEnv},
		{"the seeded token is used exactly as given", " seeded ", "", proto.RoleCompute, " seeded ", EnvJoinToken, proto.TokenSourceEnv},
		{"compute with neither", "", "", proto.RoleCompute, "", "none", proto.TokenSourceNone},
		// The canonical source: one 0600 file, on every role.
		{"a token file", "", envFile, proto.RoleCompute, "from-env-file", EnvJoinTokenFile, proto.TokenSourceFile},
		{"firewall with a token file", "", envFile, proto.RoleFirewall, "from-env-file", EnvJoinTokenFile, proto.TokenSourceFile},
		// Precedence: the FILE wins. Whatever wrote it wrote it after the
		// seed, and it is the only one of the two that can be re-read.
		{"both set: the file wins", "seeded", envFile, proto.RoleCompute, "from-env-file", EnvJoinTokenFile, proto.TokenSourceFile},
		{"both set: the file wins on a firewall too", "seeded", envFile, proto.RoleFirewall, "from-env-file", EnvJoinTokenFile, proto.TokenSourceFile},
		{"both set: the ignored variable is named", "seeded", envFile, proto.RoleCompute, "from-env-file", "ignored", proto.TokenSourceFile},
		// firstboot writes RASPUTIN_CP_JOIN_TOKEN_FILE for a new controlplane
		{"controlplane with the file named", "", envFile, proto.RoleControlPlane, "from-env-file", EnvJoinTokenFile, proto.TokenSourceFile},
		// an updated controlplane whose node.env predates the file
		{"controlplane with neither: the default file", "", "", proto.RoleControlPlane, "from-default", "controlplane default", proto.TokenSourceFile},
		{"controlplane with only a seeded token keeps it", "seeded", "", proto.RoleControlPlane, "seeded", EnvJoinToken, proto.TokenSourceEnv},
		{"both set: the file wins on a controlplane too", "seeded", envFile, proto.RoleControlPlane, "from-env-file", EnvJoinTokenFile, proto.TokenSourceFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, from, kind := ResolveTokenSource(tc.token, tc.file, tc.role, defFile)
			if kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", kind, tc.wantKind)
			}
			got, err := src()
			if err != nil {
				t.Fatalf("source: %v", err)
			}
			if got != tc.want {
				t.Errorf("token = %q, want %q", got, tc.want)
			}
			if !strings.Contains(from, tc.wantFromContain) {
				t.Errorf("description %q does not mention %q", from, tc.wantFromContain)
			}
			for _, secret := range []string{"seeded", "from-env-file", "from-default"} {
				if strings.Contains(from, secret) {
					t.Errorf("description %q contains the token %q", from, secret)
				}
			}
		})
	}
}

// A named token file decides the attempt even when the legacy variable is also
// set: it is re-read every time, and a file that is missing or empty is an
// error for that attempt rather than a silent fall-back to the seeded token.
// Falling back would make a token that has been rotated or revoked on disk
// keep working for the life of the process, which is the whole reason the file
// exists.
func TestResolveTokenSource_FileWinsAndIsRereadNotFallenBackFrom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "join.token")
	src, from, kind := ResolveTokenSource("seeded", path, proto.RoleCompute, filepath.Join(dir, "unused.token"))
	if kind != proto.TokenSourceFile {
		t.Fatalf("kind = %q, want %q — the file is the source, so that is what the node must report", kind, proto.TokenSourceFile)
	}
	if !strings.Contains(from, EnvJoinTokenFile) || !strings.Contains(from, "ignored") {
		t.Fatalf("description %q should name the file source and say the variable is ignored", from)
	}

	// The file is not there yet: no token for this attempt, and no fall-back
	// to the variable.
	if got, err := src(); err == nil {
		t.Fatalf("a missing token file returned %q, want an error rather than the seeded token", got)
	}

	// It appears, and the very next attempt uses it — no restart.
	if err := os.WriteFile(path, []byte("from-the-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err != nil || got != "from-the-file" {
		t.Fatalf("source = (%q, %v), want from-the-file", got, err)
	}

	// It is rewritten (a re-mint, an identity restore): the next attempt sees
	// the new value, still not the variable.
	if err := os.WriteFile(path, []byte("re-minted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err != nil || got != "re-minted" {
		t.Fatalf("source after the re-mint = (%q, %v), want re-minted", got, err)
	}

	// It is emptied: an error again, never "seeded".
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := src(); err == nil {
		t.Fatalf("an empty token file returned %q, want an error rather than the seeded token", got)
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
	s1 := startServer(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	path := filepath.Join(t.TempDir(), "agent.token")

	connected := make(chan struct{}, 1)
	c := New(s1.ClientURL(), testNode, "",
		func(nc *nats.Conn) error {
			_, err := nc.Subscribe(testSubj, func(m *nats.Msg) { _ = m.Respond([]byte("pong")) })
			return err
		},
		func(*nats.Conn) { busEvent(connected) },
	)
	c.reconnectWait = 50 * time.Millisecond
	c.SetTokenSource(TokenFile(path))
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
	s2 := startServer(t, port, testNode, "tok-B")
	if err := os.WriteFile(path, []byte("tok-B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitBusEvent(t, connected, "the reconnect with the re-minted token")
	if c.Conn() != first || !first.IsConnected() {
		t.Fatalf("recovery replaced the conn or left it down (redials=%d, status %v)", c.Redials(), first.Status())
	}
	ping(t, c, s2, "tok-B")
}

// The static token New is given is presented unchanged on every attempt, as
// before token sources existed.
func TestClient_StaticTokenIsPresented(t *testing.T) {
	s := startServer(t, -1, testNode, "tok-A")
	c := New(s.ClientURL(), testNode, "tok-A", nil, nil)
	t.Cleanup(c.Close)
	if err := c.Dial(); err != nil {
		t.Fatalf("Dial with the static token: %v", err)
	}
	wrong := New(s.ClientURL(), testNode, "tok-B", nil, nil)
	t.Cleanup(wrong.Close)
	if err := wrong.Dial(); err == nil {
		t.Fatal("Dial with the wrong static token succeeded")
	}
}
