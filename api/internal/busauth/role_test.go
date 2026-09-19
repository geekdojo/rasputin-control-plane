package busauth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	_ "modernc.org/sqlite"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
)

// legacyRow is a bus_tokens row as a build before role binding wrote it.
type legacyRow struct {
	label     string
	nodeID    string
	selfAgent int
	revoked   bool
}

// openLegacyStore creates a database with the bus_tokens table exactly as a
// build before role binding created it (no role column), inserts rows, and then
// opens it with OpenStore, which is the upgrade under test. It returns the
// store and each row's plaintext token, in order.
func openLegacyStore(t *testing.T, rows []legacyRow) (*Store, []string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
        CREATE TABLE bus_tokens (
            token_hash   TEXT PRIMARY KEY,
            label        TEXT NOT NULL DEFAULT '',
            created_at   INTEGER NOT NULL,
            last_used_at INTEGER,
            revoked_at   INTEGER,
            node_id      TEXT,
            self_agent   INTEGER NOT NULL DEFAULT 0
        )`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	plaintexts := make([]string, len(rows))
	for i, r := range rows {
		pt, id, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		plaintexts[i] = pt
		var revoked any
		if r.revoked {
			revoked = ms(time.Now().UTC())
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO bus_tokens (token_hash, label, created_at, node_id, self_agent, revoked_at) VALUES (?, ?, ?, ?, ?, ?)`,
			id, r.label, ms(time.Now().UTC()), r.nodeID, r.selfAgent, revoked); err != nil {
			t.Fatalf("insert legacy row: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore on a legacy database: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, plaintexts
}

func roleOf(t *testing.T, s *Store, plaintext string) sql.NullString {
	t.Helper()
	var role sql.NullString
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT role FROM bus_tokens WHERE token_hash = ?`, HashToken(plaintext)).Scan(&role); err != nil {
		t.Fatalf("read role: %v", err)
	}
	return role
}

// The upgrade: a database from before role binding gets the column, and every
// row that says what it is gets its role — the self_agent row as the
// controlplane whatever its label reads, every row whose label is a role as
// that role. A row that says nothing keeps no role and is refused at the bus.
func TestOpenStore_BackfillsRoleFromLabelAndSelfAgent(t *testing.T) {
	ctx := context.Background()
	s, pt := openLegacyStore(t, []legacyRow{
		{label: "compute", nodeID: "c1"},
		{label: "firewall", nodeID: "fw1"},
		{label: "storage", nodeID: "s1"},
		{label: AgentTokenLabel, nodeID: "cp-1", selfAgent: 1},
		{label: "laptop agent", nodeID: "dev1"},
		{label: "", nodeID: "dev2"},
		{label: "bench throwaway", nodeID: "gone", revoked: true},
		{label: "Compute", nodeID: "c2"}, // a label is a role only when it is one exactly
	})

	want := []sql.NullString{
		{String: "compute", Valid: true},
		{String: "firewall", Valid: true},
		{String: "storage", Valid: true},
		{String: "controlplane", Valid: true},
		{}, {}, {}, {},
	}
	for i, w := range want {
		if got := roleOf(t, s, pt[i]); got != w {
			t.Errorf("row %d: role = %+v, want %+v", i, got, w)
		}
	}

	// The backfilled rows authenticate; the role-less ones do not.
	for i, node := range []string{"c1", "fw1", "s1", "cp-1"} {
		if ok, err := s.Validate(ctx, pt[i], node); err != nil || !ok {
			t.Errorf("Validate(backfilled %s) = (%v, %v), want (true, nil)", node, ok, err)
		}
	}
	for i, node := range map[int]string{4: "dev1", 5: "dev2", 7: "c2"} {
		if ok, err := s.Validate(ctx, pt[i], node); err != nil || ok {
			t.Errorf("Validate(role-less %s) = (%v, %v), want (false, nil)", node, ok, err)
		}
	}

	// The operator's view: three live role-less tokens (the revoked one does
	// not count), listed with no role.
	if n, err := s.CountActiveRoleless(ctx); err != nil || n != 3 {
		t.Errorf("CountActiveRoleless = (%d, %v), want (3, nil)", n, err)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	byNode := map[string]proto.NodeRole{}
	for _, tk := range list {
		byNode[*tk.NodeID] = tk.Role
	}
	for node, role := range map[string]proto.NodeRole{"c1": "compute", "fw1": "firewall", "s1": "storage", "cp-1": "controlplane", "dev1": "", "dev2": "", "c2": ""} {
		if byNode[node] != role {
			t.Errorf("List: %s role = %q, want %q", node, byNode[node], role)
		}
	}
}

// The backfill runs on every open, so a role-less row that comes back — an
// identity archive taken before role binding, restored — is filled again, and
// a row already carrying a role is never rewritten from its label.
func TestOpenStore_BackfillIsIdempotentAndRerunsOnEveryOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bus.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	minted, _, err := s.MintBound(ctx, "storage", "n1", proto.RoleCompute)
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	// A restored row with no role, as an older archive would bring back.
	pt, id, _ := GenerateToken()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, 'firewall', ?, 'fw1')`,
		id, ms(time.Now().UTC())); err != nil {
		t.Fatalf("insert: %v", err)
	}
	_ = s.Close()

	for range 2 {
		s, err = OpenStore(ctx, path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		if got := roleOf(t, s, pt); got.String != "firewall" {
			t.Errorf("restored row's role = %+v, want firewall", got)
		}
		if got := roleOf(t, s, minted); got.String != "compute" {
			t.Errorf("minted row's role = %+v, want compute (the label must not overwrite it)", got)
		}
		_ = s.Close()
	}
}

func TestMintBound_RequiresAValidRole(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	for _, role := range []proto.NodeRole{"", "nonsense", "Compute"} {
		pt, id, err := s.MintBound(ctx, "compute", "node-a", role)
		if !errors.Is(err, ErrNoRole) || pt != "" || id != "" {
			t.Errorf("MintBound(role %q) = (%q, %q, %v), want ErrNoRole and nothing", role, pt, id, err)
		}
	}
	if list, _ := s.List(ctx); len(list) != 0 {
		t.Fatalf("refused mints stored %d rows", len(list))
	}
	for _, role := range proto.AllRoles {
		pt, _, err := s.MintBound(ctx, "t", "node-"+string(role), role)
		if err != nil {
			t.Fatalf("MintBound(%s): %v", role, err)
		}
		if got := roleOf(t, s, pt); got.String != string(role) {
			t.Errorf("minted role = %+v, want %s", got, role)
		}
	}
}

func TestResolveRole(t *testing.T) {
	for _, tc := range []struct {
		role  proto.NodeRole
		label string
		want  proto.NodeRole
		err   bool
	}{
		{role: "compute", label: "anything", want: "compute"},
		{role: "", label: "firewall", want: "firewall"},
		{role: "", label: "laptop agent", err: true},
		{role: "", label: "", err: true},
		{role: "bogus", label: "compute", err: true}, // an explicit role is never replaced by the label
		{role: "firewall", label: "compute", want: "firewall"},
	} {
		got, err := ResolveRole(tc.role, tc.label)
		if tc.err {
			if !errors.Is(err, ErrNoRole) {
				t.Errorf("ResolveRole(%q, %q) = (%q, %v), want ErrNoRole", tc.role, tc.label, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ResolveRole(%q, %q) = (%q, %v), want %q", tc.role, tc.label, got, err, tc.want)
		}
	}
}

// A preseed entry carries its role, or — in a manifest from before the field —
// the role as its label. An entry whose role cannot be resolved fails the whole
// load with nothing stored, the #423 treatment of a hand-edited manifest.
func TestPreloadHashes_Role(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	ptA, hA, _ := GenerateToken()
	ptB, hB, _ := GenerateToken()
	n, err := s.PreloadHashes(ctx, []PreseedToken{
		{Hash: hA, NodeID: "a", Label: "compute", Role: "firewall"},
		{Hash: hB, NodeID: "b", Label: "storage"}, // an older manifest
	})
	if err != nil || n != 2 {
		t.Fatalf("PreloadHashes = (%d, %v), want (2, nil)", n, err)
	}
	if got := roleOf(t, s, ptA); got.String != "firewall" {
		t.Errorf("entry with role: %+v, want firewall", got)
	}
	if got := roleOf(t, s, ptB); got.String != "storage" {
		t.Errorf("entry with the role as its label: %+v, want storage", got)
	}

	for _, bad := range []PreseedToken{
		{Label: "hand edited", Role: ""},
		{Label: "compute", Role: "bogus"},
	} {
		fresh := newTokenStore(t)
		_, hOK, _ := GenerateToken()
		_, hBad, _ := GenerateToken()
		bad.Hash, bad.NodeID = hBad, "bad"
		n, err := fresh.PreloadHashes(ctx, []PreseedToken{{Hash: hOK, NodeID: "ok", Label: "compute"}, bad})
		if !errors.Is(err, ErrNoRole) || n != 0 {
			t.Errorf("PreloadHashes with %+v = (%d, %v), want (0, ErrNoRole)", bad, n, err)
		}
		if list, _ := fresh.List(ctx); len(list) != 0 {
			t.Errorf("a refused preload stored %d rows, want none", len(list))
		}
	}
}

// The controlplane's own agent: a token the api minted is a controlplane
// token, and one adopted from the file becomes one.
func TestEnsureAgentToken_Role(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path := agentTokenPath(t)
	if _, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatalf("EnsureAgentToken: %v", err)
	}
	if got := roleOf(t, s, readTokenFile(t, path)); got.String != "controlplane" {
		t.Errorf("minted agent token role = %+v, want controlplane", got)
	}
}

// An upgrade from a build that minted the agent token before the self_agent
// marker existed: the row names no role (its label is display text, not a
// role), so the token no longer validates and the api re-mints at start —
// the controlplane's agent keeps a working token with no operator step.
func TestEnsureAgentToken_ReMintsARolelessPreMarkerToken(t *testing.T) {
	ctx := context.Background()
	s, pt := openLegacyStore(t, []legacyRow{{label: AgentTokenLabel, nodeID: "cp-1"}})
	path := agentTokenPath(t)
	if err := atrest.WriteSecretFile(path, []byte(pt[0]+"\n")); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	reason, err := s.EnsureAgentToken(ctx, path, "cp-1")
	if err != nil || reason == "" {
		t.Fatalf("EnsureAgentToken = (%q, %v), want a re-mint", reason, err)
	}
	fresh := readTokenFile(t, path)
	if fresh == pt[0] {
		t.Fatal("the role-less token was kept")
	}
	if ok, err := s.Validate(ctx, fresh, "cp-1"); err != nil || !ok {
		t.Errorf("Validate(re-minted) = (%v, %v), want (true, nil)", ok, err)
	}
	if got := roleOf(t, s, fresh); got.String != "controlplane" {
		t.Errorf("re-minted role = %+v, want controlplane", got)
	}
	if live := liveTokensFor(t, s, "cp-1"); len(live) != 1 {
		t.Errorf("live tokens for cp-1 = %d, want 1 (the role-less one revoked)", len(live))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("token file: %v", err)
	}
}

// On the real bus: a legacy token whose row names no role is refused at
// connect, and a legacy token whose label named its role was backfilled and
// connects and works.
func TestBus_RolelessTokenRefused_BackfilledAdmitted(t *testing.T) {
	eb := startEnforcedBus(t, "127.0.0.1")
	ctx := context.Background()

	pt := make([]string, 2)
	for i, label := range []string{"laptop agent", "compute"} {
		p, id, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		pt[i] = p
		if _, err := eb.tokens.db.ExecContext(ctx,
			`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, ?, ?, ?)`,
			id, label, ms(time.Now().UTC()), []string{"legacy", "backfilled"}[i]); err != nil {
			t.Fatalf("insert legacy row: %v", err)
		}
	}
	// The backfill is what OpenStore runs on every start.
	if err := backfillRoles(ctx, eb.tokens.db); err != nil {
		t.Fatalf("backfillRoles: %v", err)
	}

	if nc, err := connect(eb.url, "legacy", pt[0]); err == nil {
		nc.Close()
		t.Fatal("a role-less token connected; want it refused")
	} else {
		t.Logf("role-less token refused: %v", err)
	}
	nc, err := connect(eb.url, "backfilled", pt[1])
	if err != nil {
		t.Fatalf("a token backfilled from its label was refused: %v", err)
	}
	defer nc.Close()
	assertNodeRoundTrip(t, eb.srv.Conn(), nc, "backfilled")
}
