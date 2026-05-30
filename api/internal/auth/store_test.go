package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// authFixture holds an open Store + Service rooted in t.TempDir. The Service
// is built with a synthetic Config so cookie behavior is exercised without a
// real RP.
type authFixture struct {
	ctx   context.Context
	dir   string
	store *Store
	svc   *Service
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(ctx, filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	svc, err := NewService(store, Config{
		RPDisplayName: "Rasputin Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000"},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return &authFixture{ctx: ctx, dir: dir, store: store, svc: svc}
}

// mintUser creates and persists a User with a synthetic 16-byte id. Returns
// the created user; the credentials slice is empty.
func (f *authFixture) mintUser(t *testing.T, name string) *User {
	t.Helper()
	u, err := makeUser(name, name+" Display")
	if err != nil {
		t.Fatalf("makeUser: %v", err)
	}
	if err := f.store.CreateUser(f.ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

// mintCredential attaches a synthetic credential (random id, dummy public
// key) to the given user.
func (f *authFixture) mintCredential(t *testing.T, u *User, id string) *Credential {
	t.Helper()
	c := &Credential{
		ID:              []byte(id),
		UserID:          u.ID,
		PublicKey:       []byte("fake-pubkey"),
		AttestationType: "none",
		Transports:      []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal},
		AAGUID:          []byte{0xde, 0xad, 0xbe, 0xef},
		SignCount:       1,
		CloneWarning:    false,
		BackupEligible:  true,
		BackupState:     true,
		Nickname:        id + "-key",
		CreatedAt:       time.Now().UTC(),
	}
	if err := f.store.CreateCredential(f.ctx, c); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	return c
}

// ============================================================================
// Store: users
// ============================================================================

func TestStore_CountUsers_Empty(t *testing.T) {
	f := newAuthFixture(t)
	n, err := f.store.CountUsers(f.ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0 users, got %d", n)
	}
}

func TestStore_CreateUserAndCount(t *testing.T) {
	f := newAuthFixture(t)
	f.mintUser(t, "alice")
	f.mintUser(t, "bob")
	n, err := f.store.CountUsers(f.ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 users, got %d", n)
	}
}

func TestStore_GetUserByName(t *testing.T) {
	f := newAuthFixture(t)
	alice := f.mintUser(t, "alice")
	got, err := f.store.GetUserByName(f.ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByName: %v", err)
	}
	if got == nil {
		t.Fatal("want alice, got nil")
	}
	if string(got.ID) != string(alice.ID) {
		t.Errorf("id mismatch: want %x got %x", alice.ID, got.ID)
	}
	if got.DisplayName != "alice Display" {
		t.Errorf("display name: got %q", got.DisplayName)
	}
}

func TestStore_GetUserByName_NotFound(t *testing.T) {
	f := newAuthFixture(t)
	got, err := f.store.GetUserByName(f.ctx, "nobody")
	if err != nil {
		t.Fatalf("GetUserByName: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_GetUserByID(t *testing.T) {
	f := newAuthFixture(t)
	alice := f.mintUser(t, "alice")
	got, err := f.store.GetUserByID(f.ctx, alice.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got == nil || got.Name != "alice" {
		t.Fatalf("want alice, got %+v", got)
	}
}

func TestStore_GetUserByID_LoadsCredentials(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	f.mintCredential(t, u, "credA")
	f.mintCredential(t, u, "credB")

	got, err := f.store.GetUserByID(f.ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	creds := got.WebAuthnCredentials()
	if len(creds) != 2 {
		t.Fatalf("want 2 credentials, got %d", len(creds))
	}
}

// NOTE: Store.ListUsers is not covered here. It calls listCredentialsForUser
// while iterating rows, which deadlocks under db.SetMaxOpenConns(1). That's
// a production bug (separate from this test suite), reported as a testability
// gap rather than worked around in tests.

func TestStore_UpdateLastLogin(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	ts := time.Now().UTC().Truncate(time.Millisecond)
	if err := f.store.UpdateLastLogin(f.ctx, u.ID, ts); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}
	got, err := f.store.GetUserByID(f.ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.LastLoginAt == nil {
		t.Fatal("LastLoginAt is nil")
	}
	if !got.LastLoginAt.Equal(ts) {
		t.Errorf("LastLoginAt: want %v got %v", ts, got.LastLoginAt)
	}
}

// ============================================================================
// Store: credentials
// ============================================================================

func TestStore_UpdateCredentialAfterLogin(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	cred := f.mintCredential(t, u, "credA")

	// Sign count climbs; BS flips.
	wac := webauthn.Credential{
		ID:        cred.ID,
		PublicKey: cred.PublicKey,
		Flags: webauthn.CredentialFlags{
			BackupEligible: true,
			BackupState:    false, // flipped
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       cred.AAGUID,
			SignCount:    99,
			CloneWarning: true,
		},
	}
	ts := time.Now().UTC().Truncate(time.Millisecond)
	if err := f.store.UpdateCredentialAfterLogin(f.ctx, &wac, ts); err != nil {
		t.Fatalf("UpdateCredentialAfterLogin: %v", err)
	}

	got, err := f.store.GetUserByID(f.ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	creds := got.WebAuthnCredentials()
	if len(creds) != 1 {
		t.Fatalf("want 1 cred, got %d", len(creds))
	}
	if creds[0].Authenticator.SignCount != 99 {
		t.Errorf("SignCount: want 99, got %d", creds[0].Authenticator.SignCount)
	}
	if !creds[0].Authenticator.CloneWarning {
		t.Error("CloneWarning: want true")
	}
	if creds[0].Flags.BackupState {
		t.Error("BackupState: want false (flipped)")
	}
}

func TestStore_UserHandleForCredential(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	cred := f.mintCredential(t, u, "credA")

	uid, err := f.store.UserHandleForCredential(f.ctx, cred.ID)
	if err != nil {
		t.Fatalf("UserHandleForCredential: %v", err)
	}
	if string(uid) != string(u.ID) {
		t.Errorf("user handle mismatch: want %x got %x", u.ID, uid)
	}
}

func TestStore_UserHandleForCredential_NotFound(t *testing.T) {
	f := newAuthFixture(t)
	uid, err := f.store.UserHandleForCredential(f.ctx, []byte("nope"))
	if err != nil {
		t.Fatalf("UserHandleForCredential: %v", err)
	}
	if uid != nil {
		t.Errorf("want nil, got %x", uid)
	}
}

// ============================================================================
// Store: sessions
// ============================================================================

func TestStore_CreateAndGetSession(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &Session{
		Token:        "tok-1",
		UserID:       u.ID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
		LastActiveAt: now,
	}
	if err := f.store.CreateSession(f.ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := f.store.GetSession(f.ctx, "tok-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got == nil {
		t.Fatal("session not found")
	}
	if !got.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Errorf("ExpiresAt: want %v got %v", sess.ExpiresAt, got.ExpiresAt)
	}
}

func TestStore_GetSession_NotFound(t *testing.T) {
	f := newAuthFixture(t)
	got, err := f.store.GetSession(f.ctx, "nope")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_TouchSession(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &Session{
		Token: "tok-touch", UserID: u.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now,
	}
	if err := f.store.CreateSession(f.ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	later := now.Add(30 * time.Minute)
	if err := f.store.TouchSession(f.ctx, "tok-touch", later); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, err := f.store.GetSession(f.ctx, "tok-touch")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !got.LastActiveAt.Equal(later) {
		t.Errorf("LastActiveAt: want %v got %v", later, got.LastActiveAt)
	}
}

func TestStore_DeleteSession(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &Session{
		Token: "tok-del", UserID: u.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now,
	}
	if err := f.store.CreateSession(f.ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := f.store.DeleteSession(f.ctx, "tok-del"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	got, _ := f.store.GetSession(f.ctx, "tok-del")
	if got != nil {
		t.Errorf("expected session gone, got %+v", got)
	}
}

func TestStore_DeleteExpiredSessions(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Live session.
	live := &Session{Token: "live", UserID: u.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now}
	if err := f.store.CreateSession(f.ctx, live); err != nil {
		t.Fatalf("CreateSession live: %v", err)
	}
	// Expired session.
	dead := &Session{Token: "dead", UserID: u.ID,
		CreatedAt:    now.Add(-2 * time.Hour),
		ExpiresAt:    now.Add(-time.Hour),
		LastActiveAt: now.Add(-time.Hour),
	}
	if err := f.store.CreateSession(f.ctx, dead); err != nil {
		t.Fatalf("CreateSession dead: %v", err)
	}

	if err := f.store.DeleteExpiredSessions(f.ctx, now); err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if got, _ := f.store.GetSession(f.ctx, "dead"); got != nil {
		t.Error("expired session was not deleted")
	}
	if got, _ := f.store.GetSession(f.ctx, "live"); got == nil {
		t.Error("live session got deleted")
	}
}

// ============================================================================
// Transport encoding round-trip
// ============================================================================

func TestEncodeDecodeTransports(t *testing.T) {
	in := []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC, protocol.Internal}
	enc := encodeTransports(in)
	got := decodeTransports(enc)
	if len(got) != len(in) {
		t.Fatalf("len mismatch: want %d got %d (raw=%s)", len(in), len(got), enc)
	}
	for i, v := range in {
		if got[i] != v {
			t.Errorf("idx %d: want %q got %q", i, v, got[i])
		}
	}
}

func TestEncodeTransports_Empty(t *testing.T) {
	if got := encodeTransports(nil); got != "[]" {
		t.Errorf("want %q, got %q", "[]", got)
	}
}

// ============================================================================
// boolToInt
// ============================================================================

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("boolToInt(true) != 1")
	}
	if boolToInt(false) != 0 {
		t.Error("boolToInt(false) != 0")
	}
}

// ============================================================================
// fromMs / ms
// ============================================================================

func TestMsRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	got := fromMs(ms(now))
	if !got.Equal(now) {
		t.Errorf("round-trip: want %v got %v", now, got)
	}
}
