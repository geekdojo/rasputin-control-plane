package move

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// failingDes is a designation read that fails.
type failingDes struct{}

func (failingDes) Get(context.Context, string) (accounts.Designation, bool, error) {
	return accounts.Designation{}, false, errDown
}

// fixedPending answers the move's pending state.
type fixedPending struct {
	p   bool
	err error
}

func (p fixedPending) Pending(context.Context) (bool, error) { return p.p, p.err }

// accountsWorld is Accounts over the world's real stores and a real
// Designations on the same rasputin.db.
func accountsWorld(t *testing.T) (*world, *accounts.Designations) {
	t.Helper()
	w := newWorld(t)
	des, err := accounts.OpenDesignations(t.Context(), w.dbPath, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = des.Close() })
	return w, des
}

// moveOne records a move row for an old user with a passkey.
func moveOne(t *testing.T, w *world, h byte, oldName, newName string) ([]byte, string) {
	t.Helper()
	handle := w.addOld(t, h, oldName, int64(h))
	if err := w.old.CreateCredential(t.Context(), &auth.Credential{ID: []byte{h, 'k'}, UserID: handle, PublicKey: []byte{1},
		CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	sub := auth.MovedAccountID(handle)
	if err := w.store.Record(t.Context(), []Row{{Handle: handle, AccountID: sub, OldName: oldName, NewName: newName, MovedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	return handle, sub
}

// The role rule (F-1005-06, C25): the moved administrator designation is
// admin; a waiting one carries no role; no designation is not Designated;
// no move row is no account; NeedsPassword follows the fact.
func TestAccounts_Account(t *testing.T) {
	w, des := accountsWorld(t)
	ctx := t.Context()
	h, sub := moveOne(t, w, 1, "b", "b-1")
	a, err := NewAccounts(w.store, w.state(t), w.old, des)
	if err != nil {
		t.Fatal(err)
	}
	m, ok, err := a.Account(ctx, h)
	if err != nil || !ok || m.Designated || len(m.Roles) != 0 || m.Sub != sub || m.Name != "b-1" || m.OldName != "b" || !m.NeedsPassword {
		t.Errorf("no designation: %+v %v %v", m, ok, err)
	}
	if err := des.DesignateMoved(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := a.Account(ctx, h); !m.Designated || !slices.Equal(m.Roles, []string{"admin"}) {
		t.Errorf("moved: %+v", m)
	}
	if err := des.Wait(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := a.Account(ctx, h); !m.Designated || len(m.Roles) != 0 || m.Roles == nil {
		t.Errorf("waiting: %+v", m)
	}
	if err := w.store.RecordPasswordSet(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := a.Account(ctx, h); m.NeedsPassword {
		t.Error("NeedsPassword with the fact recorded")
	}
	if _, ok, err := a.Account(ctx, []byte("0000000000000009")); ok || err != nil {
		t.Errorf("no move row: %v %v", ok, err)
	}
	bad, _ := NewAccounts(w.store, w.state(t), w.old, failingDes{})
	if _, _, err := bad.Account(ctx, h); !errors.Is(err, errDown) {
		t.Errorf("a designation read error: %v", err)
	}
	if _, err := NewAccounts(nil, w.state(t), w.old, des); err == nil {
		t.Error("NewAccounts accepted a nil collaborator")
	}
}

// TC-1005-23 (the offer, F-1005-04): Offered is true while the move is
// pending; true while a move row lacks its fact and its old user holds a
// passkey; false once every row has its fact, or its passkeys are gone
// (C15); a read error is returned.
func TestAccounts_TC1005_23_Offered(t *testing.T) {
	w, des := accountsWorld(t)
	ctx := t.Context()
	offered := func(a *Accounts) bool {
		t.Helper()
		ok, err := a.Offered(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	empty, _ := NewAccounts(w.store, w.state(t), w.old, des)
	if offered(empty) {
		t.Error("offered with no old users")
	}
	w.addOld(t, 9, "early", 9)
	if !offered(empty) {
		t.Error("not offered while the move is pending")
	}
	_, subA := moveOne(t, w, 1, "a", "a")
	_, subB := moveOne(t, w, 2, "b", "b-1")
	a, _ := NewAccounts(w.store, fixedPending{}, w.old, des)
	if !offered(a) {
		t.Error("not offered with two accounts lacking a password")
	}
	if err := w.store.RecordPasswordSet(ctx, subA); err != nil {
		t.Fatal(err)
	}
	if !offered(a) {
		t.Error("not offered with one account lacking a password")
	}
	if _, _, err := w.old.RemoveMovedRows(ctx, subB); err != nil {
		t.Fatal(err)
	}
	if offered(a) {
		t.Error("offered for an account whose passkeys are gone")
	}
	if err := w.store.RecordPasswordSet(ctx, subB); err != nil {
		t.Fatal(err)
	}
	if offered(a) {
		t.Error("offered with every fact recorded")
	}
	failing, _ := NewAccounts(w.store, fixedPending{err: errDown}, w.old, des)
	if _, err := failing.Offered(ctx); !errors.Is(err, errDown) {
		t.Errorf("a pending read error: %v", err)
	}
	if _, err := w.store.db.ExecContext(ctx, `DELETE FROM identity_bridge`); err != nil {
		t.Fatal(err)
	}
	_ = w.old.Close() // every old read now fails
	if _, err := a.Offered(ctx); err == nil {
		t.Error("an old user read error was not returned")
	}
	if _, err := w.store.db.ExecContext(ctx, `DROP TABLE identity_bridge`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Offered(ctx); err == nil {
		t.Error("a fact read error was not returned")
	}
	if _, err := w.store.db.ExecContext(ctx, `DROP TABLE identity_move`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Offered(ctx); err == nil {
		t.Error("a rows read error was not returned")
	}
}
