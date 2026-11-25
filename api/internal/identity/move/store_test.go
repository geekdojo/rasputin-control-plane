package move

import (
	"testing"
	"time"
)

// TC-1005-23 (the facts): PasswordSet is false, RecordPasswordSet makes it
// true and is idempotent; Record of a repair re-run deletes the recorded
// accounts' facts in its own transaction and leaves the others; Account
// reads one move row by handle; every read error is returned.
func TestStore_TC1005_23_PasswordFacts(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	if set, err := w.store.PasswordSet(ctx, "acct-a"); set || err != nil {
		t.Fatalf("PasswordSet before: %v %v", set, err)
	}
	for range 2 {
		if err := w.store.RecordPasswordSet(ctx, "acct-a"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.store.RecordPasswordSet(ctx, "acct-b"); err != nil {
		t.Fatal(err)
	}
	if set, err := w.store.PasswordSet(ctx, "acct-a"); !set || err != nil {
		t.Fatalf("PasswordSet after: %v %v", set, err)
	}
	if err := w.store.RecordPasswordSet(ctx, ""); err == nil {
		t.Error("a fact with no account")
	}
	h := []byte("0123456789abcdef")
	row := Row{Handle: h, AccountID: "acct-a", OldName: "b", NewName: "b-1", MovedAt: time.UnixMilli(1000).UTC()}
	if err := w.store.Record(ctx, []Row{row}); err != nil {
		t.Fatal(err)
	}
	if set, _ := w.store.PasswordSet(ctx, "acct-a"); set {
		t.Error("Record kept the recorded account's fact")
	}
	if set, _ := w.store.PasswordSet(ctx, "acct-b"); !set {
		t.Error("Record deleted another account's fact")
	}
	got, ok, err := w.store.Account(ctx, h)
	if err != nil || !ok || got.AccountID != "acct-a" || got.OldName != "b" || got.NewName != "b-1" || !got.MovedAt.Equal(row.MovedAt) {
		t.Errorf("Account: %+v %v %v", got, ok, err)
	}
	if _, ok, err := w.store.Account(ctx, []byte("no-such-handle--")); ok || err != nil {
		t.Errorf("Account of no row: %v %v", ok, err)
	}
	if _, err := w.store.db.ExecContext(ctx, `DROP TABLE identity_bridge`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.store.PasswordSet(ctx, "acct-a"); err == nil {
		t.Error("PasswordSet read error not returned")
	}
	if err := w.store.RecordPasswordSet(ctx, "acct-a"); err == nil {
		t.Error("RecordPasswordSet write error not returned")
	}
	if err := w.store.Record(ctx, []Row{row}); err == nil {
		t.Error("Record did not fail with its fact delete")
	}
	if _, err := w.store.db.ExecContext(ctx, `DROP TABLE identity_move`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.store.Account(ctx, h); err == nil {
		t.Error("Account read error not returned")
	}
}
