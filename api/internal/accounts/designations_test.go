package accounts

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
)

func openDesignations(t *testing.T) (*Designations, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rasputin.db")
	d, err := OpenDesignations(t.Context(), path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, path
}

// TC-990-33: the model service. Designate upserts and keeps the higher
// role; DesignateTx in a transaction that rolls back leaves no row; Get on
// an absent account reports absent; List returns every row; Clear removes
// one; an unreadable table is an error from each method.
func TestDesignations_TC990_33(t *testing.T) {
	d, _ := openDesignations(t)
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(d.Designate(ctx, Designation{Sub: "a", ConsoleRole: "viewer", AppRole: AppAdmin, Reason: ReasonPrivileged}))
	must(d.Designate(ctx, Designation{Sub: "a", ConsoleRole: "admin", AppRole: AppUser, Reason: ReasonRepair}))
	got, ok, err := d.Get(ctx, "a")
	if err != nil || !ok || got.ConsoleRole != "admin" || got.AppRole != AppAdmin || got.Reason != ReasonRepair {
		t.Errorf("after the upsert: %+v %v %v, want admin and app admin kept, reason repair", got, ok, err)
	}
	// A designation that raises nothing keeps the reason it had.
	must(d.Designate(ctx, Designation{Sub: "a", ConsoleRole: "viewer", Reason: ReasonMoved}))
	if got, _, _ := d.Get(ctx, "a"); got.Reason != ReasonRepair || got.ConsoleRole != "admin" {
		t.Errorf("a lower designation changed the row: %+v", got)
	}

	tx, err := d.db.BeginTx(ctx, nil)
	must(err)
	must(d.DesignateTx(ctx, tx, Designation{Sub: "rolled", ConsoleRole: "admin", Reason: ReasonFirstAdmin}))
	must(tx.Rollback())
	if _, ok, err := d.Get(ctx, "rolled"); ok || err != nil {
		t.Errorf("a rolled-back designation left a row: %v %v", ok, err)
	}
	tx, err = d.db.BeginTx(ctx, nil)
	must(err)
	must(d.DesignateFirstAdmin(ctx, tx, "first"))
	must(tx.Commit())
	if got, ok, _ := d.Get(ctx, "first"); !ok || got.ConsoleRole != "admin" || got.AppRole != AppAdmin || got.Reason != ReasonFirstAdmin {
		t.Errorf("the first-run designation: %+v", got)
	}
	if err := d.DesignateTx(ctx, nil, Designation{Sub: "x", ConsoleRole: "admin", Reason: ReasonPrivileged}); err == nil {
		t.Error("DesignateTx with no transaction succeeded")
	}

	if _, ok, err := d.Get(ctx, "absent"); ok || err != nil {
		t.Errorf("an absent account: %v %v", ok, err)
	}
	all, err := d.List(ctx)
	if err != nil || len(all) != 2 || all[0].Sub != "a" || all[1].Sub != "first" {
		t.Errorf("List = %+v, %v", all, err)
	}
	must(d.Clear(ctx, "a"))
	if all, _ := d.List(ctx); len(all) != 1 || all[0].Sub != "first" {
		t.Errorf("after Clear: %+v", all)
	}
	if err := d.Clear(ctx, ""); err == nil {
		t.Error("Clear with no account succeeded")
	}

	for name, x := range map[string]Designation{
		"no account":     {ConsoleRole: "admin", Reason: ReasonPrivileged},
		"no role":        {Sub: "a", Reason: ReasonPrivileged},
		"unknown role":   {Sub: "a", ConsoleRole: "owner", Reason: ReasonPrivileged},
		"unknown app":    {Sub: "a", AppRole: "root", Reason: ReasonPrivileged},
		"unknown reason": {Sub: "a", ConsoleRole: "admin", Reason: "because"},
	} {
		if err := d.Designate(ctx, x); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, err := d.db.Exec(`DROP TABLE designations`); err != nil {
		t.Fatal(err)
	}
	if err := d.Designate(ctx, Designation{Sub: "b", ConsoleRole: "admin", Reason: ReasonPrivileged}); err == nil {
		t.Error("Designate on an unreadable table succeeded")
	}
	if _, _, err := d.Get(ctx, "first"); err == nil {
		t.Error("Get on an unreadable table succeeded")
	}
	if _, err := d.List(ctx); err == nil {
		t.Error("List on an unreadable table succeeded")
	}
	if err := d.Clear(ctx, "first"); err == nil {
		t.Error("Clear on an unreadable table succeeded")
	}
}

// TC-990-31: a rasputin.db the previous release made has no designations
// table; opening Designations creates it.
func TestOpenDesignations_TC990_31_Upgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rasputin.db")
	prev, err := dbutil.Open(t.Context(), path, `CREATE TABLE IF NOT EXISTS users (id BLOB PRIMARY KEY)`, "previous")
	if err != nil {
		t.Fatal(err)
	}
	_ = prev.Close()
	d, err := OpenDesignations(t.Context(), path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'designations'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("designations after the upgrade: %d, %v", n, err)
	}
	if _, err := OpenDesignations(t.Context(), path, nil); err == nil {
		t.Error("OpenDesignations with no clock succeeded")
	}
}
