package accounts

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
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

// TC-994-17: a database holding #990's table (no network column) and one
// row upgrades on open, twice; the old row reads network ”; Designate,
// Choose and Withdraw work field by field; an unreadable table is an error
// from each method, and a step that needs it fails with its sentence and
// changes no role.
func TestDesignations_TC994_17_Upgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rasputin.db")
	old, err := dbutil.Open(t.Context(), path, `
CREATE TABLE designations (sub TEXT PRIMARY KEY, console_role TEXT NOT NULL, app_role TEXT NOT NULL,
    reason TEXT NOT NULL, created_at INTEGER NOT NULL);
INSERT INTO designations VALUES ('old', 'admin', 'admin', 'first_admin', 1);`, "old")
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	for range 2 {
		d, err := OpenDesignations(t.Context(), path, time.Now)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		_ = d.Close()
	}
	d, err := OpenDesignations(t.Context(), path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	var cols []string
	rows, err := d.db.QueryContext(t.Context(), `SELECT name FROM pragma_table_info('designations')`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		cols = append(cols, c)
	}
	_ = rows.Close()
	x, ok, err := d.Get(t.Context(), "old")
	if !slices.Contains(cols, "network") || err != nil || !ok || x.Network != "" || x.ConsoleRole != "admin" || x.Reason != ReasonFirstAdmin {
		t.Errorf("columns %v, old row %+v %v %v", cols, x, ok, err)
	}

	ctx := t.Context()
	if err := d.Choose(ctx, "c", LevelNetwork, "gear-admin"); err != nil {
		t.Fatal(err)
	}
	if err := d.Choose(ctx, "c", LevelConsole, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := d.Choose(ctx, "c", LevelConsole, "viewer"); err != nil {
		t.Fatal(err)
	}
	if x, _, _ := d.Get(ctx, "c"); x.ConsoleRole != "viewer" || x.Network != "gear-admin" || x.Reason != ReasonPrivileged {
		t.Errorf("after the choices: %+v", x)
	}
	if err := d.Designate(ctx, Designation{Sub: "c", ConsoleRole: "operator", Network: "gear-admin", Reason: ReasonReset}); err != nil {
		t.Fatal(err)
	}
	if x, _, _ := d.Get(ctx, "c"); x.ConsoleRole != "operator" || x.Reason != ReasonReset {
		t.Errorf("a re-designation keeps the higher: %+v", x)
	}
	for _, l := range []Level{LevelConsole, LevelNetwork} {
		if err := d.Withdraw(ctx, "c", l); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, _ := d.Get(ctx, "c"); ok {
		t.Error("an empty designation kept its row")
	}
	if err := d.Withdraw(ctx, "nobody", LevelApp); err != nil {
		t.Errorf("withdrawing from no designation: %v", err)
	}
	for _, bad := range []error{d.Choose(ctx, "c", LevelNetwork, "gear-root"), d.Choose(ctx, "c", "nowhere", "x"), d.Choose(ctx, "c", LevelApp, "")} {
		if bad == nil {
			t.Error("a bad choice was accepted")
		}
	}

	if _, err := d.db.ExecContext(ctx, `DROP TABLE designations`); err != nil {
		t.Fatal(err)
	}
	if err := d.Designate(ctx, Designation{Sub: "a", ConsoleRole: "admin", Reason: ReasonReset}); err == nil {
		t.Error("Designate on an unreadable table")
	}
	if err := d.Withdraw(ctx, "a", LevelApp); err == nil {
		t.Error("Withdraw on an unreadable table")
	}
	if _, _, err := d.Get(ctx, "a"); err == nil {
		t.Error("Get on an unreadable table")
	}
	if _, err := d.List(ctx); err == nil {
		t.Error("List on an unreadable table")
	}

	h := newChangeHarness(t)
	if _, err := h.designations.db.ExecContext(ctx, `DROP TABLE designations`); err != nil {
		t.Fatal(err)
	}
	r := h.run(t, adminSubmitter, KindSetRoles, RoleSpec{AccountID: target, Role: "operator"}, true, "")
	if r.job.Status != jobs.StatusFailed || r.job.Error != sentenceDesignation || len(h.log.only("add-console")) != 0 {
		t.Errorf("the step: %s %q, roles %v", r.job.Status, r.job.Error, h.log.only("add-console"))
	}
}
