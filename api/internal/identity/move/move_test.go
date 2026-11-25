package move

import (
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-1004-10: the import's request shape and the step order. One
// partialImport with ifResourceExists=SKIP; each user under
// MovedAccountID(handle), enabled, rasputin_app_role=user, the
// recovery-codes action, offline_access, and no credentials or email. The
// calls run: access facts, designations, import, read-back, rows.
func TestMove_TC1004_10_Shape(t *testing.T) {
	w := newWorld(t)
	h1 := w.addOld(t, 1, "Alice", 1)
	h2 := w.addOld(t, 2, "9bob", 2)
	prior, err := w.run(t, Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.imports) != 1 {
		t.Fatalf("%d partialImports, want 1", len(w.imports))
	}
	body := w.imports[0]
	if body.IfResourceExists != "SKIP" || len(body.Users) != 2 {
		t.Fatalf("body %+v", body)
	}
	raw, _ := json.Marshal(body)
	for _, banned := range []string{`"credentials"`, `"email"`} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("the import body carries %s: %s", banned, raw)
		}
	}
	wantIDs := map[string]string{auth.MovedAccountID(h1): "alice", auth.MovedAccountID(h2): "u9bob"}
	for _, u := range body.Users {
		if wantIDs[u.ID] != u.Username || !u.Enabled || !slices.Equal(u.Attributes[accounts.AttrAppRole], []string{"user"}) ||
			!slices.Equal(u.RequiredActions, []string{flows.ActionRecoveryCodes}) || !slices.Equal(u.RealmRoles, []string{"offline_access"}) {
			t.Errorf("user %+v", u)
		}
	}
	var order []string
	for _, c := range w.log1() {
		if c == "fact" || c == "designate" || c == "import" || c == "read" || c == "record" {
			if len(order) == 0 || order[len(order)-1] != c {
				order = append(order, c)
			}
		}
	}
	if !slices.Equal(order, []string{"fact", "designate", "import", "read", "record"}) {
		t.Errorf("order %v", order)
	}
	var res importResult
	if err := json.Unmarshal(prior[StepImport], &res); err != nil || len(res.Accounts) != 2 {
		t.Fatalf("import result %s %v", prior[StepImport], err)
	}
	rows, _ := w.store.Rows(t.Context())
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if wantIDs[r.AccountID] != r.NewName || r.AccountID != auth.MovedAccountID(r.Handle) {
			t.Errorf("row %+v", r)
		}
	}
	// One INFO per step, with the counts and no name or id.
	steps := w.rec.Matching(slog.LevelInfo, "")
	n := 0
	for _, r := range steps {
		if v, _ := logkittest.Attr(r, "event"); v == "identity.move.step" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d step records, want 3", n)
	}
	if txt := w.rec.Text(); strings.Contains(txt, "alice") || strings.Contains(txt, auth.MovedAccountID(h1)) {
		t.Error("a log record names an account")
	}
	// A second run finds the move recorded: not_needed, no import.
	if _, err := w.run(t, Spec{}); err != nil {
		t.Fatal(err)
	}
	if len(w.imports) != 1 {
		t.Errorf("a recorded move imported again: %d imports", len(w.imports))
	}
}

// TC-1004-11: every failure path fails the job with its sentence, writes
// no move row, sends no import when it fails before the import, and writes
// one ERROR record with the step (and an Admin API error's status and
// kind), naming no account.
func TestMove_TC1004_11_FailClosed(t *testing.T) {
	adminErr := &idclient.Error{Op: "admin", Status: 503, Kind: idclient.ErrUnreachable}
	for _, c := range []struct {
		name     string
		set      func(w *world)
		step     string
		sentence string
		imported bool
		status   bool
	}{
		{"import 5xx", func(w *world) { w.fail["import"] = adminErr }, StepImport, sentenceMove, true, true},
		{"read-back other name", func(w *world) { w.readName = "other" }, StepImport, sentenceMove, true, false},
		{"read-back no app access", func(w *world) { w.noApp = true }, StepImport, sentenceMove, true, false},
		{"read-back not found", func(w *world) { w.fail["read"] = &idclient.Error{Status: 404, Kind: idclient.ErrNotFound} }, StepImport, sentenceMove, true, true},
		{"access fact unreadable", func(w *world) { w.fail["fact"] = removednames.ErrUnreadable }, StepImport, sentenceMove, false, false},
		{"designation", func(w *world) { w.fail["designate"] = errDown }, StepImport, sentenceMove, false, false},
		{"map", func(w *world) {}, StepImport, sentenceMove, false, false},
		{"not ready", func(w *world) { w.fail["ready"] = errDown }, StepCheck, sentenceNotReady, false, false},
		{"record", func(w *world) { w.fail["record"] = errDown }, StepRecord, sentenceMove, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.addOld(t, 1, "alice", 1)
			if c.name == "map" {
				// An old name outside the old rule: written past the auth
				// store, as a corrupt row would be.
				w.addOld(t, 2, "bad name", 2)
			}
			c.set(w)
			_, err := w.run(t, Spec{})
			if err == nil || err.Error() != c.sentence {
				t.Fatalf("err %v, want %q", err, c.sentence)
			}
			if n := w.rowCount(t); n != 0 {
				t.Errorf("%d rows, want 0", n)
			}
			if got := len(w.imports) > 0 || w.fail["import"] != nil && slices.Contains(w.log1(), "import"); got != c.imported {
				t.Errorf("import sent %v, want %v", got, c.imported)
			}
			errs := w.rec.AtLevel(slog.LevelError)
			if len(errs) != 1 {
				t.Fatalf("%d ERROR records, want 1", len(errs))
			}
			if v, _ := logkittest.Attr(errs[0], "event"); v != "identity.move.failed" {
				t.Errorf("event %q", v)
			}
			if v, _ := logkittest.Attr(errs[0], "step"); v != c.step {
				t.Errorf("step %q, want %q", v, c.step)
			}
			if _, ok := logkittest.Attr(errs[0], "status"); ok != c.status {
				t.Errorf("status present %v, want %v", ok, c.status)
			}
			if strings.Contains(w.rec.Text(), "alice") {
				t.Error("a record names the account")
			}
		})
	}
}

// TC-1004-19: repair mode. A state gone fails with move_state's sentence
// and a changed token with state_changed's, both writing nothing; a run
// that proceeds leaves the removed name out of the import; an unreadable
// removed-name list fails the import; rows an earlier move wrote are kept
// unchanged.
func TestMove_TC1004_19_Repair(t *testing.T) {
	ctx := t.Context()
	setup := func(t *testing.T) (*world, string) {
		t.Helper()
		w := newWorld(t)
		w.addOld(t, 1, "alice", 1)
		w.addOld(t, 2, "bob", 2)
		if _, err := w.run(t, Spec{}); err != nil {
			t.Fatal(err)
		}
		w.realm = map[string]accounts.Account{} // C9: the realm lost its persons
		w.imports = nil
		r, err := w.state(t).Repair(ctx)
		if err != nil || !r.Holds {
			t.Fatalf("C9: %+v %v", r, err)
		}
		return w, r.Token
	}
	t.Run("state gone", func(t *testing.T) {
		w, tok := setup(t)
		w.realm["p"] = accounts.Account{ID: "p", Username: "door"}
		_, err := w.run(t, Spec{Repair: true, StateToken: tok})
		if err == nil || err.Error() != authz.KindSentence(authz.CodeMoveState) || len(w.imports) != 0 {
			t.Errorf("err %v, %d imports", err, len(w.imports))
		}
	})
	t.Run("token changed", func(t *testing.T) {
		w, _ := setup(t)
		_, err := w.run(t, Spec{Repair: true, StateToken: "stale"})
		if err == nil || err.Error() != authz.KindSentence(authz.CodeStateChanged) || len(w.imports) != 0 {
			t.Errorf("err %v, %d imports", err, len(w.imports))
		}
	})
	t.Run("removed name left out, earlier rows kept", func(t *testing.T) {
		w, _ := setup(t)
		before, _ := w.store.Rows(ctx)
		w.removed = map[string]bool{"bob": true}
		r, _ := w.state(t).Repair(ctx)
		prior, err := w.run(t, Spec{Repair: true, StateToken: r.Token})
		if err != nil {
			t.Fatal(err)
		}
		if len(w.imports) != 1 || len(w.imports[0].Users) != 1 || w.imports[0].Users[0].Username != "alice" {
			t.Fatalf("imports %+v, want alice only", w.imports)
		}
		var res importResult
		_ = json.Unmarshal(prior[StepImport], &res)
		if res.LeftOut != 1 {
			t.Errorf("leftOut %d, want 1", res.LeftOut)
		}
		after, _ := w.store.Rows(ctx)
		if len(after) != len(before) {
			t.Fatalf("rows %d, want %d", len(after), len(before))
		}
		for i := range after {
			if !after[i].MovedAt.Equal(before[i].MovedAt) || after[i].NewName != before[i].NewName {
				t.Errorf("row %d changed: %+v -> %+v", i, before[i], after[i])
			}
		}
	})
	t.Run("removed-name list unreadable", func(t *testing.T) {
		w, tok := setup(t)
		w.fail["removed"] = removednames.ErrUnreadable
		// At the check, which reads the list for the state, and at the
		// import, after the check's two reads pass.
		for _, pass := range []int{0, 2} {
			w.removedPass = pass
			_, err := w.run(t, Spec{Repair: true, StateToken: tok})
			if err == nil || err.Error() != sentenceMove || len(w.imports) != 0 {
				t.Errorf("pass %d: err %v, %d imports", pass, err, len(w.imports))
			}
		}
		if v, _ := logkittest.Attr(w.rec.AtLevel(slog.LevelError)[1], "step"); v != StepImport {
			t.Errorf("the second failure was at %q, want the import", v)
		}
	})
}

// TC-1004-23: New refuses each nil collaborator, an empty realm and a
// non-positive step bound, and does no I/O.
func TestNew_TC1004_23(t *testing.T) {
	w := newWorld(t)
	before := len(w.log1())
	for name, edit := range map[string]func(d *Deps){
		"Admin": func(d *Deps) { d.Admin = nil }, "OldUsers": func(d *Deps) { d.OldUsers = nil },
		"Persons": func(d *Deps) { d.Persons = nil }, "Designations": func(d *Deps) { d.Designations = nil },
		"Facts": func(d *Deps) { d.Facts = nil }, "Removed": func(d *Deps) { d.Removed = nil },
		"Ready": func(d *Deps) { d.Ready = nil }, "Records": func(d *Deps) { d.Records = nil },
		"Lock": func(d *Deps) { d.Lock = nil }, "Now": func(d *Deps) { d.Now = nil }, "Log": func(d *Deps) { d.Log = nil },
		"Realm": func(d *Deps) { d.Realm = "" }, "StepTimeout": func(d *Deps) { d.StepTimeout = 0 },
	} {
		d := w.deps()
		edit(&d)
		if m, err := New(d); err == nil || m != nil {
			t.Errorf("New without %s: %v %v, want refused", name, m, err)
		}
	}
	if m, err := New(w.deps()); err != nil || m == nil {
		t.Errorf("New: %v", err)
	}
	if len(w.log1()) != before {
		t.Errorf("New made calls: %v", w.log1()[before:])
	}
	wf := w.mover.Workflow()
	if wf.Kind != Kind || !wf.System || len(wf.Steps) != 3 {
		t.Errorf("workflow %s system=%v steps=%d", wf.Kind, wf.System, len(wf.Steps))
	}
}
