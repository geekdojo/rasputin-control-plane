package recoveradmin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeReady answers Ready with err and counts the calls.
type fakeReady struct {
	err error
	n   int
}

func (f *fakeReady) Ready(context.Context) error { f.n++; return f.err }

// scriptedSession answers each Admin call with the next error in errs (nil
// is a 200), repeating the last one, and counts the calls.
type scriptedSession struct {
	errs []error
	n    int
}

func (s *scriptedSession) Admin(_ context.Context, method, path string, _, _ any) (idclient.Response, error) {
	if method != "GET" || path != "/admin/realms/rasputin" {
		return idclient.Response{}, fmt.Errorf("unexpected %s %s", method, path)
	}
	i := min(s.n, len(s.errs)-1)
	s.n++
	if err := s.errs[i]; err != nil {
		return idclient.Response{}, err
	}
	return idclient.Response{Status: 200}, nil
}

// fakeLedger is the job ledger: jobs newest first. submit stands in for the
// scheduler's SubmitRawSpec creating a row.
type fakeLedger struct {
	mu   sync.Mutex
	list []*jobs.Job
	err  error
	n    int
}

func (l *fakeLedger) ListJobsByKind(_ context.Context, kind string, limit int) ([]*jobs.Job, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	if l.err != nil {
		return nil, l.err
	}
	if kind != Kind || limit != 1 {
		return nil, fmt.Errorf("unexpected ListJobsByKind(%q, %d)", kind, limit)
	}
	if len(l.list) == 0 {
		return nil, nil
	}
	return []*jobs.Job{l.list[0]}, nil
}

func (l *fakeLedger) submit(id string) *jobs.Job {
	l.mu.Lock()
	defer l.mu.Unlock()
	j := &jobs.Job{ID: id, Kind: Kind, Status: jobs.StatusRunning, CreatedAt: time.Date(2026, 11, 15, 12, 0, len(l.list), 0, time.UTC)}
	l.list = append([]*jobs.Job{j}, l.list...)
	return j
}

func (l *fakeLedger) finish(status jobs.Status) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list[0].Status = status
	at := l.list[0].CreatedAt.Add(time.Minute)
	l.list[0].FinishedAt = &at
}

// deniedLogin is the token endpoint refusing the client, wrapped as Session
// wraps a failed login.
func deniedLogin(oauth string, status int) error {
	return fmt.Errorf("idclient: log in as rasputin-admin: %w",
		&idclient.Error{Op: "token", Path: "/realms/rasputin/protocol/openid-connect/token", Status: status, Kind: idclient.ErrDenied, OAuthError: oauth})
}

func forbidden() error {
	return &idclient.Error{Op: "admin", Path: "/admin/realms/rasputin", Status: 403, Kind: idclient.ErrForbidden}
}

type triggerRig struct {
	ready   *fakeReady
	session *scriptedSession
	ledger  *fakeLedger
	rec     *logkittest.Recorder
	trig    *Trigger
}

func newRig(t *testing.T, errs ...error) *triggerRig {
	t.Helper()
	log, rec := logkittest.New()
	r := &triggerRig{ready: &fakeReady{}, session: &scriptedSession{errs: errs}, ledger: &fakeLedger{}, rec: rec}
	trig, err := NewTrigger(TriggerDeps{Ready: r.ready, Admin: r.session, Ledger: r.ledger, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.trig = trig
	return r
}

// eventRecords are the records carrying event=ev.
func eventRecords(rec *logkittest.Recorder, ev string) []slog.Record {
	var out []slog.Record
	for _, r := range rec.Records() {
		if v, _ := logkittest.Attr(r, "event"); v == ev {
			out = append(out, r)
		}
	}
	return out
}

// TC-1127-01: while the identity service is not ready, or the check's context
// ended, the trigger is not due and makes no admin call and no record.
func TestTrigger_NotReadyIsNotDue(t *testing.T) {
	for name, err := range map[string]error{
		"not ready":         &identitystate.NotReadyError{State: identitystate.DatabaseDown},
		"cancelled context": context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, deniedLogin("invalid_client", 401))
			r.ready.err = err
			if due, _ := r.trig.Due(t.Context()); due {
				t.Error("due while not ready")
			}
			if r.session.n != 0 || r.ledger.n != 0 {
				t.Errorf("%d admin calls and %d ledger reads, want 0", r.session.n, r.ledger.n)
			}
			if n := len(r.rec.Records()); n != 0 {
				t.Errorf("%d records, want 0:\n%s", n, r.rec.Text())
			}
		})
	}
}

// TC-1127-02: a client that works is not due, and a new trigger seeing it
// writes nothing (the first start after an upgrade).
func TestTrigger_WorkingClientIsNotDue(t *testing.T) {
	r := newRig(t, nil)
	if due, reason := r.trig.Due(t.Context()); due || reason != "" {
		t.Errorf("Due = %v %q, want false and no reason", due, reason)
	}
	if n := len(r.rec.Records()); n != 0 {
		t.Errorf("%d records, want 0:\n%s", n, r.rec.Text())
	}
}

// tokenLogin is a TokenSource whose first login gives a token with known
// text and every later login is refused with err.
type tokenLogin struct {
	n   int
	err error
}

const fakeTokenText = "tc-1127-fake-token-text"

func (l *tokenLogin) ClientCredentials(context.Context, string, string, *secret.Value) (secret.Value, error) {
	l.n++
	if l.n == 1 {
		return secret.New([]byte(fakeTokenText)), nil
	}
	return secret.Value{}, l.err
}

// refusingAdmin refuses every token (the client was deleted after the
// session logged in).
type refusingAdmin struct{}

func (refusingAdmin) Admin(_ context.Context, _ secret.Value, _, path string, _, _ any) (idclient.Response, error) {
	return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Status: 401, Kind: idclient.ErrTokenRefused}
}

// TC-1127-03 and TC-1127-04: the token endpoint refusing the client is due,
// with one WARN carrying the error's fields and never the token.
func TestTrigger_RefusedClientIsDue(t *testing.T) {
	for _, tc := range []struct {
		id, oauth string
		status    int
	}{{"TC-1127-03", "invalid_client", 401}, {"TC-1127-04", "unauthorized_client", 400}} {
		t.Run(tc.id, func(t *testing.T) {
			log, rec := logkittest.New()
			sessLog := slog.New(slog.DiscardHandler)
			login := &tokenLogin{err: &idclient.Error{Op: "token", Path: "/realms/rasputin/protocol/openid-connect/token",
				Status: tc.status, Kind: idclient.ErrDenied, OAuthError: tc.oauth}}
			sess, err := idclient.NewSession(idclient.SessionConfig{Login: login, Admin: refusingAdmin{}, Realm: realm, ClientID: adminClient, Log: sessLog})
			if err != nil {
				t.Fatal(err)
			}
			trig, err := NewTrigger(TriggerDeps{Ready: &fakeReady{}, Admin: sess, Ledger: &fakeLedger{}, Log: log})
			if err != nil {
				t.Fatal(err)
			}
			// The first check's fresh token is refused (401 on its own is
			// not the fact); the next check's login is refused.
			if due, _ := trig.Due(t.Context()); due {
				t.Fatal("a refused fresh token is due")
			}
			due, reason := trig.Due(t.Context())
			if !due || reason == "" {
				t.Fatalf("Due = %v %q, want true with a reason", due, reason)
			}
			if login.n != 2 {
				t.Fatalf("logins = %d, want the first and the refused one", login.n)
			}
			recs := eventRecords(rec, "identity.recover_admin_due")
			if len(recs) != 1 || recs[0].Level != slog.LevelWarn || len(rec.Records()) != 1 {
				t.Fatalf("records:\n%s\nwant exactly one WARN identity.recover_admin_due", rec.Text())
			}
			want := map[string]string{"component": "identity", "op": "token", "path": "/realms/rasputin/protocol/openid-connect/token",
				"status": fmt.Sprint(tc.status), "kind": "denied", "oauth_error": tc.oauth}
			for k, v := range want {
				if got, _ := logkittest.Attr(recs[0], k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			if strings.Contains(rec.Text(), fakeTokenText) || strings.Contains(reason, fakeTokenText) {
				t.Error("the record or the reason carries the token")
			}
		})
	}
}

// TC-1127-05: 403 on the realm read (the client lost its roles) is due.
func TestTrigger_ForbiddenIsDue(t *testing.T) {
	r := newRig(t, forbidden())
	if due, _ := r.trig.Due(t.Context()); !due {
		t.Fatal("403 is not due")
	}
	recs := eventRecords(r.rec, "identity.recover_admin_due")
	if len(recs) != 1 {
		t.Fatalf("records:\n%s", r.rec.Text())
	}
	if s, _ := logkittest.Attr(recs[0], "status"); s != "403" {
		t.Errorf("status = %q, want 403", s)
	}
	if k, _ := logkittest.Attr(recs[0], "kind"); k != "forbidden" {
		t.Errorf("kind = %q, want forbidden", k)
	}
}

// TC-1127-06: every answer that is not the fact is not due and writes
// nothing (ERR-CLOSED), including the brute-force lockout's invalid_request.
func TestTrigger_OtherAnswersAreNotDue(t *testing.T) {
	for name, err := range map[string]error{
		"TLS refusal":       deniedLogin("", 0),
		"unreachable":       &idclient.Error{Op: "token", Kind: idclient.ErrUnreachable, Err: errors.New("connection refused")},
		"protocol 404":      &idclient.Error{Op: "admin", Status: 404, Kind: idclient.ErrProtocol},
		"lockout":           deniedLoginKind(idclient.ErrProtocol, "invalid_request", 401),
		"token refused":     &idclient.Error{Op: "admin", Status: 401, Kind: idclient.ErrTokenRefused},
		"not found":         &idclient.Error{Op: "admin", Status: 404, Kind: idclient.ErrNotFound},
		"context cancelled": context.Canceled,
		"plain error":       errors.New("something else"),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, err)
			if due, _ := r.trig.Due(t.Context()); due {
				t.Error("due")
			}
			if n := len(r.rec.Records()); n != 0 {
				t.Errorf("%d records, want 0:\n%s", n, r.rec.Text())
			}
		})
	}
}

func deniedLoginKind(kind error, oauth string, status int) error {
	return fmt.Errorf("idclient: log in as rasputin-admin: %w",
		&idclient.Error{Op: "token", Status: status, Kind: kind, OAuthError: oauth, Err: errors.New("unexpected status")})
}

// TC-1127-07: once fired, the trigger is not due again while its job runs or
// after it failed, and writes nothing more.
func TestTrigger_LatchedWhileRunningAndAfterFailure(t *testing.T) {
	r := newRig(t, deniedLogin("invalid_client", 401))
	if due, _ := r.trig.Due(t.Context()); !due {
		t.Fatal("the first refusal is not due")
	}
	r.ledger.submit("J1")
	before := len(r.rec.Records())
	for i, step := range []func(){func() {}, func() {}, func() { r.ledger.finish(jobs.StatusFailed) }} {
		step()
		if due, reason := r.trig.Due(t.Context()); due || reason != "" {
			t.Errorf("check %d: Due = %v %q, want false and no reason", i, due, reason)
		}
	}
	if n := len(r.rec.Records()); n != before {
		t.Errorf("records grew from %d to %d:\n%s", before, n, r.rec.Text())
	}
}

// TC-1127-07 (F-1127-03): a fired Due whose submit created no row is due
// again on the next refused reading.
func TestTrigger_FailedSubmitFiresAgain(t *testing.T) {
	r := newRig(t, deniedLogin("invalid_client", 401))
	for i := range 2 {
		if due, _ := r.trig.Due(t.Context()); !due {
			t.Fatalf("check %d: not due with no job in the ledger", i)
		}
	}
}

// TC-1127-07 (F-1127-03): a ledger that cannot be read is not due and writes
// one WARN per outage.
func TestTrigger_LedgerUnreadableIsNotDue(t *testing.T) {
	r := newRig(t, deniedLogin("invalid_client", 401))
	r.ledger.err = errors.New("database is locked")
	for i := range 3 {
		if due, reason := r.trig.Due(t.Context()); due || reason == "" {
			t.Errorf("check %d: Due = %v %q, want false with a reason", i, due, reason)
		}
	}
	if w := r.rec.Matching(slog.LevelWarn, "The job ledger could not be read"); len(w) != 1 || len(r.rec.Records()) != 1 {
		t.Errorf("records:\n%s\nwant one ledger WARN", r.rec.Text())
	}
	r.ledger.err = nil
	if due, _ := r.trig.Due(t.Context()); !due {
		t.Error("not due once the ledger reads again")
	}
	r.ledger.err = errors.New("database is locked again")
	r.trig.Due(t.Context())
	if w := r.rec.Matching(slog.LevelWarn, "The job ledger could not be read"); len(w) != 2 {
		t.Errorf("%d ledger WARNs after a second outage, want 2", len(w))
	}
}

// TC-1127-08: a probe that succeeds re-arms the trigger with one INFO; the
// next refusal is due again.
func TestTrigger_RearmsOnAWorkingProbe(t *testing.T) {
	r := newRig(t, deniedLogin("invalid_client", 401), nil, nil, deniedLogin("invalid_client", 401))
	if due, _ := r.trig.Due(t.Context()); !due {
		t.Fatal("the first refusal is not due")
	}
	r.ledger.submit("J1")
	r.ledger.finish(jobs.StatusSucceeded)
	for i := range 2 {
		if due, _ := r.trig.Due(t.Context()); due {
			t.Errorf("200 #%d is due", i+1)
		}
	}
	if n := len(eventRecords(r.rec, "identity.recover_admin_rearmed")); n != 1 {
		t.Errorf("%d rearmed records, want 1:\n%s", n, r.rec.Text())
	}
	if due, _ := r.trig.Due(t.Context()); !due {
		t.Error("the refusal after a re-arm is not due")
	}
	if n := len(eventRecords(r.rec, "identity.recover_admin_due")); n != 2 {
		t.Errorf("%d due records, want 2", n)
	}
}

// TC-1127-09: a new process's trigger is due on the fact even though the
// ledger holds an earlier run; NewTrigger refuses a nil collaborator and
// calls none.
func TestTrigger_NewProcessAndConstructor(t *testing.T) {
	r := newRig(t, deniedLogin("invalid_client", 401))
	r.trig.Due(t.Context())
	r.ledger.submit("J1")
	r.ledger.finish(jobs.StatusFailed)
	if due, _ := r.trig.Due(t.Context()); due {
		t.Fatal("the latched trigger is due")
	}
	again, err := NewTrigger(r.trig.d)
	if err != nil {
		t.Fatal(err)
	}
	if due, _ := again.Due(t.Context()); !due {
		t.Error("a new process's trigger is not due")
	}

	ready, sess, ledger := &fakeReady{}, &scriptedSession{errs: []error{nil}}, &fakeLedger{}
	full := TriggerDeps{Ready: ready, Admin: sess, Ledger: ledger, Log: slog.New(slog.DiscardHandler)}
	for name, m := range map[string]func(*TriggerDeps){
		"readiness": func(d *TriggerDeps) { d.Ready = nil },
		"session":   func(d *TriggerDeps) { d.Admin = nil },
		"ledger":    func(d *TriggerDeps) { d.Ledger = nil },
		"logger":    func(d *TriggerDeps) { d.Log = nil },
	} {
		d := full
		m(&d)
		if _, err := NewTrigger(d); err == nil {
			t.Errorf("%s: NewTrigger accepted it", name)
		}
	}
	if ready.n+sess.n+ledger.n != 0 {
		t.Errorf("the constructor made %d calls", ready.n+sess.n+ledger.n)
	}
}

// F-1127-08: the still-refused alert is present only while the trigger is
// latched, its last probe was refused and the run failed, and clears on a
// working probe.
func TestTrigger_StillRefusedAlert(t *testing.T) {
	r := newRig(t, deniedLogin("invalid_client", 401))
	now := time.Now()
	if a := r.trig.Alerts(t.Context(), now); a != nil {
		t.Fatalf("alerts before any reading = %v", a)
	}
	r.trig.Due(t.Context())
	if a := r.trig.Alerts(t.Context(), now); a != nil {
		t.Errorf("alerts after firing, before any job = %v", a)
	}
	r.ledger.submit("J1")
	if a := r.trig.Alerts(t.Context(), now); a != nil {
		t.Errorf("alerts while the job runs = %v", a)
	}
	r.ledger.finish(jobs.StatusFailed)
	got := r.trig.Alerts(t.Context(), now)
	want := proto.Alert{ID: "identity:admin-client-refused", Severity: proto.AlertWarn, Source: proto.AlertSourceSecurity,
		Title:  "The control plane cannot administer its sign-in service.",
		Detail: "Its admin client is refused and the automatic recovery failed (see Tasks). Restarting the control plane retries the recovery once.",
		Since:  *r.ledger.list[0].FinishedAt, RelatedKind: "job", RelatedID: "J1"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("alerts after the run failed = %+v, want %+v", got, want)
	}
	r.ledger.err = errors.New("unreadable")
	if a := r.trig.Alerts(t.Context(), now); a != nil {
		t.Errorf("alerts with the ledger unreadable = %v", a)
	}
	r.ledger.err = nil

	r.session.errs = append(r.session.errs, nil)
	if due, _ := r.trig.Due(t.Context()); due { // 200
		t.Fatal("a working probe is due")
	}
	if a := r.trig.Alerts(t.Context(), now); a != nil {
		t.Errorf("alerts after a working probe = %v", a)
	}

	s := newRig(t, deniedLogin("invalid_client", 401))
	s.trig.Due(t.Context())
	s.ledger.submit("J2")
	s.ledger.finish(jobs.StatusSucceeded)
	if a := s.trig.Alerts(t.Context(), now); a != nil {
		t.Errorf("alerts after the run succeeded = %v", a)
	}
}

// TC-1127-14: nothing but the job, its trigger and the trigger's wiring names
// the kind, so no other code path can submit it.
func TestKind_NamedOnlyByTheJobAndItsTrigger(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "cmd", "rasputin-api", "main.go")); err != nil {
		t.Fatalf("%s is not the api module root: %v", root, err)
	}
	allowed := []string{"recoveradmin.go", "trigger.go", "recoveradmin_trigger_wiring.go"}
	var scanned int
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		s := string(b)
		if strings.Contains(s, "recoveradmin.Kind") || strings.Contains(s, `"identity.recover_admin"`) {
			found = append(found, path)
			if !slices.Contains(allowed, filepath.Base(path)) {
				t.Errorf("%s names identity.recover_admin's kind", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 || len(found) < 2 {
		t.Fatalf("scanned %d files and found the kind in %v; the scan proved nothing", scanned, found)
	}
}
