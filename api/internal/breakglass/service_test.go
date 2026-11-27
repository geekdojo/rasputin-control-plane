package breakglass

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeAlerts records the event alerts raised; err fails them.
type fakeAlerts struct {
	mu               sync.Mutex
	issued, redeemed []string
	// resets are "<event>/<account>" per reset alert.
	resets []string
	err    error
}

func (a *fakeAlerts) RaiseBreakGlassReset(_ context.Context, id, account string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resets = append(a.resets, id+"/"+account)
	return a.err
}

func (a *fakeAlerts) RaiseBreakGlassIssued(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.issued = append(a.issued, id)
	return a.err
}

func (a *fakeAlerts) RaiseBreakGlassRedeemed(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.redeemed = append(a.redeemed, id)
	return a.err
}

// fakeJobs serves jobs by id.
type fakeJobs map[string]*jobs.Job

func (f fakeJobs) GetJob(_ context.Context, id string) (*jobs.Job, error) {
	if j, ok := f[id]; ok {
		return j, nil
	}
	return nil, errors.New("no such job")
}

// fakeIdentity is the sign-in service's state.
type fakeIdentity struct {
	st  identitystate.State
	err error
}

func (f *fakeIdentity) State(context.Context) (identitystate.State, error) { return f.st, f.err }

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

const testHost = "ci.local"

var testIP = net.IPv4(192, 0, 2, 1)

type rig struct {
	svc      *Service
	alerts   *fakeAlerts
	jobs     fakeJobs
	identity *fakeIdentity
	busy     string
	bmcHost  bool
	// serialOn and serialErr are the serial login fact's answer, and
	// serialCalls how many times it was read.
	serialOn    bool
	serialErr   error
	serialCalls int
	clock       *clock
	rec         *logkittest.Recorder
}

func newRig(t *testing.T) *rig {
	t.Helper()
	log, rec := logkittest.New()
	r := &rig{alerts: &fakeAlerts{}, jobs: fakeJobs{}, identity: &fakeIdentity{st: identitystate.Failed},
		clock: &clock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}, rec: rec}
	n := 0
	svc, err := New(Deps{
		Now: r.clock.Now, Rand: rand.Reader, IDs: func() string { n++; return "ev-" + string(rune('0'+n)) }, Log: log,
		Alerts: r.alerts, Jobs: r.jobs, Identity: r.identity,
		Busy: func(context.Context) (string, bool) { return r.busy, r.busy != "" },
		Facts: Facts{ConsoleHost: testHost, PrimaryIP: func() net.IP { return testIP },
			BMCHost: func() bool { return r.bmcHost },
			SerialLogin: func(ctx context.Context) (bool, error) {
				r.serialCalls++
				if err := ctx.Err(); err != nil {
					return false, err
				}
				return r.serialOn, r.serialErr
			}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

// newCode is a code as the command prints it, issued.
func (r *rig) issue(t *testing.T) string {
	t.Helper()
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:20]
	if err := r.svc.Issue(context.Background(), Hash([]byte(code))); err != nil {
		t.Fatal(err)
	}
	return code
}

var (
	consoleOrigin = "https://" + testHost
	ipOrigin      = "https://192.0.2.1"
	src           = netip.MustParseAddr("198.51.100.7")
)

func (r *rig) redeem(code, origin string, from netip.Addr) (secret.Value, error) {
	return r.svc.Redeem(context.Background(), from, origin, secret.New([]byte(code)))
}

// events are the records whose event field is ev, with reason when given.
func (r *rig) events(ev, reason string) []slog.Record {
	var out []slog.Record
	for _, rec := range r.rec.Records() {
		if e, _ := logkittest.Attr(rec, "event"); e != ev {
			continue
		}
		if got, _ := logkittest.Attr(rec, "reason"); reason != "" && got != reason {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func TestNew_RefusesAMissingCollaborator(t *testing.T) {
	good := func() Deps {
		return Deps{Now: time.Now, Rand: rand.Reader, IDs: func() string { return "x" }, Log: slog.New(slog.DiscardHandler),
			Alerts: &fakeAlerts{}, Jobs: fakeJobs{}, Busy: func(context.Context) (string, bool) { return "", false },
			Facts: Facts{ConsoleHost: "h", PrimaryIP: func() net.IP { return nil }, BMCHost: func() bool { return false },
				SerialLogin: func(context.Context) (bool, error) { return false, nil }}}
	}
	if _, err := New(good()); err != nil {
		t.Fatalf("a complete Deps with no Identity: %v", err)
	}
	for name, edit := range map[string]func(*Deps){
		"Now": func(d *Deps) { d.Now = nil }, "Rand": func(d *Deps) { d.Rand = nil }, "IDs": func(d *Deps) { d.IDs = nil },
		"Log": func(d *Deps) { d.Log = nil }, "Alerts": func(d *Deps) { d.Alerts = nil }, "Jobs": func(d *Deps) { d.Jobs = nil },
		"Busy": func(d *Deps) { d.Busy = nil }, "ConsoleHost": func(d *Deps) { d.Facts.ConsoleHost = "" },
		"PrimaryIP": func(d *Deps) { d.Facts.PrimaryIP = nil }, "BMCHost": func(d *Deps) { d.Facts.BMCHost = nil },
		// TC-321-74: the serial login fact is a collaborator too.
		"SerialLogin": func(d *Deps) { d.Facts.SerialLogin = nil },
	} {
		d := good()
		edit(&d)
		if _, err := New(d); err == nil {
			t.Errorf("New with no %s succeeded", name)
		}
	}
}

// TC-321-09 (b): an administrator's sign-in retires the code, with INFO
// breakglass.code_retired; (c): a fresh Service, as after an api restart,
// holds no code; (d): 50 wrong codes from 10 sources never retire it.
func TestRetirementFacts_TC321_09(t *testing.T) {
	r := newRig(t)
	a := r.issue(t)
	r.svc.AdminSignedIn(context.Background())
	if _, err := r.redeem(a, consoleOrigin, src); !errors.Is(err, ErrNoCode) {
		t.Fatalf("(b) after an admin's sign-in: %v, want ErrNoCode", err)
	}
	if recs := r.events("breakglass.code_retired", "admin_signin"); len(recs) != 1 || recs[0].Level != slog.LevelInfo {
		t.Errorf("(b) code_retired admin_signin records: %v", recs)
	}

	a = r.issue(t)
	fresh := newRig(t)
	if _, err := fresh.redeem(a, consoleOrigin, src); !errors.Is(err, ErrNoCode) {
		t.Fatalf("(c) on a fresh Service: %v, want ErrNoCode", err)
	}

	for i := range 10 {
		from := netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
		for range 5 {
			if _, err := r.redeem("WRONGWRONGWRONGWRONG", consoleOrigin, from); !errors.Is(err, ErrWrongCode) {
				t.Fatalf("(d) wrong code from %s: %v", from, err)
			}
		}
	}
	if c, err := r.redeem(a, consoleOrigin, netip.MustParseAddr("203.0.113.200")); err != nil || c.Len() == 0 {
		t.Fatalf("(d) the code after 50 wrong ones from 10 sources: %v", err)
	}
}

// TC-321-16 (lifetime): the session is live at createdAt + 7 days - 1s and
// ended, with reason=lifetime, at createdAt + 7 days.
func TestSessionLifetime_TC321_16(t *testing.T) {
	r := newRig(t)
	cookie, err := r.redeem(r.issue(t), consoleOrigin, src)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Add(7*24*time.Hour - time.Second)
	if _, ok := r.svc.Resolve(context.Background(), cookie, consoleOrigin); !ok {
		t.Fatal("the session ended before its seven days")
	}
	r.clock.Add(time.Second)
	if _, ok := r.svc.Resolve(context.Background(), cookie, consoleOrigin); ok {
		t.Fatal("the session is live at seven days")
	}
	if recs := r.events("breakglass.session_ended", "lifetime"); len(recs) != 1 || recs[0].Level != slog.LevelInfo {
		t.Errorf("session_ended lifetime records: %v", recs)
	}
}

// TC-321-17 (breakglass's half): AdminSignedIn ends the live session and
// retires the outstanding code.
func TestAdminSignedIn_TC321_17(t *testing.T) {
	r := newRig(t)
	cookie, err := r.redeem(r.issue(t), consoleOrigin, src)
	if err != nil {
		t.Fatal(err)
	}
	b := r.issue(t)
	r.svc.AdminSignedIn(context.Background())
	if _, ok := r.svc.Resolve(context.Background(), cookie, consoleOrigin); ok {
		t.Error("the session is live after an admin's sign-in")
	}
	if _, err := r.redeem(b, consoleOrigin, src); !errors.Is(err, ErrNoCode) {
		t.Errorf("the outstanding code after an admin's sign-in: %v", err)
	}
	if len(r.events("breakglass.session_ended", "admin_signin")) != 1 || len(r.events("breakglass.code_retired", "admin_signin")) != 1 {
		t.Errorf("records: %s", r.rec.Text())
	}
}

// TC-321-22 (the service's half): an issue raises the issued alert and a
// redemption the redeemed one, each under a fresh event id; with the alert
// store failing, both still succeed and an ERROR alert=not_raised is
// written for each.
func TestAlerts_TC321_22(t *testing.T) {
	r := newRig(t)
	code := r.issue(t)
	if _, err := r.redeem(code, consoleOrigin, src); err != nil {
		t.Fatal(err)
	}
	if len(r.alerts.issued) != 1 || len(r.alerts.redeemed) != 1 || r.alerts.issued[0] == r.alerts.redeemed[0] {
		t.Fatalf("alerts issued %v redeemed %v, want one each under distinct ids", r.alerts.issued, r.alerts.redeemed)
	}
	r.alerts.err = errors.New("the alert store is down")
	code = r.issue(t)
	if c, err := r.redeem(code, consoleOrigin, src); err != nil || c.Len() == 0 {
		t.Fatalf("redeem with the alert store down: %v", err)
	}
	var notRaised int
	for _, rec := range r.rec.AtLevel(slog.LevelError) {
		if v, _ := logkittest.Attr(rec, "alert"); v == "not_raised" {
			notRaised++
		}
	}
	if notRaised != 2 {
		t.Errorf("%d ERROR alert=not_raised records, want 2:\n%s", notRaised, r.rec.Text())
	}
}

// TC-321-21 (the service's half) and TC-321-73: the ways list the screen,
// the serial console only while the BMC-host marker is absent and a serial
// login getty runs, and the ssh command; the state carries the sentence,
// RESTART with enabled and a reason, and the session's jobs; a failed state
// read keeps RESTART enabled; nothing else is ever listed.
func TestStateAndWays_TC321_21(t *testing.T) {
	r := newRig(t)
	ids := func(w Ways) []string {
		var out []string
		for _, x := range w.Ways {
			out = append(out, x.ID)
		}
		return out
	}
	unread := func() []slog.Record { return r.events("breakglass.serial_unread", "") }
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []struct {
		name      string
		marker    bool
		on        bool
		err       error
		ctx       context.Context
		want      string
		calls, wn int
	}{
		{name: "marker absent, a getty running", on: true, ctx: context.Background(), want: "screen,serial,ssh", calls: 1},
		{name: "marker absent, no getty", ctx: context.Background(), want: "screen,ssh", calls: 1},
		{name: "marker present", marker: true, on: true, ctx: context.Background(), want: "screen,ssh"},
		{name: "a failed read", on: true, err: errors.New("no bus"), ctx: context.Background(), want: "screen,ssh", calls: 1, wn: 1},
		{name: "a cancelled context", on: true, ctx: cancelled, want: "screen,ssh", calls: 1, wn: 1},
	} {
		r.bmcHost, r.serialOn, r.serialErr, r.serialCalls = c.marker, c.on, c.err, 0
		before := len(unread())
		w := r.svc.Ways(c.ctx)
		if got := strings.Join(ids(w), ","); got != c.want {
			t.Errorf("%s: ways %s, want %s", c.name, got, c.want)
		}
		if r.serialCalls != c.calls {
			t.Errorf("%s: the serial login was read %d times, want %d", c.name, r.serialCalls, c.calls)
		}
		recs := unread()[before:]
		if len(recs) != c.wn {
			t.Errorf("%s: %d breakglass.serial_unread records, want %d", c.name, len(recs), c.wn)
		}
		for _, rec := range recs {
			e, _ := logkittest.Attr(rec, "err")
			if rec.Level != slog.LevelWarn || rec.Message != "The serial console's login state couldn't be read for the repair page." || e == "" {
				t.Errorf("%s: record %v %q err %q", c.name, rec.Level, rec.Message, e)
			}
		}
		if ssh := w.Ways[len(w.Ways)-1]; ssh.ID != "ssh" || ssh.Command != "ssh -t root@ci.local rasputin-api repair-code" {
			t.Errorf("%s: ssh way %+v", c.name, ssh)
		}
		if strings.Join(w.URLs, " ") != "https://ci.local/repair https://192.0.2.1/repair" {
			t.Errorf("%s: urls %v", c.name, w.URLs)
		}
	}
	r.bmcHost = true

	cookie, err := r.redeem(r.issue(t), consoleOrigin, src)
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := r.svc.Resolve(context.Background(), cookie, consoleOrigin)
	r.jobs["J1"] = &jobs.Job{ID: "J1", Kind: RestartKind, Status: jobs.StatusRunning}
	r.svc.RecordJob(sess, "J1")
	st := r.svc.State(context.Background(), sess)
	if st.Sentence != identitystate.Failed.Sentence() || st.Ready || st.SignInAt != "https://ci.local" {
		t.Errorf("state %+v", st)
	}
	if len(st.Actions) != 1 || st.Actions[0].ID != "restart" || !st.Actions[0].Enabled || st.Actions[0].Kind != RestartKind {
		t.Errorf("actions %+v, want RESTART alone, enabled", st.Actions)
	}
	if len(st.Jobs) != 1 || st.Jobs[0].Status != "running" || st.Jobs[0].Finished {
		t.Errorf("jobs %+v", st.Jobs)
	}
	r.jobs["J1"].Status = jobs.StatusSucceeded
	if st := r.svc.State(context.Background(), sess); !st.Jobs[0].Finished {
		t.Errorf("a succeeded job is not finished: %+v", st.Jobs)
	}

	r.busy = "busy now."
	if st := r.svc.State(context.Background(), sess); st.Actions[0].Enabled || st.Actions[0].Reason != "busy now." {
		t.Errorf("busy: %+v", st.Actions)
	}
	r.busy = ""
	r.identity.err = errors.New("ctx ended")
	if st := r.svc.State(context.Background(), sess); st.Sentence != "The sign-in service's state couldn't be read." || !st.Actions[0].Enabled {
		t.Errorf("failed read: %+v", st)
	}
	r.identity.err, r.identity.st = nil, identitystate.Ready
	if st := r.svc.State(context.Background(), sess); !st.Ready {
		t.Errorf("ready: %+v", st)
	}
	// Reset and move are unwired here, so neither is listed (TC-321-45
	// lists them); restore is never listed.
	for _, st := range []StateView{r.svc.State(context.Background(), sess)} {
		for _, a := range st.Actions {
			for _, never := range []string{"reset", "restore", "move"} {
				if strings.Contains(a.ID, never) || strings.Contains(a.Kind, never) {
					t.Errorf("action %+v is listed", a)
				}
			}
		}
	}

	off := newRig(t)
	off.svc.d.Identity = nil
	st = off.svc.State(context.Background(), Session{})
	if st.Sentence != "Sign-in isn't installed on this control plane." || st.Actions[0].Enabled || st.Actions[0].Reason == "" {
		t.Errorf("identity off: %+v", st)
	}
}

// TC-321-12: a code typed in lower case, with spaces or dashes anywhere,
// hashes as the printed one.
func TestHashToleratesTyping_TC321_12(t *testing.T) {
	want := Hash([]byte("ABCDEFGHIJKLMNOPQRST"))
	for _, typed := range []string{"abcdefghijklmnopqrst", "ABCDE-FGHIJ-KLMNO-PQRST", " abc de-fgh ij-klmnopqrs t ", "A-B-C-D-E-F-G-H-I-J-K-L-M-N-O-P-Q-R-S-T"} {
		if Hash([]byte(typed)) != want {
			t.Errorf("%q hashes differently", typed)
		}
	}
	if Hash([]byte("ABCDEFGHIJKLMNOPQRSA")) == want {
		t.Error("a different code hashes the same")
	}
}

// TC-321-26 (the constructor's half): a session's submitter is the repair
// session, holding Repair only and recording break-glass.
func TestSessionSubmitter_TC321_26(t *testing.T) {
	s := Session{}.Submitter()
	if s.CreatedBy() != "break-glass" || !s.Capabilities().Has(authz.Repair) || s.Capabilities().Has(authz.View) || s.IsSystem() {
		t.Errorf("submitter %+v", s)
	}
	if _, ok := SessionFrom(context.Background()); ok {
		t.Error("an empty context carries a session")
	}
	if got, ok := SessionFrom(WithSession(context.Background(), Session{origin: "o"})); !ok || got.Origin() != "o" {
		t.Errorf("SessionFrom = %+v %v", got, ok)
	}
}

// TC-321-13 (the service's half): a code redeems at the console's origin and
// at the primary LAN address's, and the session resolves only at the origin
// it was opened at; any other origin is ErrOrigin and leaves the code
// outstanding.
func TestOrigins_TC321_13(t *testing.T) {
	r := newRig(t)
	for _, o := range []string{"https://other.local", "https://100.64.0.1", "http://ci.local", "https://ci.local:8443"} {
		code := r.issue(t)
		if _, err := r.redeem(code, o, src); !errors.Is(err, ErrOrigin) {
			t.Errorf("%s: %v, want ErrOrigin", o, err)
		}
		if _, err := r.redeem(code, consoleOrigin, src); err != nil {
			t.Errorf("%s left the code unusable: %v", o, err)
		}
	}
	cookie, err := r.redeem(r.issue(t), ipOrigin, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.svc.Resolve(context.Background(), cookie, ipOrigin); !ok {
		t.Error("the session does not resolve at its own origin")
	}
	if _, ok := r.svc.Resolve(context.Background(), cookie, consoleOrigin); ok {
		t.Error("the address's session resolves at the console's name")
	}
	if _, ok := r.svc.Resolve(context.Background(), secret.Value{}, ipOrigin); ok {
		t.Error("an empty cookie resolves")
	}
}
