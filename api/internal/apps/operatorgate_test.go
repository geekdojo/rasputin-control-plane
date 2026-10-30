package apps

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

const opGateAppID = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"

// gateSentinel is a value no error or log record may ever hold.
const gateSentinel = "S-780-sentinel-value"

type fakeAppReader struct {
	app   *App
	err   error
	calls int
}

func (f *fakeAppReader) Get(_ context.Context, id string) (*App, error) {
	f.calls++
	return f.app, f.err
}

// fakeSecretReader answers each name from set (a value), err (a failure) or,
// absent from both, secretstore.ErrNotFound. Every value it hands out is kept
// so a test can check it was destroyed.
type fakeSecretReader struct {
	set    map[string]bool
	err    error
	reads  []string
	actors []secrets.Actor
	given  []secret.Value
}

func (f *fakeSecretReader) Read(_ context.Context, a secrets.Actor, r secrets.Ref) (secrets.Secret, error) {
	f.reads = append(f.reads, r.String())
	f.actors = append(f.actors, a)
	v := secret.New([]byte(gateSentinel))
	f.given = append(f.given, v)
	if f.err != nil {
		// A value alongside the error, which the gate must neither use nor leak.
		return secrets.Secret{Value: v}, f.err
	}
	for name := range f.set {
		if strings.HasSuffix(r.String(), "/"+name) {
			return secrets.Secret{Value: v, Version: 1}, nil
		}
	}
	return secrets.Secret{}, &secretstore.Error{Op: "read", Kind: secretstore.ErrNotFound}
}

type fakeNext struct {
	calls   int
	appID   string
	compose string
	env     map[string]secret.Value
	err     error
}

func (f *fakeNext) ResolveCompose(_ context.Context, appID, compose string) (secret.Value, map[string]secret.Value, error) {
	f.calls++
	f.appID, f.compose = appID, compose
	if f.err != nil {
		return secret.Value{}, nil, f.err
	}
	return secret.New([]byte("resolved")), f.env, nil
}

const gateCompose = "services:\n  app:\n    environment:\n      FEED: ${secret:feed-key}\n      MAP: ${secret:map-key}\n      DB: ${secret:db-password}\n"

func gateApp() *App {
	return &App{ID: opGateAppID, TargetNode: "n1", OperatorSecrets: []tileschema.OperatorSecret{
		{Name: "feed-key", Label: "Feed API key"},
		{Name: "map-key", Label: "Map token"},
	}}
}

type gateRig struct {
	gate *OperatorSecretGate
	apps *fakeAppReader
	sec  *fakeSecretReader
	next *fakeNext
	rec  *logkittest.Recorder
}

func newGateRig(t *testing.T, app *App, sec *fakeSecretReader) *gateRig {
	t.Helper()
	log, rec := logkittest.New()
	r := &gateRig{apps: &fakeAppReader{app: app}, sec: sec, next: &fakeNext{}, rec: rec}
	g, err := NewOperatorSecretGate(OperatorSecretGateDeps{Next: r.next, Apps: r.apps, Secrets: r.sec, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.gate = g
	return r
}

func opJobCtx() context.Context { return jobs.ContextWithJobID(context.Background(), "job-780") }

// codeOf is the refusal's stable code, or "".
func opCodeOf(err error) string {
	var c codedRefusal
	if errors.As(err, &c) {
		return c.Code()
	}
	return ""
}

func opAttr(t *testing.T, r slog.Record, key string) string {
	t.Helper()
	v, ok := logkittest.Attr(r, key)
	if !ok {
		t.Errorf("log record %q has no %s", r.Message, key)
	}
	return v
}

// TC-780-10: two declared names, both in the compose, both unset. The deploy
// is refused with the owner's sentence and code, Next (the deriving source)
// is never called, and one WARN record carries the correlation fields.
func TestOperatorSecretGateRefusesUnsetNames(t *testing.T) {
	r := newGateRig(t, gateApp(), &fakeSecretReader{})
	v, env, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, gateCompose)
	if err == nil {
		t.Fatal("a compose using unset operator secrets was resolved")
	}
	if v.Len() != 0 || env != nil {
		t.Error("a refusal returned a compose or a value map")
	}
	if c := opCodeOf(err); c != CodeOperatorSecretUnset {
		t.Errorf("code %q, want %q", c, CodeOperatorSecretUnset)
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "This app") || !strings.HasSuffix(msg, ".") {
		t.Errorf("not a sentence: %q", msg)
	}
	for _, want := range []string{"Feed API key (feed-key)", "Map token (map-key)", "was not deployed",
		"running containers are unchanged", "Set them, then deploy the app again", CodeOperatorSecretUnset} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal %q does not say %q", msg, want)
		}
	}
	if strings.Contains(msg, "db-password") {
		t.Errorf("the refusal lists a derived secret: %q", msg)
	}
	if r.next.calls != 0 {
		t.Fatalf("Next was called %d time(s): the declared name would be derived", r.next.calls)
	}
	recs := r.rec.Matching(slog.LevelWarn, "operator secret is not set")
	if len(recs) != 1 {
		t.Fatalf("%d WARN records, want 1:\n%s", len(recs), r.rec.Text())
	}
	rec := recs[0]
	if got := opAttr(t, rec, "event"); got != "apps.operator_secret_unset" {
		t.Errorf("event %q", got)
	}
	if got := opAttr(t, rec, "component"); got != "apps" {
		t.Errorf("component %q", got)
	}
	if got := opAttr(t, rec, "app_id"); got != opGateAppID {
		t.Errorf("app_id %q", got)
	}
	if got := opAttr(t, rec, "job_id"); got != "job-780" {
		t.Errorf("job_id %q", got)
	}
	if got := opAttr(t, rec, "names"); !strings.Contains(got, "feed-key") || !strings.Contains(got, "map-key") {
		t.Errorf("names %q do not list both", got)
	}
	// The presence check reads as the app's own deploy job on its target node.
	for _, a := range r.sec.actors {
		if a != secrets.DeployActor(opGateAppID, "n1") {
			t.Errorf("read as %+v, want the app's deploy actor", a)
		}
	}
}

// TC-780-10, the other half of "never derived": one set and one unset is
// still a refusal, naming only the unset one.
func TestOperatorSecretGateRefusesWhenOnlySomeAreSet(t *testing.T) {
	r := newGateRig(t, gateApp(), &fakeSecretReader{set: map[string]bool{"feed-key": true}})
	_, _, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, gateCompose)
	if opCodeOf(err) != CodeOperatorSecretUnset || r.next.calls != 0 {
		t.Fatalf("err %v, next calls %d; want the unset refusal and no Next call", err, r.next.calls)
	}
	if strings.Contains(err.Error(), "feed-key") || !strings.Contains(err.Error(), "map-key") {
		t.Errorf("the refusal lists the wrong names: %q", err)
	}
}

// TC-780-11: every declared value set, so Next is called once with the same
// app and compose, its answer is returned unchanged, and each value read for
// the check is destroyed.
func TestOperatorSecretGatePassesWhenEverythingIsSet(t *testing.T) {
	r := newGateRig(t, gateApp(), &fakeSecretReader{set: map[string]bool{"feed-key": true, "map-key": true}})
	want := map[string]secret.Value{"RASPUTIN_SECRET_FEED_KEY": secret.New([]byte("x"))}
	r.next.env = want
	v, env, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, gateCompose)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if r.next.calls != 1 || r.next.appID != opGateAppID || r.next.compose != gateCompose {
		t.Fatalf("Next got %d call(s) with (%q, %q)", r.next.calls, r.next.appID, r.next.compose)
	}
	if string(v.Reveal()) != "resolved" || len(env) != 1 || env["RASPUTIN_SECRET_FEED_KEY"].Len() != 1 {
		t.Error("Next's compose or map was not returned unchanged")
	}
	if len(r.sec.given) != 2 {
		t.Fatalf("%d reads, want 2 (one per declared name in the compose)", len(r.sec.given))
	}
	for i, g := range r.sec.given {
		if g.Len() != 0 {
			t.Errorf("value %d read for the presence check was not destroyed", i)
		}
	}
}

// TC-780-12: a presence read that fails refuses with the store-unavailable
// code, never calls Next, leaks neither the store's text nor a value into the
// error, keeps the store error reachable through errors.Is, and logs the
// correlation fields.
func TestOperatorSecretGateFailsClosedOnAFailedRead(t *testing.T) {
	const storeText = "S-780-store-says-no"
	for _, c := range []struct {
		name  string
		err   error
		kinds []error
	}{
		{"disabled", &secretstore.Error{Op: "read", Kind: secretstore.ErrDisabled, StoreMessages: []string{storeText}},
			[]error{secretstore.ErrDisabled}},
		{"unreachable, timed out", &secretstore.Error{Op: "read", Kind: secretstore.ErrUnreachable,
			Err: fmt.Errorf("%s: %w", storeText, context.DeadlineExceeded)},
			[]error{secretstore.ErrUnreachable, context.DeadlineExceeded}},
		{"sealed", fmt.Errorf("secrets: read: %w", &secretstore.Error{Op: "read", Status: 503, Kind: secretstore.ErrSealed,
			StoreMessages: []string{storeText}}), []error{secretstore.ErrSealed}},
		{"forbidden", fmt.Errorf("%w: the node is not the app's target node", secrets.ErrForbidden),
			[]error{secrets.ErrForbidden}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newGateRig(t, gateApp(), &fakeSecretReader{err: c.err})
			_, env, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, gateCompose)
			if err == nil || env != nil {
				t.Fatal("a failed presence check was not a refusal")
			}
			if code := opCodeOf(err); code != appsecret.CodeStoreUnavailable {
				t.Errorf("code %q, want %q", code, appsecret.CodeStoreUnavailable)
			}
			if r.next.calls != 0 {
				t.Errorf("Next was called %d time(s) after a failed check", r.next.calls)
			}
			if strings.Contains(err.Error(), storeText) || strings.Contains(err.Error(), gateSentinel) {
				t.Errorf("the refusal carries the store's text or a value: %q", err)
			}
			if strings.Contains(r.rec.Text(), gateSentinel) {
				t.Error("a value reached the log")
			}
			for _, k := range c.kinds {
				if !errors.Is(err, k) {
					t.Errorf("errors.Is(refusal, %v) is false: the refusal does not unwrap to the store error", k)
				}
			}
			for i, g := range r.sec.given {
				if g.Len() != 0 {
					t.Errorf("value %d returned beside the error was not destroyed", i)
				}
			}
			recs := r.rec.Matching(slog.LevelWarn, "could not be checked")
			if len(recs) != 1 {
				t.Fatalf("%d WARN records, want 1:\n%s", len(recs), r.rec.Text())
			}
			rec := recs[0]
			if got := opAttr(t, rec, "event"); got != "apps.operator_secret_check_failed" {
				t.Errorf("event %q", got)
			}
			if got := opAttr(t, rec, "component"); got != "apps" {
				t.Errorf("component %q", got)
			}
			if got := opAttr(t, rec, "app_id"); got != opGateAppID {
				t.Errorf("app_id %q", got)
			}
			if got := opAttr(t, rec, "ref"); got != "apps/"+opGateAppID+"/feed-key" {
				t.Errorf("ref %q", got)
			}
			if got := opAttr(t, rec, "job_id"); got != "job-780" {
				t.Errorf("job_id %q", got)
			}
		})
	}
}

// TC-780-13: the gate reads only what it must.
func TestOperatorSecretGateReadsOnlyWhatItMust(t *testing.T) {
	t.Run("no token: no Get, no Read, Next called", func(t *testing.T) {
		r := newGateRig(t, gateApp(), &fakeSecretReader{})
		if _, _, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, "services: {}\n"); err != nil {
			t.Fatal(err)
		}
		if r.apps.calls != 0 || len(r.sec.reads) != 0 || r.next.calls != 1 {
			t.Errorf("Get %d, Read %d, Next %d; want 0, 0, 1", r.apps.calls, len(r.sec.reads), r.next.calls)
		}
	})
	t.Run("tokens, no declarations: no Read, Next called", func(t *testing.T) {
		r := newGateRig(t, &App{ID: opGateAppID, TargetNode: "n1"}, &fakeSecretReader{})
		if _, _, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, gateCompose); err != nil {
			t.Fatal(err)
		}
		if len(r.sec.reads) != 0 || r.next.calls != 1 {
			t.Errorf("Read %d, Next %d; want 0, 1", len(r.sec.reads), r.next.calls)
		}
	})
	t.Run("a declared name the compose does not use is not read", func(t *testing.T) {
		app := &App{ID: opGateAppID, TargetNode: "n1", OperatorSecrets: []tileschema.OperatorSecret{{Name: "x", Label: "X"}}}
		r := newGateRig(t, app, &fakeSecretReader{})
		if _, _, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, gateCompose); err != nil {
			t.Fatal(err)
		}
		if len(r.sec.reads) != 0 || r.next.calls != 1 {
			t.Errorf("reads %v, Next %d; want none, 1", r.sec.reads, r.next.calls)
		}
	})
	t.Run("a malformed token goes to Next, whose refusal is returned", func(t *testing.T) {
		r := newGateRig(t, gateApp(), &fakeSecretReader{})
		r.next.err = errors.New("next refused the malformed token")
		_, _, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, "A: ${secret:BAD}\n")
		if err == nil || err.Error() != "next refused the malformed token" {
			t.Errorf("err %v, want Next's refusal unchanged", err)
		}
		if r.apps.calls != 0 || len(r.sec.reads) != 0 || r.next.calls != 1 {
			t.Errorf("Get %d, Read %d, Next %d; want 0, 0, 1", r.apps.calls, len(r.sec.reads), r.next.calls)
		}
	})
}

// TC-780-14: the app cannot be read, or does not exist.
func TestOperatorSecretGateRefusesWhenTheAppCannotBeRead(t *testing.T) {
	for name, apps := range map[string]*fakeAppReader{
		"Get fails":   {err: errors.New("database is locked")},
		"app missing": {},
	} {
		t.Run(name, func(t *testing.T) {
			r := newGateRig(t, nil, &fakeSecretReader{})
			r.gate.apps = apps
			_, _, err := r.gate.ResolveCompose(opJobCtx(), opGateAppID, gateCompose)
			if err == nil || !strings.Contains(err.Error(), opGateAppID) {
				t.Fatalf("err %v, want a refusal naming the app", err)
			}
			if len(r.sec.reads) != 0 || r.next.calls != 0 {
				t.Errorf("Read %d, Next %d; want 0, 0", len(r.sec.reads), r.next.calls)
			}
		})
	}
}

// TC-780-15: the constructor refuses a nil collaborator, naming it.
func TestNewOperatorSecretGateRefusesANilDependency(t *testing.T) {
	full := func() OperatorSecretGateDeps {
		return OperatorSecretGateDeps{Next: &fakeNext{}, Apps: &fakeAppReader{}, Secrets: &fakeSecretReader{}, Log: slog.New(slog.DiscardHandler)}
	}
	for field, clear := range map[string]func(*OperatorSecretGateDeps){
		"Next":    func(d *OperatorSecretGateDeps) { d.Next = nil },
		"Apps":    func(d *OperatorSecretGateDeps) { d.Apps = nil },
		"Secrets": func(d *OperatorSecretGateDeps) { d.Secrets = nil },
		"Log":     func(d *OperatorSecretGateDeps) { d.Log = nil },
	} {
		d := full()
		clear(&d)
		g, err := NewOperatorSecretGate(d)
		if err == nil || g != nil || !strings.Contains(err.Error(), "Deps."+field) {
			t.Errorf("nil %s: got (%v, %v), want an error naming it", field, g, err)
		}
	}
	if _, err := NewOperatorSecretGate(full()); err != nil {
		t.Errorf("a full set of deps was refused: %v", err)
	}
}
