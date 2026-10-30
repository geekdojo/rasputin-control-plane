package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

const opSvcAppID = "01J9ZK3Q0M8X7Y6W5V4T3S2R3A"

// opLog is one ordered log the fake writer and the fake ref store share.
type opLog struct{ calls []string }

type fakeOpWriter struct {
	log        *opLog
	createErr  error
	replaceErr error
	actors     []secrets.Actor
	values     []string
	failIfUsed *testing.T
}

func (f *fakeOpWriter) Create(_ context.Context, a secrets.Actor, r secrets.Ref, v secret.Value) (int, error) {
	if f.failIfUsed != nil {
		f.failIfUsed.Error("the secrets service was called")
	}
	f.log.calls = append(f.log.calls, "create "+r.String())
	f.actors = append(f.actors, a)
	f.values = append(f.values, string(v.Reveal()))
	return 1, f.createErr
}

func (f *fakeOpWriter) Replace(_ context.Context, a secrets.Actor, r secrets.Ref, v secret.Value) (int, error) {
	if f.failIfUsed != nil {
		f.failIfUsed.Error("the secrets service was called")
	}
	f.log.calls = append(f.log.calls, "replace "+r.String())
	f.actors = append(f.actors, a)
	f.values = append(f.values, string(v.Reveal()))
	return 2, f.replaceErr
}

func (f *fakeOpWriter) writes() int {
	n := 0
	for _, c := range f.log.calls {
		if strings.HasPrefix(c, "create ") || strings.HasPrefix(c, "replace ") {
			n++
		}
	}
	return n
}

type fakeRefStore struct {
	log       *opLog
	refs      []SecretRef
	recordErr error
	listErr   error
}

func (f *fakeRefStore) RecordSecretRef(_ context.Context, appID, name string) error {
	f.log.calls = append(f.log.calls, "ref "+appID+"/"+name)
	if f.recordErr != nil {
		return f.recordErr
	}
	f.refs = append(f.refs, SecretRef{AppID: appID, Name: name})
	return nil
}

func (f *fakeRefStore) ListSecretRefs(context.Context) ([]SecretRef, error) {
	return f.refs, f.listErr
}

func (f *fakeRefStore) recorded() int {
	n := 0
	for _, c := range f.log.calls {
		if strings.HasPrefix(c, "ref ") {
			n++
		}
	}
	return n
}

func opSvcApp() *App {
	no := false
	return &App{ID: opSvcAppID, TargetNode: "n1", OperatorSecrets: []tileschema.OperatorSecret{
		{Name: "feed-key", Label: "Feed API key"},
		{Name: "opt-key", Label: "Optional key", Required: &no},
	}}
}

type opSvcRig struct {
	svc  *OperatorSecrets
	apps *fakeAppReader
	w    *fakeOpWriter
	refs *fakeRefStore
	log  *opLog
}

func newOpSvcRig(t *testing.T, app *App) *opSvcRig {
	t.Helper()
	l := &opLog{}
	r := &opSvcRig{apps: &fakeAppReader{app: app}, w: &fakeOpWriter{log: l}, refs: &fakeRefStore{log: l}, log: l}
	svc, err := NewOperatorSecrets(OperatorSecretsDeps{Apps: r.apps, Secrets: r.w, Refs: r.refs, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

// TC-604-06: Set refuses an undeclared name, an empty value and an absent app
// with no write and no ref; writes an unset name as Create then ref; replaces
// on ErrExists; returns ErrConflict and a store error with no ref.
func TestOperatorSecretsSet(t *testing.T) {
	ctx := context.Background()
	feedRef := "apps/" + opSvcAppID + "/feed-key"

	t.Run("refusals before any write", func(t *testing.T) {
		for _, c := range []struct {
			why   string
			app   *App
			name  string
			value string
			want  error
		}{
			{"undeclared name", opSvcApp(), "db-password", "v", ErrOperatorSecretNotDeclared},
			{"empty value", opSvcApp(), "feed-key", "", ErrOperatorSecretEmpty},
			{"absent app", nil, "feed-key", "v", ErrAppNotFound},
		} {
			t.Run(c.why, func(t *testing.T) {
				r := newOpSvcRig(t, c.app)
				err := r.svc.Set(ctx, "alice", opSvcAppID, c.name, secret.New([]byte(c.value)))
				if !errors.Is(err, c.want) {
					t.Fatalf("Set = %v, want %v", err, c.want)
				}
				if r.w.writes() != 0 || r.refs.recorded() != 0 {
					t.Fatalf("call log %v, want no write and no ref", r.log.calls)
				}
			})
		}
	})
	t.Run("an unset name is created, then recorded", func(t *testing.T) {
		r := newOpSvcRig(t, opSvcApp())
		if err := r.svc.Set(ctx, "alice", opSvcAppID, "feed-key", secret.New([]byte("v1"))); err != nil {
			t.Fatal(err)
		}
		want := []string{"create " + feedRef, "ref " + opSvcAppID + "/feed-key"}
		if !reflect.DeepEqual(r.log.calls, want) {
			t.Fatalf("call log %v, want %v", r.log.calls, want)
		}
		if r.w.actors[0] != secrets.OperatorActor("alice") || r.w.values[0] != "v1" {
			t.Fatal("Create was not given OperatorActor(user) and the value")
		}
	})
	t.Run("a set name is replaced, then recorded", func(t *testing.T) {
		r := newOpSvcRig(t, opSvcApp())
		r.w.createErr = fmt.Errorf("%w: %s", secrets.ErrExists, feedRef)
		if err := r.svc.Set(ctx, "alice", opSvcAppID, "feed-key", secret.New([]byte("v2"))); err != nil {
			t.Fatal(err)
		}
		want := []string{"create " + feedRef, "replace " + feedRef, "ref " + opSvcAppID + "/feed-key"}
		if !reflect.DeepEqual(r.log.calls, want) {
			t.Fatalf("call log %v, want %v", r.log.calls, want)
		}
	})
	t.Run("a failed write records no ref", func(t *testing.T) {
		for _, c := range []struct {
			why        string
			createErr  error
			replaceErr error
			want       error
		}{
			{"conflict", fmt.Errorf("%w: x", secrets.ErrExists), fmt.Errorf("%w: x", secrets.ErrConflict), secrets.ErrConflict},
			{"store error", &secretstore.Error{Op: "write", Kind: secretstore.ErrSealed}, nil, secretstore.ErrSealed},
		} {
			t.Run(c.why, func(t *testing.T) {
				r := newOpSvcRig(t, opSvcApp())
				r.w.createErr, r.w.replaceErr = c.createErr, c.replaceErr
				err := r.svc.Set(ctx, "alice", opSvcAppID, "feed-key", secret.New([]byte("v")))
				if !errors.Is(err, c.want) {
					t.Fatalf("Set = %v, want %v", err, c.want)
				}
				if r.refs.recorded() != 0 {
					t.Fatalf("a ref was recorded after the write failed: %v", r.log.calls)
				}
			})
		}
	})
	t.Run("a failed ref record is returned", func(t *testing.T) {
		r := newOpSvcRig(t, opSvcApp())
		boom := errors.New("database is locked")
		r.refs.recordErr = boom
		if err := r.svc.Set(ctx, "alice", opSvcAppID, "feed-key", secret.New([]byte("v"))); !errors.Is(err, boom) {
			t.Fatalf("Set = %v, want the record error", err)
		}
	})
	t.Run("an unreadable app", func(t *testing.T) {
		r := newOpSvcRig(t, opSvcApp())
		boom := errors.New("apps table unreadable")
		r.apps.err = boom
		if err := r.svc.Set(ctx, "alice", opSvcAppID, "feed-key", secret.New([]byte("v"))); !errors.Is(err, boom) || r.w.writes() != 0 {
			t.Fatalf("Set = %v with %d write(s), want the read error and none", err, r.w.writes())
		}
	})
	t.Run("nil dependencies", func(t *testing.T) {
		l := &opLog{}
		full := OperatorSecretsDeps{Apps: &fakeAppReader{}, Secrets: &fakeOpWriter{log: l}, Refs: &fakeRefStore{log: l}, Log: slog.New(slog.DiscardHandler)}
		for name, clear := range map[string]func(*OperatorSecretsDeps){
			"Apps":    func(d *OperatorSecretsDeps) { d.Apps = nil },
			"Secrets": func(d *OperatorSecretsDeps) { d.Secrets = nil },
			"Refs":    func(d *OperatorSecretsDeps) { d.Refs = nil },
			"Log":     func(d *OperatorSecretsDeps) { d.Log = nil },
		} {
			d := full
			clear(&d)
			if s, err := NewOperatorSecrets(d); err == nil || s != nil {
				t.Errorf("nil %s: %v, %v; want an error", name, s, err)
			}
		}
	})
}

// TC-604-07: Status lists each declaration with label, required and set, set
// exactly for recorded refs, with no secrets-service call; an absent app is
// not found.
func TestOperatorSecretsStatus(t *testing.T) {
	ctx := context.Background()
	r := newOpSvcRig(t, opSvcApp())
	r.w.failIfUsed = t
	r.refs.refs = []SecretRef{
		{AppID: opSvcAppID, Name: "feed-key"},
		{AppID: "01J9ZK3Q0M8X7Y6W5V4T3S2R3B", Name: "opt-key"}, // another app's
	}
	got, err := r.svc.Status(ctx, opSvcAppID)
	if err != nil {
		t.Fatal(err)
	}
	want := []OperatorSecretStatus{
		{Name: "feed-key", Label: "Feed API key", Required: true, Set: true},
		{Name: "opt-key", Label: "Optional key", Required: false, Set: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Status = %+v, want %+v", got, want)
	}
	b, err := json.Marshal(got[0])
	if err != nil || string(b) != `{"name":"feed-key","label":"Feed API key","required":true,"set":true}` {
		t.Fatalf("JSON %s, %v", b, err)
	}

	absent := newOpSvcRig(t, nil)
	absent.w.failIfUsed = t
	if _, err := absent.svc.Status(ctx, opSvcAppID); !errors.Is(err, ErrAppNotFound) {
		t.Fatalf("Status of an absent app = %v, want ErrAppNotFound", err)
	}
	boom := errors.New("refs unreadable")
	r.refs.listErr = boom
	if _, err := r.svc.Status(ctx, opSvcAppID); !errors.Is(err, boom) {
		t.Fatalf("Status with unreadable refs = %v, want the error", err)
	}
}
