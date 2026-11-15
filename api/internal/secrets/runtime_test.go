package secrets_test

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-1081-13: AppRuntimeSecret builds apps/<ID>/_runtime/<name>, refuses what
// AppSecret refuses, and a pushed secret can never be named _runtime.
func TestAppRuntimeSecret(t *testing.T) {
	r, err := secrets.AppRuntimeSecret(appX, "session-key")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := r.String(), "apps/"+appX+"/_runtime/session-key"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	for _, id := range []string{strings.ToLower(appX), "not-a-ulid", ""} {
		if r, err := secrets.AppRuntimeSecret(id, "k"); !errors.Is(err, secrets.ErrInvalidRef) || r != (secrets.Ref{}) {
			t.Errorf("AppRuntimeSecret(%q, k) = %q, %v; want ErrInvalidRef", id, r, err)
		}
	}
	for _, name := range []string{"", "A", "_x", "a/b", "..", strings.Repeat("a", 64)} {
		if r, err := secrets.AppRuntimeSecret(appX, name); !errors.Is(err, secrets.ErrInvalidRef) || r != (secrets.Ref{}) {
			t.Errorf("AppRuntimeSecret(appX, %q) = %q, %v; want ErrInvalidRef", name, r, err)
		}
	}
	if _, err := secrets.AppSecret(appX, "_runtime"); !errors.Is(err, secrets.ErrInvalidRef) {
		t.Errorf("AppSecret(appX, _runtime) = %v; want ErrInvalidRef", err)
	}
}

func runtimeRef(t *testing.T, appID, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.AppRuntimeSecret(appID, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// op runs one operation by name.
func op(rg *rig, name string, a secrets.Actor, r secrets.Ref) error {
	ctx := rg.t.Context()
	switch name {
	case "read":
		_, err := rg.svc.Read(ctx, a, r)
		return err
	case "create":
		_, err := rg.svc.Create(ctx, a, r, val(sentinel))
		return err
	case "replace":
		_, err := rg.svc.Replace(ctx, a, r, val(sentinel))
		return err
	case "delete":
		return rg.svc.Delete(ctx, a, r)
	case "exists":
		_, err := rg.svc.Exists(ctx, a, r)
		return err
	}
	rg.t.Fatalf("unknown op %s", name)
	return nil
}

// TC-1081-14: the scope rule. A runtime actor uses its own runtime entries
// from its own node, and nothing else: not another app's, not from another
// node, not once the app is gone, never a pushed value, never Exists; a
// lookup error refuses. An operator only deletes a runtime entry, with the
// app gone or not. Deploy and check actors never reach one. Each refusal is
// one secrets.denied WARN and no repository call.
func TestService_RuntimeScope(t *testing.T) {
	all := []string{"read", "create", "replace", "delete"}

	t.Run("own entry, own node", func(t *testing.T) {
		repo, _ := mockRepo(t)
		rg := newRig(t, repo, nil)
		a := secrets.RuntimeActor(appX, nodeN)
		r := runtimeRef(t, appX, "k")
		for _, o := range []string{"create", "read", "replace", "delete"} {
			if err := op(rg, o, a, r); err != nil {
				t.Errorf("%s = %v, want allowed", o, err)
			}
		}
		rg.assertNoSentinel()
	})

	refused := []struct {
		name  string
		actor secrets.Actor
		ref   func(t *testing.T) secrets.Ref
		ops   []string
		apps  secrets.AppTargets
	}{
		{"another app's entry", secrets.RuntimeActor(appX, nodeN), func(t *testing.T) secrets.Ref { return runtimeRef(t, appY, "k") }, all, nil},
		{"another node", secrets.RuntimeActor(appX, nodeM), func(t *testing.T) secrets.Ref { return runtimeRef(t, appX, "k") }, all, nil},
		{"the app is gone", secrets.RuntimeActor(appX, nodeN), func(t *testing.T) secrets.Ref { return runtimeRef(t, appX, "k") }, all, fakeApps{nodes: map[string]string{}}},
		{"a pushed value", secrets.RuntimeActor(appX, nodeN), func(t *testing.T) secrets.Ref { return appRef(t, appX, "db-pass") }, all, nil},
		{"Exists", secrets.RuntimeActor(appX, nodeN), func(t *testing.T) secrets.Ref { return runtimeRef(t, appX, "k") }, []string{"exists"}, nil},
		{"operator read/create/replace", secrets.OperatorActor("u1"), func(t *testing.T) secrets.Ref { return runtimeRef(t, appX, "k") }, []string{"read", "create", "replace"}, nil},
		{"deploy actor", secrets.DeployActor(appX, nodeN), func(t *testing.T) secrets.Ref { return runtimeRef(t, appX, "k") }, all, nil},
		{"check actor", secrets.CheckActor(), func(t *testing.T) secrets.Ref { return runtimeRef(t, appX, "k") }, append([]string{"exists"}, all...), nil},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			for _, o := range tc.ops {
				rg := newRig(t, &fakeRepo{}, tc.apps)
				if err := op(rg, o, tc.actor, tc.ref(t)); !errors.Is(err, secrets.ErrForbidden) {
					t.Errorf("%s = %v, want ErrForbidden", o, err)
				}
				if n := rg.repo.callCount(); n != 0 {
					t.Errorf("%s: %d repository calls on a refusal", o, n)
				}
				if got := rg.rec.Matching(slog.LevelWarn, "secret access denied"); len(got) != 1 {
					t.Errorf("%s: %d secrets.denied records, want 1", o, len(got))
				} else if ev, _ := logkittest.Attr(got[0], "event"); ev != "secrets.denied" {
					t.Errorf("%s: event %q", o, ev)
				}
			}
		})
	}

	t.Run("a lookup error refuses", func(t *testing.T) {
		rg := newRig(t, &fakeRepo{}, fakeApps{err: errors.New("database is locked")})
		for _, o := range all {
			if err := op(rg, o, secrets.RuntimeActor(appX, nodeN), runtimeRef(t, appX, "k")); err == nil {
				t.Errorf("%s allowed on a failed lookup", o)
			}
		}
		if n := rg.repo.callCount(); n != 0 {
			t.Errorf("%d repository calls", n)
		}
	})

	t.Run("operator delete with the app gone", func(t *testing.T) {
		repo, _ := mockRepo(t)
		rg := newRig(t, repo, fakeApps{nodes: map[string]string{}})
		if err := op(rg, "delete", secrets.OperatorActor("u1"), runtimeRef(t, appX, "k")); err != nil {
			t.Errorf("operator delete = %v, want allowed", err)
		}
	})
}
