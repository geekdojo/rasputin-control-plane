package secrets_test

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

func keyRef(t *testing.T, appID, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.AppKey(appID, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// keyOp runs one key operation by name.
func keyOp(rg *rig, name string, a secrets.Actor, r secrets.Ref) error {
	ctx := rg.t.Context()
	switch name {
	case "key.create":
		return rg.svc.CreateKey(ctx, a, r)
	case "key.encrypt":
		v, err := rg.svc.Encrypt(ctx, a, r, val(sentinel))
		v.Destroy()
		return err
	case "key.decrypt":
		v, err := rg.svc.Decrypt(ctx, a, r, val("vault:v1:ct"))
		v.Destroy()
		return err
	case "key.destroy":
		return rg.svc.DestroyKey(ctx, a, r)
	}
	rg.t.Fatalf("unknown key op %s", name)
	return nil
}

var keyOps = []string{"key.create", "key.encrypt", "key.decrypt", "key.destroy"}

// TC-1084-07: AppKey refuses what AppSecret refuses, names the key
// transit:app-<ID>-<name>, and distinct (app, name) pairs give distinct key
// names.
func TestAppKey(t *testing.T) {
	r := keyRef(t, appX, "wrap")
	if got, want := r.String(), "transit:app-"+appX+"-wrap"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	for _, id := range []string{strings.ToLower(appX), appX[:25], "01JABCDEFGHJKMNPQRSTVWXYZU", ""} {
		if r, err := secrets.AppKey(id, "k"); !errors.Is(err, secrets.ErrInvalidRef) || r != (secrets.Ref{}) {
			t.Errorf("AppKey(%q, k) = %q, %v; want ErrInvalidRef", id, r, err)
		}
	}
	for _, name := range []string{"", "Wrap", strings.Repeat("a", 64), "a/b", "a.b", "-a"} {
		if r, err := secrets.AppKey(appX, name); !errors.Is(err, secrets.ErrInvalidRef) || r != (secrets.Ref{}) {
			t.Errorf("AppKey(appX, %q) = %q, %v; want ErrInvalidRef", name, r, err)
		}
	}
	seen := map[string]string{}
	for _, id := range []string{appX, appY} {
		for _, name := range []string{"a", "a-b", "b", "wrap", "x-" + strings.ToLower(appY[:4])} {
			s := keyRef(t, id, name).String()
			if prev, dup := seen[s]; dup {
				t.Errorf("%s/%s and %s give the same key %s", id, name, prev, s)
			}
			seen[s] = id + "/" + name
		}
	}
}

// TC-1084-08: app A at runtime on its node cannot create, use or destroy app
// B's key: ErrForbidden, no store call, one secrets.denied WARN naming the
// reason.
func TestService_KeyOfAnotherApp(t *testing.T) {
	for _, o := range keyOps {
		rg := newRig(t, &fakeRepo{}, nil)
		err := keyOp(rg, o, secrets.RuntimeActor(appX, nodeN), keyRef(t, appY, "x"))
		if !errors.Is(err, secrets.ErrForbidden) {
			t.Errorf("%s = %v, want ErrForbidden", o, err)
		}
		if n := len(rg.keys.seen()) + rg.repo.callCount(); n != 0 {
			t.Errorf("%s: %d store calls on a refusal", o, n)
		}
		recs := rg.rec.Matching(slog.LevelWarn, "secret access denied")
		if len(recs) != 1 {
			t.Fatalf("%s: %d secrets.denied records, want 1", o, len(recs))
		}
		if reason, _ := logkittest.Attr(recs[0], "reason"); reason != "the secret belongs to another app" {
			t.Errorf("%s: reason %q", o, reason)
		}
		rg.assertNoSentinel()
	}
}

// TC-1084-09: the node, existence and actor rules, each refused before any
// store call; an operator's destroy is allowed with the app gone; the app's
// own ops from its node reach the key in the app-keys mount.
func TestService_KeyScope(t *testing.T) {
	t.Run("own key, own node", func(t *testing.T) {
		rg := newRig(t, &fakeRepo{}, nil)
		for _, o := range keyOps {
			if err := keyOp(rg, o, secrets.RuntimeActor(appX, nodeN), keyRef(t, appX, "wrap")); err != nil {
				t.Errorf("%s = %v, want allowed", o, err)
			}
		}
		k := storepolicy.AppKeysMount + "/keys/app-" + appX + "-wrap"
		want := []string{"create " + k, "encrypt " + k, "decrypt " + k, "destroy " + k}
		if got := rg.keys.seen(); !slices.Equal(got, want) {
			t.Errorf("store calls %v, want %v", got, want)
		}
		if n := len(rg.rec.Matching(slog.LevelInfo, "app key")); n != 2 {
			t.Errorf("%d INFO records, want 2 (created and destroyed)", n)
		}
		rg.assertNoSentinel()
	})
	t.Run("operator destroy with the app gone", func(t *testing.T) {
		rg := newRig(t, &fakeRepo{}, fakeApps{nodes: map[string]string{}})
		if err := keyOp(rg, "key.destroy", secrets.OperatorActor("u1"), keyRef(t, appX, "wrap")); err != nil {
			t.Errorf("operator destroy = %v, want allowed", err)
		}
	})
	for _, tc := range []struct {
		name  string
		actor secrets.Actor
		ops   []string
		apps  secrets.AppTargets
	}{
		{"another node", secrets.RuntimeActor(appX, nodeM), keyOps, nil},
		{"the app is gone", secrets.RuntimeActor(appX, nodeN), keyOps, fakeApps{nodes: map[string]string{}}},
		{"operator create, encrypt, decrypt", secrets.OperatorActor("u1"), keyOps[:3], nil},
		{"deploy actor", secrets.DeployActor(appX, nodeN), keyOps, nil},
		{"check actor", secrets.CheckActor(), keyOps, nil},
		{"no actor", secrets.Actor{}, keyOps, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, o := range tc.ops {
				rg := newRig(t, &fakeRepo{}, tc.apps)
				if err := keyOp(rg, o, tc.actor, keyRef(t, appX, "wrap")); !errors.Is(err, secrets.ErrForbidden) {
					t.Errorf("%s = %v, want ErrForbidden", o, err)
				}
				if n := len(rg.keys.seen()); n != 0 {
					t.Errorf("%s: %d store calls on a refusal", o, n)
				}
			}
		})
	}
	t.Run("a lookup error refuses", func(t *testing.T) {
		rg := newRig(t, &fakeRepo{}, fakeApps{err: errors.New("database is locked")})
		for _, o := range keyOps {
			if err := keyOp(rg, o, secrets.RuntimeActor(appX, nodeN), keyRef(t, appX, "wrap")); err == nil {
				t.Errorf("%s allowed on a failed lookup", o)
			}
		}
		if n := len(rg.keys.seen()); n != 0 {
			t.Errorf("%d store calls", n)
		}
	})
	t.Run("store errors are wrapped; an absent key's destroy is done", func(t *testing.T) {
		rg := newRig(t, &fakeRepo{}, nil)
		rg.keys.err = &secretstore.Error{Op: "transit_destroy", Kind: secretstore.ErrNotFound}
		if err := keyOp(rg, "key.destroy", secrets.RuntimeActor(appX, nodeN), keyRef(t, appX, "wrap")); err != nil {
			t.Errorf("destroy of an absent key = %v, want nil", err)
		}
		rg.keys.err = &secretstore.Error{Op: "transit_x", Kind: secretstore.ErrUnreachable}
		for _, o := range keyOps {
			if err := keyOp(rg, o, secrets.RuntimeActor(appX, nodeN), keyRef(t, appX, "wrap")); !errors.Is(err, secretstore.ErrUnreachable) {
				t.Errorf("%s = %v, want ErrUnreachable", o, err)
			}
		}
	})
}

// TC-1084-10: a key op never takes a kv reference, and a kv op never takes a
// key: each is refused before any store or repository call.
func TestService_KeyAndKVNeverCross(t *testing.T) {
	for name, ref := range map[string]secrets.Ref{
		"pushed secret":  appRef(t, appX, "k"),
		"runtime secret": runtimeRef(t, appX, "k"),
		"device secret":  deviceRef(t, "printer", "k"),
	} {
		for _, o := range keyOps {
			for _, a := range []secrets.Actor{secrets.RuntimeActor(appX, nodeN), secrets.OperatorActor("u1")} {
				rg := newRig(t, &fakeRepo{}, nil)
				if err := keyOp(rg, o, a, ref); !errors.Is(err, secrets.ErrForbidden) {
					t.Errorf("%s on a %s = %v, want ErrForbidden", o, name, err)
				}
				if n := len(rg.keys.seen()) + rg.repo.callCount(); n != 0 {
					t.Errorf("%s on a %s: %d calls", o, name, n)
				}
			}
		}
	}
	for _, o := range []string{"read", "create", "replace", "delete", "exists"} {
		for _, a := range []secrets.Actor{secrets.RuntimeActor(appX, nodeN), secrets.OperatorActor("u1"), secrets.DeployActor(appX, nodeN), secrets.CheckActor()} {
			rg := newRig(t, &fakeRepo{}, nil)
			if err := op(rg, o, a, keyRef(t, appX, "wrap")); !errors.Is(err, secrets.ErrForbidden) {
				t.Errorf("%s on a key = %v, want ErrForbidden", o, err)
			}
			if n := len(rg.keys.seen()) + rg.repo.callCount(); n != 0 {
				t.Errorf("%s on a key: %d calls", o, n)
			}
		}
	}
}

// TC-1084-11 (service side): behind a key session over the switched-off
// store, every key op returns ErrDisabled.
func TestService_KeysOnTheDisabledStore(t *testing.T) {
	log, _ := logkittest.New()
	sess, err := storesession.New(storesession.Config{Role: "rasputin-app-keys", Login: secretstore.Disabled{},
		Transit: secretstore.Disabled{}, Observer: nopObserver{}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secrets.NewService(secrets.Deps{Repo: mustRepo(t, &fakeStore{}), Transit: sess,
		Apps: fakeApps{nodes: map[string]string{appX: nodeN}}, Switch: &fakeSwitch{log: &fakeRepo{}}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	rg := &rig{t: t, svc: svc}
	for _, o := range keyOps {
		if err := keyOp(rg, o, secrets.RuntimeActor(appX, nodeN), keyRef(t, appX, "wrap")); !errors.Is(err, secretstore.ErrDisabled) {
			t.Errorf("%s = %v, want ErrDisabled", o, err)
		}
	}
}
