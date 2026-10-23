package secrets_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// versionErrRepo is a Repository whose metadata read fails with err.
type versionErrRepo struct {
	secrets.Repository
	err error
}

func (v versionErrRepo) CurrentVersion(context.Context, secrets.Ref) (int, error) { return 0, v.err }

// TC-800-15: Exists answers from metadata alone: present is (true, nil),
// absent (ErrNotFound) is (false, nil), and any other store failure is
// returned. Repository.Get is never called.
func TestService_Exists(t *testing.T) {
	ctx := context.Background()
	repo, _ := mockRepo(t)
	r := newRig(t, repo, nil)
	present, absent := appRef(t, appX, "db-pass"), appRef(t, appX, "api-key")
	if _, err := r.svc.Create(ctx, secrets.DeployActor(appX, nodeN), present, val(sentinel)); err != nil {
		t.Fatal(err)
	}
	gets := func() int {
		n := 0
		for _, c := range r.repo.calls {
			if c == "get" {
				n++
			}
		}
		return n
	}
	if ok, err := r.svc.Exists(ctx, secrets.CheckActor(), present); err != nil || !ok {
		t.Errorf("Exists(present) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := r.svc.Exists(ctx, secrets.CheckActor(), absent); err != nil || ok {
		t.Errorf("Exists(absent) = (%v, %v), want (false, nil)", ok, err)
	}
	storeErr := &secretstore.Error{Op: "versions", Kind: secretstore.ErrUnreachable}
	broken := newRig(t, versionErrRepo{Repository: repo, err: storeErr}, nil)
	ok, err := broken.svc.Exists(ctx, secrets.CheckActor(), present)
	if ok || !errors.Is(err, secretstore.ErrUnreachable) {
		t.Errorf("Exists(store down) = (%v, %v), want (false, ErrUnreachable)", ok, err)
	}
	if n := gets(); n != 0 {
		t.Errorf("Exists called Repository.Get %d time(s)", n)
	}
	r.assertNoSentinel()
}

// TC-800-16 (SEC-AUTHZ): the check actor may ask exists on an app secret and
// nothing else; nobody else may ask exists. Each refusal is ErrForbidden
// with one WARN secrets.denied record, and reaches no repository call.
func TestService_ExistsAuthorization(t *testing.T) {
	ctx := context.Background()
	repo, _ := mockRepo(t)
	app, dev := appRef(t, appX, "db-pass"), deviceRef(t, "bmc", "admin")
	check := secrets.CheckActor()
	type call func(r *rig) error
	exists := func(a secrets.Actor, ref secrets.Ref) call {
		return func(r *rig) error { _, err := r.svc.Exists(ctx, a, ref); return err }
	}
	for name, do := range map[string]call{
		"check exists on a device secret": exists(check, dev),
		"check read":                      func(r *rig) error { _, err := r.svc.Read(ctx, check, app); return err },
		"check create":                    func(r *rig) error { _, err := r.svc.Create(ctx, check, app, val("x")); return err },
		"check replace":                   func(r *rig) error { _, err := r.svc.Replace(ctx, check, app, val("x")); return err },
		"check delete":                    func(r *rig) error { return r.svc.Delete(ctx, check, app) },
		"operator exists":                 exists(secrets.OperatorActor("u1"), app),
		"deploy exists":                   exists(secrets.DeployActor(appX, nodeN), app),
		"zero actor exists":               exists(secrets.Actor{}, app),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, repo, nil)
			if err := do(r); !errors.Is(err, secrets.ErrForbidden) {
				t.Fatalf("err = %v, want ErrForbidden", err)
			}
			if n := len(r.rec.Matching(slog.LevelWarn, "secret access denied")); n != 1 {
				t.Errorf("%d secrets.denied record(s), want 1", n)
			}
			if n := r.repo.callCount(); n != 0 {
				t.Errorf("a refused call reached the repository %d time(s)", n)
			}
		})
	}
	t.Run("check exists on an app secret is allowed", func(t *testing.T) {
		r := newRig(t, repo, nil)
		if _, err := r.svc.Exists(ctx, check, app); err != nil {
			t.Fatalf("Exists = %v", err)
		}
		if n := len(r.rec.Matching(slog.LevelWarn, "secret access denied")); n != 0 {
			t.Errorf("%d denied record(s) for an allowed call", n)
		}
	})
}
