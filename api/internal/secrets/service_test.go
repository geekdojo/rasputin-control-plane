package secrets_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-761-05: a value the store's audit would write in clear (an RFC 3339
// time) and invalid UTF-8 are refused as ErrInvalidValue, and nothing is
// stored.
func TestService_RefusesUnauditableValues(t *testing.T) {
	repo, m := mockRepo(t)
	rg := newRig(t, repo, nil)
	r := appRef(t, appX, "db-pass")
	deploy := secrets.DeployActor(appX, nodeN)
	for name, v := range map[string]secret.Value{
		"an RFC 3339 time": val("2026-10-11T09:00:00Z"),
		"invalid UTF-8":    secret.New([]byte{0xff, 0xfe, 's'}),
	} {
		if _, err := rg.svc.Create(t.Context(), deploy, r, v); !errors.Is(err, secretstore.ErrInvalidValue) {
			t.Errorf("%s: Create = %v, want ErrInvalidValue", name, err)
		}
	}
	if _, err := m.Versions(t.Context(), secret.Value{}, mockPath(t, r)); !errors.Is(err, secretstore.ErrNotFound) {
		t.Errorf("Versions after the refused creates = %v, want ErrNotFound", err)
	}
}

// TC-761-06: a deploy job's read and create of another app's secret are
// ErrForbidden, with no repository call and one WARN per refusal.
func TestService_CrossAppDenied(t *testing.T) {
	repo, _ := mockRepo(t)
	rg := newRig(t, repo, nil)
	deploy := secrets.DeployActor(appX, nodeN)
	other := appRef(t, appY, "db-pass")
	if _, err := rg.svc.Read(t.Context(), deploy, other); !errors.Is(rg.keep(err), secrets.ErrForbidden) {
		t.Errorf("cross-app Read = %v, want ErrForbidden", err)
	}
	if got := len(rg.rec.AtLevel(slog.LevelWarn)); got != 1 {
		t.Errorf("after the read: %d WARN records, want 1", got)
	}
	if _, err := rg.svc.Create(t.Context(), deploy, other, val(sentinel)); !errors.Is(rg.keep(err), secrets.ErrForbidden) {
		t.Errorf("cross-app Create = %v, want ErrForbidden", err)
	}
	if got := len(rg.rec.AtLevel(slog.LevelWarn)); got != 2 {
		t.Errorf("after the create: %d WARN records, want 2", got)
	}
	if rg.repo.callCount() != 0 {
		t.Errorf("repository calls = %v, want none", rg.repo.calls)
	}
	rg.assertNoSentinel()
}

// TC-761-07: a deploy job for the wrong node, for an app that does not exist,
// or whose app lookup fails, is refused on Read and Create, and the
// repository is never called.
func TestService_DeployNodeAndLookup(t *testing.T) {
	r := appRef(t, appX, "db-pass")
	lookupErr := errors.New("database is locked")
	for _, tc := range []struct {
		name  string
		actor secrets.Actor
		apps  fakeApps
		want  error
	}{
		{"wrong node", secrets.DeployActor(appX, nodeM), fakeApps{nodes: map[string]string{appX: nodeN}}, secrets.ErrForbidden},
		{"absent app", secrets.DeployActor(appX, nodeN), fakeApps{nodes: map[string]string{}}, secrets.ErrForbidden},
		{"failed lookup", secrets.DeployActor(appX, nodeN), fakeApps{err: lookupErr}, lookupErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, _ := mockRepo(t)
			rg := newRig(t, repo, tc.apps)
			s, err := rg.svc.Read(t.Context(), tc.actor, r)
			if !errors.Is(rg.keep(err), tc.want) || s.Value.Len() != 0 {
				t.Errorf("Read = %v, want %v", err, tc.want)
			}
			v, err := rg.svc.Create(t.Context(), tc.actor, r, val(sentinel))
			if !errors.Is(rg.keep(err), tc.want) || v != 0 {
				t.Errorf("Create = %d, %v; want %v", v, err, tc.want)
			}
			if rg.repo.callCount() != 0 {
				t.Errorf("repository calls = %v, want none", rg.repo.calls)
			}
			rg.assertNoSentinel()
		})
	}
}

// TC-761-08: a deploy job creates and reads its own app's secret, and is
// refused Replace and Delete with no repository call.
func TestService_DeployAllowedAndRefused(t *testing.T) {
	repo, _ := mockRepo(t)
	rg := newRig(t, repo, nil)
	deploy := secrets.DeployActor(appX, nodeN)
	r := appRef(t, appX, "db-pass")
	if v, err := rg.svc.Create(t.Context(), deploy, r, val(sentinel)); rg.keep(err) != nil || v != 1 {
		t.Fatalf("Create = %d, %v; want version 1", v, err)
	}
	s, err := rg.svc.Read(t.Context(), deploy, r)
	if rg.keep(err) != nil {
		t.Fatal(err)
	}
	if string(s.Value.Reveal()) != sentinel || s.Version != 1 {
		t.Errorf("Read gave version %d and a different value", s.Version)
	}
	s.Value.Destroy()
	before := rg.repo.callCount()
	if _, err := rg.svc.Replace(t.Context(), deploy, r, val("other")); !errors.Is(rg.keep(err), secrets.ErrForbidden) {
		t.Errorf("deploy Replace = %v, want ErrForbidden", err)
	}
	if err := rg.svc.Delete(t.Context(), deploy, r); !errors.Is(rg.keep(err), secrets.ErrForbidden) {
		t.Errorf("deploy Delete = %v, want ErrForbidden", err)
	}
	if rg.repo.callCount() != before {
		t.Errorf("refused calls reached the repository: %v", rg.repo.calls[before:])
	}
	rg.assertNoSentinel()
}

// TC-761-09: an operator never reads (S21); creates and replaces only an
// existing app's secrets (ErrNoSuchApp otherwise, with no repository call);
// deletes even when the app is gone; and OperatorActor("") is refused.
func TestService_OperatorRules(t *testing.T) {
	appZ := "01JQQQQQQQQQQQQQQQQQQQQQQ2"
	repo, _ := mockRepo(t)
	rg := newRig(t, repo, nil)
	op := secrets.OperatorActor("u1")
	r := appRef(t, appY, "db-pass")

	if _, err := rg.svc.Read(t.Context(), op, r); !errors.Is(rg.keep(err), secrets.ErrForbidden) {
		t.Errorf("operator Read = %v, want ErrForbidden", err)
	}
	if rg.repo.callCount() != 0 {
		t.Fatalf("the refused read reached the repository: %v", rg.repo.calls)
	}
	if v, err := rg.svc.Create(t.Context(), op, r, val(sentinel)); rg.keep(err) != nil || v != 1 {
		t.Errorf("operator Create = %d, %v; want 1", v, err)
	}
	if v, err := rg.svc.Replace(t.Context(), op, r, val(sentinel+"-2")); rg.keep(err) != nil || v != 2 {
		t.Errorf("operator Replace = %d, %v; want 2", v, err)
	}

	gone := appRef(t, appZ, "db-pass")
	before := rg.repo.callCount()
	if _, err := rg.svc.Create(t.Context(), op, gone, val(sentinel)); !errors.Is(rg.keep(err), secrets.ErrNoSuchApp) {
		t.Errorf("Create for an absent app = %v, want ErrNoSuchApp", err)
	}
	if _, err := rg.svc.Replace(t.Context(), op, gone, val(sentinel)); !errors.Is(rg.keep(err), secrets.ErrNoSuchApp) {
		t.Errorf("Replace for an absent app = %v, want ErrNoSuchApp", err)
	}
	if rg.repo.callCount() != before {
		t.Errorf("ErrNoSuchApp calls reached the repository: %v", rg.repo.calls[before:])
	}
	if err := rg.svc.Delete(t.Context(), op, gone); rg.keep(err) != nil {
		t.Errorf("Delete for an absent app = %v, want success", err)
	}

	nobody := secrets.OperatorActor("")
	if _, err := rg.svc.Create(t.Context(), nobody, r, val(sentinel)); !errors.Is(rg.keep(err), secrets.ErrForbidden) {
		t.Errorf("OperatorActor(\"\") Create = %v, want ErrForbidden", err)
	}
	rg.assertNoSentinel()
}

// TC-761-10 (F-761-02): every operation on a device secret is refused for
// every actor, the zero Actor is refused on every operation, and the zero Ref
// is ErrInvalidRef; none reaches the repository, and each writes one WARN.
func TestService_DeviceZeroActorZeroRef(t *testing.T) {
	repo, _ := mockRepo(t)
	rg := newRig(t, repo, nil)
	ctx := t.Context()
	ops := func(a secrets.Actor, r secrets.Ref) map[string]error {
		_, rErr := rg.svc.Read(ctx, a, r)
		_, cErr := rg.svc.Create(ctx, a, r, val(sentinel))
		_, pErr := rg.svc.Replace(ctx, a, r, val(sentinel))
		dErr := rg.svc.Delete(ctx, a, r)
		return map[string]error{"read": rErr, "create": cErr, "replace": pErr, "delete": dErr}
	}
	dev := deviceRef(t, "bmc", "x")
	calls := 0
	for name, a := range map[string]secrets.Actor{
		"operator": secrets.OperatorActor("u1"),
		"deploy":   secrets.DeployActor(appX, nodeN),
	} {
		for op, err := range ops(a, dev) {
			calls++
			if !errors.Is(rg.keep(err), secrets.ErrForbidden) {
				t.Errorf("%s %s on a device secret = %v, want ErrForbidden", name, op, err)
			}
		}
	}
	for op, err := range ops(secrets.Actor{}, appRef(t, appX, "db-pass")) {
		calls++
		if !errors.Is(rg.keep(err), secrets.ErrForbidden) {
			t.Errorf("zero Actor %s = %v, want ErrForbidden", op, err)
		}
	}
	for op, err := range ops(secrets.OperatorActor("u1"), secrets.Ref{}) {
		calls++
		if !errors.Is(rg.keep(err), secrets.ErrInvalidRef) {
			t.Errorf("zero Ref %s = %v, want ErrInvalidRef", op, err)
		}
	}
	if rg.repo.callCount() != 0 {
		t.Errorf("refused calls reached the repository: %v", rg.repo.calls)
	}
	if got := len(rg.rec.AtLevel(slog.LevelWarn)); got != calls || len(rg.rec.Records()) != calls {
		t.Errorf("%d WARN of %d records, want one WARN per refusal (%d)", got, len(rg.rec.Records()), calls)
	}
	rg.assertNoSentinel()
}

// TC-761-11 (F-761-01): each refusal writes exactly one WARN secrets.denied,
// each successful change one INFO, all with their exact fields and the job's
// id; a successful read, ErrExists, ErrConflict and ErrNoSuchApp write no
// service record.
func TestService_Logging(t *testing.T) {
	ctx := jobs.ContextWithJobID(t.Context(), "J1")
	repo, m := mockRepo(t)
	rg := newRig(t, repo, nil)
	r := appRef(t, appX, "db-pass")
	op := secrets.OperatorActor("u1")
	deploy := secrets.DeployActor(appX, nodeN)

	// last asserts the records written since n: exactly one, at level, with
	// msg and exactly want's fields.
	n := 0
	last := func(what string, level slog.Level, msg string, want map[string]string) {
		t.Helper()
		recs := rg.rec.Records()[n:]
		n = len(rg.rec.Records())
		if len(recs) != 1 {
			t.Errorf("%s: %d records, want 1", what, len(recs))
			return
		}
		if recs[0].Level != level || recs[0].Message != msg {
			t.Errorf("%s: %v %q, want %v %q", what, recs[0].Level, recs[0].Message, level, msg)
		}
		if got := attrs(recs[0]); !maps.Equal(got, want) {
			t.Errorf("%s: fields %v, want %v", what, got, want)
		}
	}
	none := func(what string) {
		t.Helper()
		if recs := rg.rec.Records()[n:]; len(recs) != 0 {
			t.Errorf("%s: %d service records, want none", what, len(recs))
		}
		n = len(rg.rec.Records())
	}
	opFields := func(event, verb string, extra ...string) map[string]string {
		f := map[string]string{"component": "secrets", "event": event, "op": verb, "ref": r.String(),
			"actor": "operator", "user_id": "u1", "job_id": "J1"}
		for i := 0; i+1 < len(extra); i += 2 {
			f[extra[i]] = extra[i+1]
		}
		return f
	}

	if _, err := rg.svc.Create(ctx, op, r, val(sentinel)); err != nil {
		t.Fatal(err)
	}
	last("create", slog.LevelInfo, "secret created", opFields("secrets.create", "create", "version", "1"))
	if _, err := rg.svc.Replace(ctx, op, r, val(sentinel)); err != nil {
		t.Fatal(err)
	}
	last("replace", slog.LevelInfo, "secret replaced", opFields("secrets.replace", "replace", "version", "2"))

	if _, err := rg.svc.Read(ctx, op, r); !errors.Is(err, secrets.ErrForbidden) {
		t.Fatal(err)
	}
	last("operator read", slog.LevelWarn, "secret access denied",
		opFields("secrets.denied", "read", "reason", "secrets are write-only for operators"))
	if _, err := rg.svc.Read(ctx, secrets.DeployActor(appX, nodeM), r); !errors.Is(err, secrets.ErrForbidden) {
		t.Fatal(err)
	}
	last("wrong node", slog.LevelWarn, "secret access denied", map[string]string{
		"component": "secrets", "event": "secrets.denied", "op": "read", "ref": r.String(), "actor": "deploy",
		"app_id": appX, "node": nodeM, "reason": "the node is not the app's target node", "job_id": "J1"})
	if _, err := rg.svc.Read(ctx, secrets.Actor{}, r); !errors.Is(err, secrets.ErrForbidden) {
		t.Fatal(err)
	}
	last("zero actor", slog.LevelWarn, "secret access denied", map[string]string{
		"component": "secrets", "event": "secrets.denied", "op": "read", "ref": r.String(), "actor": "none",
		"reason": "no actor", "job_id": "J1"})

	s, err := rg.svc.Read(ctx, deploy, r)
	if err != nil {
		t.Fatal(err)
	}
	s.Value.Destroy()
	none("successful read")
	if _, err := rg.svc.Create(ctx, op, r, val(sentinel)); !errors.Is(err, secrets.ErrExists) {
		t.Fatalf("Create of a set secret = %v, want ErrExists", err)
	}
	none("ErrExists")
	if _, err := rg.svc.Create(ctx, op, appRef(t, "01JQQQQQQQQQQQQQQQQQQQQQQ2", "x"), val(sentinel)); !errors.Is(err, secrets.ErrNoSuchApp) {
		t.Fatalf("Create for an absent app = %v, want ErrNoSuchApp", err)
	}
	none("ErrNoSuchApp")
	racing := newRig(t, &racingRepo{Repository: repo, m: m, p: mockPath(t, r)}, nil)
	if _, err := racing.svc.Replace(ctx, op, r, val(sentinel)); !errors.Is(err, secrets.ErrConflict) {
		t.Fatalf("racing Replace = %v, want ErrConflict", err)
	}
	if recs := racing.rec.Records(); len(recs) != 0 {
		t.Errorf("ErrConflict: %d service records, want none", len(recs))
	}

	if err := rg.svc.Delete(ctx, op, r); err != nil {
		t.Fatal(err)
	}
	last("delete", slog.LevelInfo, "secret deleted", opFields("secrets.delete", "delete"))
}

// racingRepo is a repository where another writer replaces the secret between
// the service's version read and its write.
type racingRepo struct {
	secrets.Repository
	m      *secretstore.Mock
	p      secretstore.KVPath
	writes int
}

func (r *racingRepo) CurrentVersion(ctx context.Context, ref secrets.Ref) (int, error) {
	cur, err := r.Repository.CurrentVersion(ctx, ref)
	if err != nil {
		return 0, err
	}
	if _, err := r.m.Write(ctx, secret.Value{}, r.p, map[string]secret.Value{"value": val("other-writer")}, cur); err != nil {
		return 0, err
	}
	return cur, nil
}

func (r *racingRepo) Write(ctx context.Context, ref secrets.Ref, v secret.Value, cas int) (int, error) {
	r.writes++
	return r.Repository.Write(ctx, ref, v, cas)
}

// TC-761-12: Create is create-only: an existing secret is ErrExists and keeps
// its version and value; a new path gets version 1.
func TestService_CreateOnly(t *testing.T) {
	repo, m := mockRepo(t)
	rg := newRig(t, repo, nil)
	deploy := secrets.DeployActor(appX, nodeN)
	r := appRef(t, appX, "k")
	if v, err := rg.svc.Create(t.Context(), deploy, r, val(sentinel)); err != nil || v != 1 {
		t.Fatalf("first Create = %d, %v", v, err)
	}
	if _, err := rg.svc.Create(t.Context(), deploy, r, val("second")); !errors.Is(rg.keep(err), secrets.ErrExists) {
		t.Errorf("second Create = %v, want ErrExists", err)
	}
	got, version, err := readMock(t, m, mockPath(t, r), 0)
	if err != nil || version != 1 || got != sentinel {
		t.Errorf("after the refused create: version %d (%v), want version 1 with the original value", version, err)
	}
	if v, err := rg.svc.Create(t.Context(), deploy, appRef(t, appX, "new"), val(sentinel)); err != nil || v != 1 {
		t.Errorf("Create on a new path = %d, %v; want 1", v, err)
	}
	rg.assertNoSentinel()
}

// TC-761-13: Replace of an absent secret is ErrNotFound with no write; it
// writes under check-and-set on the version it read; and a lost race is
// ErrConflict after exactly one write, with the other writer's value current.
func TestService_Replace(t *testing.T) {
	r := appRef(t, appX, "k")
	op := secrets.OperatorActor("u1")

	absent := &fakeStore{versionsErr: &secretstore.Error{Op: "versions", Kind: secretstore.ErrNotFound}}
	rg := newRig(t, mustRepo(t, absent), nil)
	if _, err := rg.svc.Replace(t.Context(), op, r, val(sentinel)); !errors.Is(rg.keep(err), secretstore.ErrNotFound) {
		t.Errorf("Replace of an absent secret = %v, want ErrNotFound", err)
	}
	if len(absent.cas) != 0 {
		t.Errorf("Replace of an absent secret wrote %d times", len(absent.cas))
	}

	at3 := &fakeStore{current: 3}
	rg3 := newRig(t, mustRepo(t, at3), nil)
	if v, err := rg3.svc.Replace(t.Context(), op, r, val(sentinel)); err != nil || v != 4 {
		t.Errorf("Replace at version 3 = %d, %v; want 4", v, err)
	}
	if len(at3.cas) != 1 || at3.cas[0] != 3 {
		t.Errorf("write check-and-set values %v, want [3]", at3.cas)
	}

	repo, m := mockRepo(t)
	setup := newRig(t, repo, nil)
	if _, err := setup.svc.Create(t.Context(), op, r, val(sentinel)); err != nil {
		t.Fatal(err)
	}
	race := &racingRepo{Repository: repo, m: m, p: mockPath(t, r)}
	rgr := newRig(t, race, nil)
	if _, err := rgr.svc.Replace(t.Context(), op, r, val(sentinel+"-mine")); !errors.Is(rgr.keep(err), secrets.ErrConflict) {
		t.Fatalf("racing Replace = %v, want ErrConflict", err)
	}
	if race.writes != 1 {
		t.Errorf("racing Replace made %d writes, want exactly 1 (no retry)", race.writes)
	}
	if got, version, err := readMock(t, m, mockPath(t, r), 0); err != nil || got != "other-writer" || version != 2 {
		t.Errorf("after the lost race: version %d (%v), want the other writer's version 2", version, err)
	}
	for _, x := range []*rig{rg, rg3, rgr} {
		x.assertNoSentinel()
	}
}

func mustRepo(t *testing.T, s secrets.Store) *secrets.KVRepository {
	t.Helper()
	repo, err := secrets.NewRepository(s)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

// TC-761-14: Delete removes every version, a second Delete succeeds, and a
// later create starts again at version 1.
func TestService_DeleteEveryVersion(t *testing.T) {
	repo, m := mockRepo(t)
	rg := newRig(t, repo, nil)
	op := secrets.OperatorActor("u1")
	r := appRef(t, appX, "k")
	p := mockPath(t, r)
	if _, err := rg.svc.Create(t.Context(), op, r, val(sentinel)); err != nil {
		t.Fatal(err)
	}
	if v, err := rg.svc.Replace(t.Context(), op, r, val(sentinel+"-2")); err != nil || v != 2 {
		t.Fatalf("Replace = %d, %v", v, err)
	}
	if err := rg.svc.Delete(t.Context(), op, r); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{0, 1, 2} {
		if _, _, err := readMock(t, m, p, version); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("read at version %d after Delete = %v, want ErrNotFound", version, err)
		}
	}
	if _, err := m.Versions(t.Context(), secret.Value{}, p); !errors.Is(err, secretstore.ErrNotFound) {
		t.Errorf("Versions after Delete = %v, want ErrNotFound", err)
	}
	if err := rg.svc.Delete(t.Context(), op, r); err != nil {
		t.Errorf("second Delete = %v, want nil", err)
	}
	if v, err := rg.svc.Create(t.Context(), op, r, val(sentinel)); err != nil || v != 1 {
		t.Errorf("Create after Delete = %d, %v; want 1", v, err)
	}
	rg.assertNoSentinel()
}

// TC-761-15: every store kind reaches the caller as itself, with a zero
// result and never a nil error (Delete of an absent secret aside, which is
// TC-761-14's success); over secretstore.Disabled every operation is
// ErrDisabled.
func TestService_StoreFailuresRefuse(t *testing.T) {
	r := appRef(t, appX, "k")
	deploy := secrets.DeployActor(appX, nodeN)
	op := secrets.OperatorActor("u1")
	for _, kind := range []error{
		secretstore.ErrSealed, secretstore.ErrUninitialised, secretstore.ErrUnreachable, secretstore.ErrDenied,
		secretstore.ErrDisabled, secretstore.ErrProtocol, secretstore.ErrNotFound,
	} {
		t.Run(kind.Error(), func(t *testing.T) {
			e := &secretstore.Error{Op: "x", Kind: kind}
			fs := &fakeStore{readErr: e, versionsErr: e, writeErr: e, deleteErr: e}
			rg := newRig(t, mustRepo(t, fs), nil)
			s, err := rg.svc.Read(t.Context(), deploy, r)
			if !errors.Is(rg.keep(err), kind) || s.Value.Len() != 0 || s.Version != 0 {
				t.Errorf("Read = %+v, %v; want a zero Secret and %v", s, err, kind)
			}
			v, err := rg.svc.Create(t.Context(), deploy, r, val(sentinel))
			if !errors.Is(rg.keep(err), kind) || v != 0 {
				t.Errorf("Create = %d, %v; want 0 and %v", v, err, kind)
			}
			v, err = rg.svc.Replace(t.Context(), op, r, val(sentinel))
			if !errors.Is(rg.keep(err), kind) || v != 0 {
				t.Errorf("Replace = %d, %v; want 0 and %v", v, err, kind)
			}
			err = rg.svc.Delete(t.Context(), op, r)
			if kind == secretstore.ErrNotFound {
				if err != nil {
					t.Errorf("Delete of an absent secret = %v, want nil", err)
				}
			} else if !errors.Is(rg.keep(err), kind) {
				t.Errorf("Delete = %v, want %v", err, kind)
			}
			rg.assertNoSentinel()
		})
	}

	t.Run("disabled", func(t *testing.T) {
		repo := mustRepo(t, sessionOver(t, secretstore.Disabled{}))
		rg := newRig(t, repo, nil)
		_, rErr := rg.svc.Read(t.Context(), deploy, r)
		_, cErr := rg.svc.Create(t.Context(), deploy, r, val(sentinel))
		_, pErr := rg.svc.Replace(t.Context(), op, r, val(sentinel))
		dErr := rg.svc.Delete(t.Context(), op, r)
		for i, err := range []error{rErr, cErr, pErr, dErr} {
			if !errors.Is(rg.keep(err), secretstore.ErrDisabled) {
				t.Errorf("operation %d over Disabled = %v, want ErrDisabled", i, err)
			}
		}
		rg.assertNoSentinel()
	})
}

// TC-761-16: a Secret holding the sentinel renders without it under every
// verb and in JSON. (The log and error scans run in each test above through
// rig.assertNoSentinel.)
func TestSecret_Renders(t *testing.T) {
	s := secrets.Secret{Value: val(sentinel), Version: 3}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, s); strings.Contains(out, sentinel) {
			t.Errorf("%s renders the value: %s", verb, out)
		}
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), sentinel) {
		t.Errorf("JSON renders the value: %s", b)
	}
	log, rec := logkittest.New()
	log.Info("x", "secret", s)
	if strings.Contains(rec.Text(), sentinel) {
		t.Error("a logged Secret renders the value")
	}
}

// TC-761-17: the constructors refuse each nil collaborator.
func TestConstructors_RefuseNil(t *testing.T) {
	if r, err := secrets.NewRepository(nil); err == nil || r != nil {
		t.Errorf("NewRepository(nil) = %v, %v; want an error", r, err)
	}
	log, _ := logkittest.New()
	repo := mustRepo(t, &fakeStore{})
	apps := fakeApps{}
	sw := &fakeSwitch{log: &fakeRepo{}}
	for name, d := range map[string]secrets.Deps{
		"Repo":   {Apps: apps, Switch: sw, Log: log},
		"Apps":   {Repo: repo, Switch: sw, Log: log},
		"Switch": {Repo: repo, Apps: apps, Log: log}, // TC-604-05
		"Log":    {Repo: repo, Apps: apps, Switch: sw},
	} {
		if s, err := secrets.NewService(d); err == nil || s != nil {
			t.Errorf("NewService with nil %s = %v, %v; want an error", name, s, err)
		}
	}
}

// nulRows are a value with a NUL byte at the first, a middle and the last
// byte, so a check that skips either end is caught.
var nulRows = map[string]string{
	"first byte":  "\x00abc",
	"middle byte": "ab\x00cd",
	"last byte":   "abc\x00",
}

// hostileValues are values that would change compose text if they were ever
// written into it (geekdojo/geekdojo-brain#779). The appsecret tests carry
// the same list; each is legal for a credential and must be stored unchanged.
var hostileValues = []string{
	"a$b",
	"x${HOME}y",
	"$$z",
	"${RASPUTIN_SECRET_OTHER}",
	"${RASPUTIN_SECRET_OTHER:-leak}",
	"a\nprivileged: true\nvolumes: [\"/:/host\"]",
	"it's",
	`say "hi"`,
	"- a: b # c & *x !t | > % @",
}

// TC-779-01: a value with a NUL byte is refused at Create as
// secretstore.ErrInvalidValue, version 0, naming the reference, before any
// repository call.
func TestService_CreateRefusesNUL(t *testing.T) {
	op := secrets.OperatorActor("u1")
	r := appRef(t, appX, "db-pass")
	for name, v := range nulRows {
		t.Run(name, func(t *testing.T) {
			repo, _ := mockRepo(t)
			rg := newRig(t, repo, nil)
			got, err := rg.svc.Create(t.Context(), op, r, val(v))
			if !errors.Is(err, secretstore.ErrInvalidValue) || got != 0 {
				t.Fatalf("Create = %d, %v; want 0 and ErrInvalidValue", got, err)
			}
			if !strings.Contains(err.Error(), r.String()) {
				t.Errorf("the refusal %q does not name the reference %s", err, r)
			}
			if n := rg.repo.callCount(); n != 0 {
				t.Errorf("the refused Create made %d repository calls, want 0", n)
			}
		})
	}
}

// TC-779-02: a value with a NUL byte is refused at Replace as
// secretstore.ErrInvalidValue with no CurrentVersion or Write call, and the
// stored entry keeps its version 1 bytes.
func TestService_ReplaceRefusesNUL(t *testing.T) {
	op := secrets.OperatorActor("u1")
	r := appRef(t, appX, "db-pass")
	repo, m := mockRepo(t)
	if _, err := newRig(t, repo, nil).svc.Create(t.Context(), op, r, val("original")); err != nil {
		t.Fatal(err)
	}
	rg := newRig(t, repo, nil)
	for name, v := range nulRows {
		if _, err := rg.svc.Replace(t.Context(), op, r, val(v)); !errors.Is(err, secretstore.ErrInvalidValue) {
			t.Errorf("%s: Replace = %v, want ErrInvalidValue", name, err)
		}
	}
	if n := rg.repo.callCount(); n != 0 {
		t.Errorf("the refused Replaces made %d repository calls, want 0", n)
	}
	if got, version, err := readMock(t, m, mockPath(t, r), 0); err != nil || got != "original" || version != 1 {
		t.Errorf("after the refused Replaces: %q at version %d (%v), want the original at version 1", got, version, err)
	}
}

// TC-779-03: the rule binds every actor. A deploy job for its own app is
// refused a NUL value with no repository call; a deploy job for another app
// is ErrForbidden, not ErrInvalidValue, because authorization runs first.
func TestService_NULRuleBindsEveryActor(t *testing.T) {
	r := appRef(t, appX, "db-pass")
	repo, _ := mockRepo(t)
	rg := newRig(t, repo, nil)
	if _, err := rg.svc.Create(t.Context(), secrets.DeployActor(appX, nodeN), r, val("a\x00b")); !errors.Is(err, secretstore.ErrInvalidValue) {
		t.Errorf("own-app deploy Create = %v, want ErrInvalidValue", err)
	}
	_, err := rg.svc.Create(t.Context(), secrets.DeployActor(appY, nodeN), r, val("a\x00b"))
	if !errors.Is(err, secrets.ErrForbidden) || errors.Is(err, secretstore.ErrInvalidValue) {
		t.Errorf("other-app deploy Create = %v, want ErrForbidden and not ErrInvalidValue", err)
	}
	if n := rg.repo.callCount(); n != 0 {
		t.Errorf("%d repository calls, want 0", n)
	}
}

// TC-779-04: every hostile value is accepted by Create (on a new reference,
// version 1) and by Replace (on an existing one), and the repository's Write
// receives the bytes unchanged.
func TestService_HostileValuesAreStoredUnchanged(t *testing.T) {
	op := secrets.OperatorActor("u1")
	for i, v := range hostileValues {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			repo, _ := mockRepo(t)
			rg := newRig(t, repo, nil)
			r := appRef(t, appX, fmt.Sprintf("k%d", i))
			if got, err := rg.svc.Create(t.Context(), op, r, val(v)); err != nil || got != 1 {
				t.Fatalf("Create = %d, %v; want 1", got, err)
			}
			if _, err := rg.svc.Replace(t.Context(), op, r, val(v)); err != nil {
				t.Fatalf("Replace = %v", err)
			}
			if len(rg.repo.written) != 2 || rg.repo.written[0] != v || rg.repo.written[1] != v {
				t.Fatalf("the repository's Write received %q, want %q twice", rg.repo.written, v)
			}
		})
	}
}

// TC-779-05: a refused value leaks nowhere: the sentinel inside a NUL value
// is in no error string and no log record, and the refused calls write no
// record at all.
func TestService_NULRefusalLeaksNothingAndLogsNothing(t *testing.T) {
	op := secrets.OperatorActor("u1")
	r := appRef(t, appX, "db-pass")
	repo, _ := mockRepo(t)
	if _, err := newRig(t, repo, nil).svc.Create(t.Context(), op, r, val("original")); err != nil {
		t.Fatal(err)
	}
	rg := newRig(t, repo, nil)
	bad := val(sentinel + "\x00" + sentinel)
	if _, err := rg.svc.Create(t.Context(), op, appRef(t, appX, "fresh"), bad); !errors.Is(rg.keep(err), secretstore.ErrInvalidValue) {
		t.Errorf("Create = %v, want ErrInvalidValue", err)
	}
	if _, err := rg.svc.Replace(t.Context(), op, r, bad); !errors.Is(rg.keep(err), secretstore.ErrInvalidValue) {
		t.Errorf("Replace = %v, want ErrInvalidValue", err)
	}
	rg.assertNoSentinel()
	if n := len(rg.rec.Records()); n != 0 {
		t.Errorf("the refused calls wrote %d log records, want 0", n)
	}
}

// TC-779-08: a derived value, the only kind earlier releases stored, still
// passes the rule: a deploy job's Create of Seed.Derive succeeds at version 1
// and the repository receives the derived bytes.
func TestService_DerivedValuePassesTheRule(t *testing.T) {
	seed, err := appsecret.NewSeed(bytes.Repeat([]byte{0x11}, appsecret.SeedLen), appsecret.DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := seed.Derive(appX, "session-key", appsecret.InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	want := string(derived.Reveal())
	repo, _ := mockRepo(t)
	rg := newRig(t, repo, nil)
	if got, err := rg.svc.Create(t.Context(), secrets.DeployActor(appX, nodeN), appRef(t, appX, "session-key"), derived); err != nil || got != 1 {
		t.Fatalf("Create = %d, %v; want 1", got, err)
	}
	if len(rg.repo.written) != 1 || rg.repo.written[0] != want {
		t.Fatal("the repository did not receive the derived bytes")
	}
}
