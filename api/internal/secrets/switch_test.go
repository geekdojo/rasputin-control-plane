package secrets_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
)

// TC-604-05: an operator's Create and Replace set the switch marker before
// the first repository call; a marker that fails refuses the write with no
// repository call; a deploy job's Create never marks; and a forbidden actor,
// an absent app and a NUL-byte value are refused without marking.
func TestService_OperatorWritesMarkTheSwitchFirst(t *testing.T) {
	ctx := context.Background()
	operator := secrets.OperatorActor("u1")

	t.Run("create marks before the repository", func(t *testing.T) {
		repo, _ := mockRepo(t)
		r := newRig(t, repo, nil)
		if _, err := r.svc.Create(ctx, operator, appRef(t, appX, "feed-key"), val("v1")); err != nil {
			t.Fatal(err)
		}
		if len(r.repo.calls) < 2 || r.repo.calls[0] != "mark" || r.repo.marks() != 1 {
			t.Fatalf("call log %v, want one mark before the first repository call", r.repo.calls)
		}
	})
	t.Run("replace marks before the repository", func(t *testing.T) {
		repo, _ := mockRepo(t)
		r := newRig(t, repo, nil)
		ref := appRef(t, appX, "feed-key")
		if _, err := r.svc.Create(ctx, secrets.DeployActor(appX, nodeN), ref, val("v1")); err != nil {
			t.Fatal(err)
		}
		before := len(r.repo.calls)
		if _, err := r.svc.Replace(ctx, operator, ref, val("v2")); err != nil {
			t.Fatal(err)
		}
		got := r.repo.calls[before:]
		if len(got) < 2 || got[0] != "mark" || r.repo.marks() != 1 {
			t.Fatalf("replace call log %v, want one mark before the first repository call", got)
		}
	})
	t.Run("a failed marker refuses with no repository call", func(t *testing.T) {
		boom := errors.New("database is locked")
		for name, write := range map[string]func(*rig) error{
			"create": func(r *rig) error {
				_, err := r.svc.Create(ctx, operator, appRef(t, appX, "feed-key"), val("v1"))
				return err
			},
			"replace": func(r *rig) error {
				_, err := r.svc.Replace(ctx, operator, appRef(t, appX, "feed-key"), val("v1"))
				return err
			},
		} {
			t.Run(name, func(t *testing.T) {
				repo, _ := mockRepo(t)
				r := newRig(t, repo, nil)
				r.sw.err = boom
				err := write(r)
				if !errors.Is(err, secrets.ErrSwitch) || !errors.Is(err, boom) {
					t.Fatalf("%s = %v, want ErrSwitch wrapping the marker's error", name, err)
				}
				if n := r.repo.callCount(); n != 0 {
					t.Fatalf("%d repository call(s) after the marker failed: %v", n, r.repo.repoCalls())
				}
			})
		}
	})
	t.Run("a deploy job's create never marks", func(t *testing.T) {
		repo, _ := mockRepo(t)
		r := newRig(t, repo, nil)
		if _, err := r.svc.Create(ctx, secrets.DeployActor(appX, nodeN), appRef(t, appX, "db-pass"), val("derived")); err != nil {
			t.Fatal(err)
		}
		if r.repo.marks() != 0 || slices.Contains(r.repo.calls, "mark") {
			t.Fatalf("a deploy create marked the switch: %v", r.repo.calls)
		}
	})
	t.Run("refusals never mark", func(t *testing.T) {
		for name, write := range map[string]func(*rig) error{
			"forbidden actor": func(r *rig) error {
				_, err := r.svc.Replace(ctx, secrets.DeployActor(appX, nodeN), appRef(t, appX, "feed-key"), val("v"))
				return err
			},
			"absent app": func(r *rig) error {
				_, err := r.svc.Create(ctx, operator, appRef(t, "01JZZZZZZZZZZZZZZZZZZZZZZ9", "feed-key"), val("v"))
				return err
			},
			"NUL byte": func(r *rig) error {
				_, err := r.svc.Create(ctx, operator, appRef(t, appX, "feed-key"), val("a\x00b"))
				return err
			},
		} {
			t.Run(name, func(t *testing.T) {
				repo, _ := mockRepo(t)
				r := newRig(t, repo, nil)
				if err := write(r); err == nil {
					t.Fatalf("%s was not refused", name)
				}
				if r.repo.marks() != 0 || r.repo.callCount() != 0 {
					t.Fatalf("%s: call log %v, want no mark and no repository call", name, r.repo.calls)
				}
			})
		}
	})
}
