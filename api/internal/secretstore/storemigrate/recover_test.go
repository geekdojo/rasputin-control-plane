package storemigrate

import (
	"context"
	"log/slog"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-1132-22: Recover at api start. aside.tar without a commit restarts the
// store once and logs WARN migrate_recovered with the attempt's job id; a
// request without aside.tar is removed; aside.tar with a commit, and
// nothing, are left alone. (That main runs it before the secrets service,
// the relay and the runner is TestStoreMigrateRecoverRunsFirst.)
func TestRecover(t *testing.T) {
	for _, tc := range []struct {
		name     string
		files    []string
		restarts int
		left     []string
	}{
		{"aside.tar without commit", []string{NameAside, NameAttempt}, 1, []string{NameAside, NameAttempt}},
		{"request without aside.tar", []string{NameRequest}, 0, nil},
		{"attempt alone", []string{NameAttempt}, 0, nil},
		{"aside.tar with commit", []string{NameAside, NameCommit}, 0, []string{NameAside, NameCommit}},
		{"nothing", nil, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFx(t)
			for _, n := range tc.files {
				if err := f.files.StateDir.Write(n, []byte("boot_id="+thisBoot+"\njob_id="+jobID+"\n")); err != nil {
					t.Fatal(err)
				}
			}
			log, rec := logkittest.New()
			restarts := 0
			if err := Recover(context.Background(), RecoverDeps{Files: f.files, Log: log,
				Start: func(context.Context) error { restarts++; return nil }}); err != nil {
				t.Fatal(err)
			}
			if restarts != tc.restarts {
				t.Errorf("%d restarts, want %d", restarts, tc.restarts)
			}
			for _, n := range []string{NameRequest, NameAttempt, NameAside, NameCommit} {
				want := false
				for _, l := range tc.left {
					want = want || l == n
				}
				if f.present(n) != want {
					t.Errorf("%s present %v, want %v", n, f.present(n), want)
				}
			}
			warns := rec.Matching(slog.LevelWarn, "found unfinished at start")
			if tc.restarts == 1 || len(tc.files) == 1 {
				if len(warns) != 1 {
					t.Fatalf("WARN records %d, want 1:\n%s", len(warns), rec.Text())
				}
				if v, _ := logkittest.Attr(warns[0], "job_id"); v != jobID {
					t.Errorf("job_id = %q, want %s", v, jobID)
				}
			} else if len(warns) != 0 {
				t.Errorf("unexpected WARN:\n%s", rec.Text())
			}
		})
	}
	t.Run("unreadable state is left alone", func(t *testing.T) {
		f := newFx(t)
		f.files.presentErr = map[string]error{NameAside: errBoom}
		log, rec := logkittest.New()
		restarts := 0
		if err := Recover(context.Background(), RecoverDeps{Files: f.files, Log: log,
			Start: func(context.Context) error { restarts++; return nil }}); err != nil {
			t.Fatal(err)
		}
		if restarts != 0 || len(rec.AtLevel(slog.LevelError)) != 1 {
			t.Fatalf("restarts %d, records:\n%s", restarts, rec.Text())
		}
	})
	if err := Recover(context.Background(), RecoverDeps{}); err == nil {
		t.Error("nil collaborators accepted")
	}
}
