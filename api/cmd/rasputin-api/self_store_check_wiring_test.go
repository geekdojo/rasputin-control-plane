package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-767-12 (wiring half): the self-update's store check is wired on exactly
// the hosts whose OS update copy_store copies, keyed on the same pre-update
// copier main passes it (#873): a check for openbao and for a refused value
// (whose Disabled store then answers not ready, which the updater half of
// TC-767-12 proves), nil for the mock or nothing, and an error for a nil
// logger.
//
// TC-873-15 (check half): a nil retirer gives a nil check and no error, and
// the retirer the check is built from removes the file at the configured
// copyPath. The check's own call to its retirer at the commit is
// TC-873-05/06 in package updater, where the commit runs.
func TestSelfStoreCheckWiringFollowsTheUpdateCopy(t *testing.T) {
	for _, tc := range []struct {
		requested, mode string
		store           secretStore
		wired           bool
	}{
		{"openbao", storeModeOpenBao, secretstore.NewMock(time.Now), true},
		{"vault", storeModeOff, secretstore.Disabled{}, true},
		{"mock", storeModeMock, secretstore.NewMock(time.Now), false},
		{"", storeModeOff, secretstore.Disabled{}, false},
	} {
		t.Run("requested="+tc.requested, func(t *testing.T) {
			log, _ := logkittest.New()
			w, d := rollbackFor(t, tc.requested, tc.mode, tc.store, newFakeRollbackRunner(), log)
			check, err := selfStoreCheckWiring(w.retirer, tc.store, log)
			if err != nil {
				t.Fatalf("selfStoreCheckWiring: %v", err)
			}
			if got := check != nil; got != tc.wired {
				t.Fatalf("check wired = %v, want %v", got, tc.wired)
			}
			if !tc.wired {
				return
			}
			if _, err := selfStoreCheckWiring(w.retirer, tc.store, nil); err == nil {
				t.Error("nil logger: want an error")
			}
			if err := os.WriteFile(d.copyPath, []byte("a copy"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := w.retirer.RetireCopy(context.Background(), "upd-1"); err != nil {
				t.Fatalf("RetireCopy: %v", err)
			}
			if _, err := os.Stat(d.copyPath); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the copy at copyPath is still there: %v", err)
			}
		})
	}
}
