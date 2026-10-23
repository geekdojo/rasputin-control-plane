package main

import (
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-767-12 (wiring half): the self-update's store check is wired on exactly
// the hosts whose OS update copy_store copies, keyed on the same update copy
// main passes it: a check for openbao and for a refused value (whose Disabled
// store then answers not ready, which the updater half of TC-767-12 proves),
// nil for the mock or nothing, and an error for a nil logger.
func TestSelfStoreCheckWiringFollowsTheUpdateCopy(t *testing.T) {
	log, _ := logkittest.New()
	key, _ := sealrotate.ParseKeyID("rasputin-11111111-1111-4111-8111-111111111111")
	clean := sealAt{tree: sealrotate.Tree{Fragment: sealrotate.Fragment{Shape: sealrotate.Clean, Current: key}}}
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
			r, err := storeReadinessWiring(tc.requested, tc.mode, tc.store, openJobStore(t), time.Now, notBlank, log)
			if err != nil {
				t.Fatal(err)
			}
			updateCopy, err := storeBackupWiring(tc.requested, storestate.QuiesceOSUpdate, r.monitor, r.store, clean,
				(&recordedRun{}).run, noRestartHook, log)
			if err != nil {
				t.Fatal(err)
			}
			check, err := selfStoreCheckWiring(updateCopy, r.store, log)
			if err != nil {
				t.Fatalf("selfStoreCheckWiring: %v", err)
			}
			if got := check != nil; got != tc.wired {
				t.Fatalf("check wired = %v, want %v", got, tc.wired)
			}
			if !tc.wired {
				return
			}
			if _, err := selfStoreCheckWiring(updateCopy, r.store, nil); err == nil {
				t.Error("nil logger: want an error")
			}
		})
	}
}
