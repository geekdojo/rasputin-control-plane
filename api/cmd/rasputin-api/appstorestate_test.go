package main

import (
	"context"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

var _ apps.SecretStoreState = appStoreState{}

// The app delete's view of the store: no monitor (nothing requested, never
// switched) is unconfigured, and a store that is switched but not configured
// reads not ready, so a delete with stored secrets refuses (F-783-04).
func TestAppStoreState(t *testing.T) {
	log, _ := logkittest.New()
	js := openJobStore(t)

	off, err := storeReadinessWiring("", false, storeModeOff, secretstore.Disabled{}, js, time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	s := appStoreState{monitor: off.monitor}
	if s.Configured() {
		t.Error("no store requested and never switched reads configured")
	}
	if _, err := s.State(context.Background()); err == nil {
		t.Error("State with no monitor = nil error")
	}

	switched, err := storeReadinessWiring("", true, storeModeOff, secretstore.Disabled{}, js, time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	s = appStoreState{monitor: switched.monitor}
	if !s.Configured() {
		t.Fatal("a switched cluster with no store reads unconfigured; its stored secrets would be skipped")
	}
	if st, err := s.State(context.Background()); err != nil || st == storestate.Ready {
		t.Errorf("State = %s, %v; want not ready", st, err)
	}

	mock, err := storeReadinessWiring(storeModeMock, false, storeModeMock, secretstore.NewMock(time.Now), js, time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := (appStoreState{monitor: mock.monitor}).State(context.Background()); err != nil || st != storestate.Ready {
		t.Errorf("State over the mock = %s, %v; want ready", st, err)
	}
}
