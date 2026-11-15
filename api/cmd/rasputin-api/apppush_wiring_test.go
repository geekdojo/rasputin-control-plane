package main

import (
	"context"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// noAppSecretDeletes is an apps.AppSecretDeleter this test never reaches: it
// only registers the sagas, it runs none of them.
type noAppSecretDeletes struct{}

func (noAppSecretDeletes) Delete(context.Context, secrets.Actor, secrets.Ref) error { return nil }

// The four push-family app sagas register through main's helper with the
// app-identity switch it builds off (geekdojo/geekdojo-brain#1080), and none of
// their constructors refuses that wiring: the api comes up with all four. The
// switch being off is what each constructor is handed here; that the zero value
// sends the agent what it always has is TC-1080-01's golden, in the apps
// package.
func TestRegisterAppPushWorkflows_RegistersTheFourWithTheSwitchOff(t *testing.T) {
	log, _ := logkittest.New()
	_, hkdf := loadAppSecrets(t.Context(), log, func(code int) { t.Fatalf("loadAppSecrets exited %d", code) }, t.TempDir())

	var kinds []string
	register := func(w jobs.Workflow) { kinds = append(kinds, w.Kind) }
	must := func(w jobs.Workflow, err error) jobs.Workflow {
		if err != nil {
			t.Fatalf("a push-family constructor refused main's wiring: %v", err)
		}
		return w
	}
	registerAppPushWorkflows(register, must, appPushDeps{
		Apps:       openAppsStore(t),
		Stash:      apps.NewComposeStash(),
		Secrets:    hkdf,
		SecretDeps: apps.DeleteSecretsDeps{Secrets: noAppSecretDeletes{}, Store: appStoreState{}, Log: log},
	})

	slices.Sort(kinds)
	want := []string{"app.deploy", "app.edit", "app.revert", "app.upgrade"}
	if !slices.Equal(kinds, want) {
		t.Fatalf("registered %v, want %v", kinds, want)
	}
}
