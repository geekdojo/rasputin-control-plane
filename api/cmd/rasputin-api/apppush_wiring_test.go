package main

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// noAppSecretDeletes is an apps.AppSecretDeleter this test never reaches: it
// only registers the sagas, it runs none of them.
type noAppSecretDeletes struct{}

func (noAppSecretDeletes) Delete(context.Context, secrets.Actor, secrets.Ref) error { return nil }
func (noAppSecretDeletes) DestroyKey(context.Context, secrets.Actor, secrets.Ref) error {
	return nil
}

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

// TC-1081-05: main's app-identity switch grants nothing, with the
// controlplane CA loaded and without it (F-1081-05: the issuer is built
// either way), so no embedded catalog tile is issued a relay socket; the push
// sagas, the delete saga and the relay endpoint all accept the wiring.
func TestNewAppIdentity_ShippedWiringGrantsNothing(t *testing.T) {
	log, _ := logkittest.New()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	inv, err := inventory.OpenStore(t.Context(), filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	_, hkdf := loadAppSecrets(t.Context(), log, func(code int) { t.Fatalf("loadAppSecrets exited %d", code) }, t.TempDir())
	store := openAppsStore(t)
	deps := apps.DeleteSecretsDeps{Secrets: noAppSecretDeletes{}, Store: appStoreState{}, Log: log}

	for name, ca := range map[string]*tlsca.CA{
		"with a CA": tlscatest.Controlplane(t, filepath.Join(t.TempDir(), "trust")),
		"no CA":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			identity, err := newAppIdentity(ca, nc, inv)
			if err != nil {
				t.Fatalf("newAppIdentity: %v", err)
			}
			if identity.Any() {
				t.Error("the shipped grant list grants a tile")
			}
			for _, tile := range catalog.MustLoad().All() {
				if identity.Granted(&apps.App{ID: "01J9ZK3Q0M8X7Y6W5V4T3S2R1A", SourceTile: tile.ID}) {
					t.Errorf("tile %s is granted", tile.ID)
				}
			}
			must := func(w jobs.Workflow, err error) jobs.Workflow {
				if err != nil {
					t.Fatalf("a constructor refused main's wiring: %v", err)
				}
				return w
			}
			registerAppPushWorkflows(func(jobs.Workflow) {}, must, appPushDeps{
				Apps: store, Stash: apps.NewComposeStash(), Secrets: hkdf, SecretDeps: deps, Identity: identity,
			})
			w := must(apps.DeleteWorkflow(store, inv, nc, nil, deps, identity))
			if len(w.Steps) != 4 {
				t.Errorf("the delete saga has %d steps, want its four", len(w.Steps))
			}
			sub, err := wireAppRelay(nc, store, identity, noRuntimeSecrets{}, log, func() string { return "cid" })
			if err != nil {
				t.Fatalf("wireAppRelay: %v", err)
			}
			_ = sub.Unsubscribe()
		})
	}
}

// noRuntimeSecrets is an apprelay.RuntimeSecrets this test never reaches.
type noRuntimeSecrets struct{}

func (noRuntimeSecrets) Read(context.Context, secrets.Actor, secrets.Ref) (secrets.Secret, error) {
	return secrets.Secret{}, nil
}
func (noRuntimeSecrets) Create(context.Context, secrets.Actor, secrets.Ref, secret.Value) (int, error) {
	return 0, nil
}
func (noRuntimeSecrets) Replace(context.Context, secrets.Actor, secrets.Ref, secret.Value) (int, error) {
	return 0, nil
}
func (noRuntimeSecrets) Delete(context.Context, secrets.Actor, secrets.Ref) error    { return nil }
func (noRuntimeSecrets) CreateKey(context.Context, secrets.Actor, secrets.Ref) error { return nil }
func (noRuntimeSecrets) Encrypt(context.Context, secrets.Actor, secrets.Ref, secret.Value) (secret.Value, error) {
	return secret.Value{}, nil
}
func (noRuntimeSecrets) Decrypt(context.Context, secrets.Actor, secrets.Ref, secret.Value) (secret.Value, error) {
	return secret.Value{}, nil
}
func (noRuntimeSecrets) DestroyKey(context.Context, secrets.Actor, secrets.Ref) error { return nil }
