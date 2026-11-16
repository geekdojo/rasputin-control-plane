package main

import (
	"log/slog"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apprelay"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// appPushDeps are the collaborators of the four app sagas that push a compose
// to an agent: app.deploy, app.revert, app.edit and app.upgrade. main builds
// each one and passes it here.
type appPushDeps struct {
	Apps      *apps.Store
	Inventory *inventory.Store
	Conn      *nats.Conn
	Rotate    apps.LeafRotator
	// Stash holds an app.edit's compose, never the job spec; the server is
	// given the same stash, and the workflow discards what it holds when the
	// job ends (#410).
	Stash *apps.ComposeStash
	// Tiles is the catalog store's lookup: app.upgrade's new compose comes
	// from it and nowhere else (#409).
	Tiles      apps.TileLookup
	Secrets    apps.SecretSource
	SecretDeps apps.DeleteSecretsDeps
	// Identity is the app-identity switch newAppIdentity builds; the same
	// value goes to the delete saga and the relay service.
	Identity apps.AppIdentity
}

// registerAppPushWorkflows registers the four push-family app sagas through
// register, each unwrapped by must (workflowOrExit in main), with the
// app-identity switch main built (newAppIdentity).
func registerAppPushWorkflows(register func(jobs.Workflow), must func(jobs.Workflow, error) jobs.Workflow, d appPushDeps) {
	identity := d.Identity
	register(must(apps.DeployWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Secrets, identity)))
	// app.revert (#411): re-apply an app's previous compose, named by hash.
	// Its compose comes from the row, so it needs nothing from the catalog.
	register(must(apps.RevertWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Secrets, identity)))
	// app.edit (#410): replace a custom app's compose with one its owner sent.
	register(must(apps.EditWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Stash, d.Secrets, d.SecretDeps, identity)))
	// app.upgrade (#409): its new compose comes from the catalog store.
	register(must(apps.UpgradeWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Tiles, d.Secrets, d.SecretDeps, identity)))
}

// appIdentityGrants are the catalog tiles granted a runtime identity
// (geekdojo/geekdojo-brain#1081). Empty: no tile is granted, so no app is
// issued a relay socket, every deploy sends the agent what it always has,
// and the delete saga keeps its four steps. A grant is a change to this list
// in an api release, never a setting (ADR-0011).
var appIdentityGrants = []string{}

// newAppIdentity builds the app-identity switch over appIdentityGrants and an
// Issuer that is always built (F-1081-05): with no controlplane CA it refuses
// each Issue, so a granted app's push is refused while the api and every
// other app carry on.
func newAppIdentity(cpCA *tlsca.CA, conn *nats.Conn, inv *inventory.Store) (apps.AppIdentity, error) {
	d := apprelay.IssuerDeps{Bus: conn, Silence: inv}
	if cpCA != nil {
		d.Signer, d.CACert, d.CAPEM = cpCA, cpCA.Cert, cpCA.CertPEM
	}
	issuer, err := apprelay.NewIssuer(d)
	if err != nil {
		return apps.AppIdentity{}, err
	}
	return apps.NewAppIdentity(appIdentityGrants, issuer)
}

// wireAppRelay builds the relay service and its bus endpoint over identity,
// and subscribes it on conn. main calls it before agents are admitted to the
// bus (geekdojo/geekdojo-brain#623). ids is the correlation id source.
func wireAppRelay(conn *nats.Conn, appsStore *apps.Store, identity apps.AppIdentity, secretsSvc apprelay.RuntimeSecrets, logger *slog.Logger, ids func() string) (*nats.Subscription, error) {
	svc, err := apprelay.NewService(apprelay.ServiceDeps{Apps: appsStore, Grants: identity, Index: appsStore, Secrets: secretsSvc})
	if err != nil {
		return nil, err
	}
	h, err := apprelay.NewHandler(apprelay.HandlerDeps{Service: svc, Log: logger, IDs: ids})
	if err != nil {
		return nil, err
	}
	return h.Subscribe(conn)
}
