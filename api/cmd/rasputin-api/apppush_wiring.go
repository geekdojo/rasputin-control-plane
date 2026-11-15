package main

import (
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
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
}

// registerAppPushWorkflows registers the four push-family app sagas through
// register, each unwrapped by must (workflowOrExit in main).
//
// It builds their app-identity switch, and builds it off
// (geekdojo/geekdojo-brain#1080): no tile is granted and there is no issuer,
// so no app is issued an identity and every deploy, revert, edit and upgrade
// sends the agent what it always has. #1081 wires the issuer and the grants.
func registerAppPushWorkflows(register func(jobs.Workflow), must func(jobs.Workflow, error) jobs.Workflow, d appPushDeps) {
	identity := apps.AppIdentity{}
	register(must(apps.DeployWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Secrets, identity)))
	// app.revert (#411): re-apply an app's previous compose, named by hash.
	// Its compose comes from the row, so it needs nothing from the catalog.
	register(must(apps.RevertWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Secrets, identity)))
	// app.edit (#410): replace a custom app's compose with one its owner sent.
	register(must(apps.EditWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Stash, d.Secrets, d.SecretDeps, identity)))
	// app.upgrade (#409): its new compose comes from the catalog store.
	register(must(apps.UpgradeWorkflow(d.Apps, d.Inventory, d.Conn, d.Rotate, d.Tiles, d.Secrets, d.SecretDeps, identity)))
}
