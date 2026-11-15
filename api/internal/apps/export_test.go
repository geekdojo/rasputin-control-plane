package apps

import (
	"encoding/json"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The helpers the external apps_test package uses. Its tests need packages
// that import apps (alerts), which this package's own tests cannot.
var (
	StartNATS           = startNATS
	FakeDeployAgent     = fakeDeployAgent
	SeedComposeApp      = seedComposeApp
	RealRunner          = realRunner
	WiringSource        = wiringSource
	WatchDeploying      = watchDeploying
	AssertLedgerLacks   = assertLedgerLacks
	ReceiveDeployWithin = receiveWithin[proto.AppDeployCmd]
	FakeDeleteAgent     = fakeDeleteAgent
)

// ReleaseUnusedSecrets is app.upgrade's and app.edit's release_secrets step,
// for the F1.4 functional test (geekdojo/geekdojo-brain#783).
func ReleaseUnusedSecrets(store *Store, d DeleteSecretsDeps) jobs.DoFn {
	return releaseUnusedSecrets(store, d, composeChangeSpecAppID)
}

// SecretComposeV1 is a custom compose that asks for the secret db-password.
const SecretComposeV1 = secretComposeV1

// The helpers the geekdojo/geekdojo-brain#1081 tests in apps_test use to run
// the push family with the real relay issuer, which imports apps.
var (
	SeedUpgradeApp  = seedUpgradeApp
	FakePullAgent   = fakePullAgent
	TestSource      = testSource
	TestSecretDeps  = testSecretDeps
	LookupOf        = lookupOf
	UpgradeTile     = upgradeTile
	RevertSpecJSON  = revertSpec
	NewStepCtxNATS  = newStepCtxNATS
	DeployGoldenDir = deployGoldenDir
)

// ComposeV1 and ComposeV2 are the upgrade tests' two composes of the kuma tile.
const (
	ComposeV1 = composeV1
	ComposeV2 = composeV2
	// TestAppID is the app SeedUpgradeApp and UpgradedToV2 seed.
	TestAppID = testAppID
)

// UpgradedToV2 is upgradedToV2's stores: an app upgraded from ComposeV1 to
// ComposeV2, so a revert has a target.
func UpgradedToV2(t *testing.T) (*Store, *inventory.Store) {
	store, inv, _, _ := upgradedToV2(t)
	return store, inv
}

// WorkflowRun is runWorkflow's result, for apps_test.
type WorkflowRun struct {
	FailedAt string
	Err      error
	Results  map[string]json.RawMessage
	Logs     []string
}

// RunWorkflow runs w's steps in order, as runWorkflow does.
func RunWorkflow(t *testing.T, w jobs.Workflow, nc *nats.Conn, spec, jobID string) WorkflowRun {
	r := runWorkflow(t, w, nc, spec, jobID)
	return WorkflowRun{FailedAt: r.failedAt, Err: r.err, Results: r.results, Logs: r.logs}
}

// DeployWorkflowFor builds a deploy saga over a golden case's collaborators.
type DeployWorkflowFor = deployWorkflowFor

// DeployGoldenWire runs the golden case named name through build's push, as
// TestDeployGolden_WhatTheAgentReceives does, and returns what it records and
// the bytes the agent received.
func DeployGoldenWire(t *testing.T, build DeployWorkflowFor, name string) (string, []byte) {
	t.Helper()
	for _, c := range deployGoldenCases() {
		if c.name == name {
			return deployGoldenWire(t, build, c)
		}
	}
	t.Fatalf("no golden case %q", name)
	return "", nil
}
