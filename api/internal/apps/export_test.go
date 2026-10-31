package apps

import (
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
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
