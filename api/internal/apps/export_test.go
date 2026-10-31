package apps

import "github.com/geekdojo/rasputin-control-plane/proto"

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

// SecretComposeV1 is a custom compose that asks for the secret db-password.
const SecretComposeV1 = secretComposeV1
