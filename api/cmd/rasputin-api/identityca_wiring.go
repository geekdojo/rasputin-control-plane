package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The identity CA's leaves (geekdojo/geekdojo-brain#977, Identity 3.1).
//
// The identity CA (tlsca.IdentityConfig) signs six leaves the api mints and
// renews on its own sweeper, in <dataDir>/tls/<name>/. Each carries exactly
// one EKU. The identity service's unit and its database's load theirs by
// LoadCredential= at start, so a renewed leaf restarts the unit that reads it;
// the api's own client leaf's reload is the identity client's
// CloseIdleConnections when that client is wired (Identity 3.2, #978), and
// the two client leaves nothing in the api reads (the door's, #321) have no
// reload.
//
// They are not gated on any identity setting: keycloak.service will not start
// until its leaves exist, and only the api mints them.

const (
	// The leaf names, which are also their directories under <dataDir>/tls/.
	identityDBServerLeafName   = "identity-db-server"
	identityDBClientLeafName   = "identity-db-client"
	identityServerLeafName     = "identity-server"
	identityAPIClientLeafName  = "identity-api-client"
	identityDoorClientLeafName = "identity-door-client"
	identityRepairCodeLeafName = "identity-repair-code"

	// identityAPIClientCN is the api's client leaf's CommonName; the identity
	// service's administrator client admits that subject by client-x509.
	identityAPIClientCN = "rasputin-api"
	// identityDoorClientCN is the door's client leaf's CommonName. Relayed
	// browser traffic carries it, and no administrator client accepts it.
	identityDoorClientCN = "rasputin-door"
	// identityDBClientCN is the identity service's database login: the
	// database's cert auth maps the CommonName to its role.
	identityDBClientCN = "keycloak"
	// identityRepairCodeName is the repair-code socket's server name (#321):
	// its command sets it as ServerName and verifies by chain to the identity
	// CA. .invalid is reserved, so the name can never resolve anywhere.
	identityRepairCodeName = "repair-code.rasputin.invalid"

	// The units rasputin-os ships for the identity service and its database
	// (#973).
	identityDBUnit = "keycloak-db.service"
	identityUnit   = "keycloak.service"
)

// identityServerLeafSpec is the identity service's listener leaf: serverAuth
// for the one loopback address it binds. The api verifies it by chain to the
// identity CA alone (register row C26).
func identityServerLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{
		Usage:       tlsca.UsageServer,
		CommonName:  "rasputin identity service",
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
}

// identityDBServerLeafSpec is the identity database's listener leaf:
// serverAuth for the one loopback address it binds.
func identityDBServerLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{
		Usage:       tlsca.UsageServer,
		CommonName:  "rasputin identity database",
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
}

// identityAPIClientLeafSpec is the api's client leaf at the identity service:
// clientAuth with the subject its administrator client admits (register row
// C27).
func identityAPIClientLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: identityAPIClientCN}
}

// identityDoorClientLeafSpec is the door's client leaf at the identity
// service: clientAuth, with a subject no administrator client admits.
func identityDoorClientLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: identityDoorClientCN}
}

// identityDBClientLeafSpec is the identity service's client leaf at its
// database. Its key is also written as DER PKCS-8, the only form the
// service's database driver reads.
func identityDBClientLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: identityDBClientCN, KeyPKCS8: true}
}

// identityRepairCodeLeafSpec is the repair-code socket's server leaf (#321).
func identityRepairCodeLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{
		Usage:      tlsca.UsageServer,
		CommonName: "rasputin repair code",
		DNSNames:   []string{identityRepairCodeName},
	}
}

// wireIdentityLeaves builds the identity CA's sweeper and registers its six
// leaves; main starts its startup sweep with startLeafSweep and hands it to
// the scheduled leaf sweep. With no identity CA it returns nil, nil and
// touches neither run nor the disk: the leaves are off, and a nil sweeper is
// skipped everywhere it is passed. An error is a programming error (a
// duplicate or incomplete registration), which main treats as fatal.
//
// The registration order is the mint order on a first boot: the database's
// leaves, then the service's, so the one restart keycloak.service gets is the
// last, once everything it loads exists (the db-client leaf's restart is
// condition-skipped by the unit until the server leaf exists).
//
// apiClientReload is the api client leaf's reload: identityWiring.reload,
// nil unless the identity client is wired.
func wireIdentityLeaves(ca *tlsca.CA, dataDir string, run runFunc, apiClientReload func(context.Context, tlsca.LeafPaths) error) (*tlsca.LeafSweeper, error) {
	if ca == nil {
		return nil, nil
	}
	if run == nil {
		return nil, errors.New("identity leaves: the command runner is nil")
	}
	restart := func(unit string) func(context.Context, tlsca.LeafPaths) error {
		return func(ctx context.Context, _ tlsca.LeafPaths) error {
			return restartUnits(ctx, run, []string{identityDBUnit, identityUnit}, unit)
		}
	}
	sweeper := tlsca.NewLeafSweeper(ca)
	for _, c := range []struct {
		name   string
		spec   func() tlsca.LeafSpec
		reload func(context.Context, tlsca.LeafPaths) error
	}{
		{identityDBServerLeafName, identityDBServerLeafSpec, restart(identityDBUnit)},
		{identityDBClientLeafName, identityDBClientLeafSpec, restart(identityUnit)},
		{identityServerLeafName, identityServerLeafSpec, restart(identityUnit)},
		{identityAPIClientLeafName, identityAPIClientLeafSpec, apiClientReload},
		{identityDoorClientLeafName, identityDoorClientLeafSpec, nil},
		{identityRepairCodeLeafName, identityRepairCodeLeafSpec, nil},
	} {
		spec := c.spec
		if err := sweeper.Register(tlsca.LeafConsumer{
			Name:   c.name,
			Dir:    filepath.Join(dataDir, "tls", c.name),
			Spec:   func() (tlsca.LeafSpec, error) { return spec(), nil },
			Reload: c.reload,
		}); err != nil {
			return nil, fmt.Errorf("identity leaves: %w", err)
		}
	}
	return sweeper, nil
}

// identityLeafNames are the identity leaves this configuration holds and must
// renew: all six when the identity CA loaded, none otherwise. main checks them
// against the sweepers' registrations (verifyLeafConsumers).
func identityLeafNames(identityLoaded bool) []string {
	if !identityLoaded {
		return nil
	}
	return []string{identityDBServerLeafName, identityDBClientLeafName, identityServerLeafName,
		identityAPIClientLeafName, identityDoorClientLeafName, identityRepairCodeLeafName}
}
