package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/artifactsig"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The identity service's client wiring (geekdojo/geekdojo-brain#978,
// Identity 3.2).
//
// RASPUTIN_IDENTITY_BACKEND selects the identity service, and nothing infers
// one:
//
//   - unset or empty: off (idclient.Disabled with ErrDisabled), at INFO;
//   - exactly "mock" on a dev build: idclient.Disabled with ErrMock, at WARN.
//     The mock refuses every call; nothing consumes identity locally until
//     the console signs in through it (Identity 4.7,
//     geekdojo/geekdojo-brain#989);
//   - exactly "mock" on a release build (artifactsig.ReleaseBuild, a
//     compile-time marker no setting or file can remove): off, with one
//     configfault ERROR, so a dev relaxation is never live on an appliance
//     (geekdojo/geekdojo-brain#982, auth-methodology.md §8 gate 3);
//   - exactly "keycloak": the real client over the api's identity-CA client
//     leaf, its Admin API session, and the identity.recover_admin job;
//   - anything else, a refused address, or an identity CA that did not load:
//     off, with one ERROR record carrying configfault=true and the setting.
//     The api still starts.
//
// The CA and the leaf paths are derived from the data dir: the api mints
// these files itself (#977), so no setting may point the client elsewhere.

const (
	identityModeOff      = "off"
	identityModeMock     = "mock"
	identityModeKeycloak = "keycloak"

	// identityRealm and identityAdminClient are the realm baseline's realm
	// and the administrator client the api's session logs in as (C27, C28).
	identityRealm       = "rasputin"
	identityAdminClient = adminguard.AdminClientID

	// identityCallTimeout bounds one call to the identity service. It bounds
	// I/O on a loopback socket and decides no state.
	identityCallTimeout = 30 * time.Second
	// identityRecoverStepTimeout bounds identity.recover_admin's one step:
	// a stop, a JVM run of kc.sh, a start and a few Admin API calls take a
	// few minutes at most. It only marks the job dead when it is far outside
	// that, and decides nothing else.
	identityRecoverStepTimeout = 15 * time.Minute

	// identityRecoverLauncher is the OS's admin recovery launcher
	// (rasputin-os, geekdojo/geekdojo-brain#1131): it runs kc.sh
	// bootstrap-admin as keycloak.service's own user, with that unit's
	// credentials and sandbox, and reads the secret from its stdin.
	identityRecoverLauncher = "/usr/lib/rasputin/identity/rasputin-keycloak-recover-admin.sh"
	// identityBaseline is the baseline the api tarball installs
	// (scripts/build-release.sh).
	identityBaseline = "/usr/share/rasputin/identity/realm-baseline.json"
	// identityLauncherPath is the launcher's whole environment: nothing is
	// inherited from the api's own (F-978-03). The launcher takes everything
	// else from keycloak.service itself.
	identityLauncherPath = "PATH=/usr/bin:/bin"
)

// runInFunc runs a command with exactly env as its environment and stdin as
// its standard input, and returns its combined output
// (execrun.CombinedOutputInput's shape).
type runInFunc func(ctx context.Context, env []string, stdin []byte, name string, args ...string) ([]byte, error)

// identityClient is the composition root's view of whichever client was
// selected: *idclient.Client or idclient.Disabled.
type identityClient interface {
	ClientCredentials(ctx context.Context, realm, clientID string, clientSecret *secret.Value) (secret.Value, error)
	Admin(ctx context.Context, token secret.Value, method, path string, in, out any) (idclient.Response, error)
	Ready(ctx context.Context) error
	Health(ctx context.Context) (idclient.HealthReport, error)
}

// identityWiring is what wireIdentity built.
type identityWiring struct {
	mode   string
	client identityClient
	// session is the api's Admin API session as rasputin-admin, over client;
	// under off and mock every call refuses with client's kind.
	session *idclient.Session
	// recoverer and reload are set only under keycloak.
	recoverer *recoveradmin.Recoverer
	reload    func(context.Context, tlsca.LeafPaths) error
}

// register registers identity.recover_admin, under keycloak only: no other
// mode has an identity service to recover.
func (w identityWiring) register(r interface{ Register(jobs.Workflow) }) {
	if w.recoverer != nil {
		r.Register(w.recoverer.Workflow())
	}
}

// wireIdentityFromEnv is main's one call: wireIdentity with this binary's
// release marker and the RASPUTIN_IDENTITY_* settings. It is bound here, not
// in main, so the release-tag test runs the same binding (TC-982-06).
func wireIdentityFromEnv(ctx context.Context, logger *slog.Logger, ca *tlsca.CA, dataDir string,
	run runFunc, runIn runInFunc, restored *atomic.Pointer[restoredFunc]) (identityWiring, error) {
	return wireIdentity(ctx, logger, artifactsig.ReleaseBuild(), identityBackendFromEnv(), identityAddrFromEnv(), identityMgmtAddrFromEnv(),
		ca, dataDir, run, runIn, restored)
}

// wireIdentity selects the identity service from backend and builds its
// client. release is the binary's release marker, passed in by the
// composition root: under it the mock is refused. It never reads the leaf files: a leaf absent at wiring is every
// first boot, minted moments later by the identity leaf sweep. It returns an
// error only for a programming error, which main treats as fatal; every
// refused setting is a configfault and the off client. restored is the
// holder the composition root sets to the restored alert once the alerts
// service exists (recoveradmin_trigger_wiring.go).
func wireIdentity(ctx context.Context, logger *slog.Logger, release bool, backend, addr, mgmtAddr string, ca *tlsca.CA, dataDir string,
	run runFunc, runIn runInFunc, restored *atomic.Pointer[restoredFunc]) (identityWiring, error) {
	disabled := func(mode string, kind error) (identityWiring, error) {
		c := idclient.Disabled{Kind: kind}
		s, err := identitySession(c, logger)
		if err != nil {
			return identityWiring{}, err
		}
		return identityWiring{mode: mode, client: c, session: s}, nil
	}
	configFault := func(setting, value, reason string) (identityWiring, error) {
		logger.ErrorContext(ctx, "identity service off: configuration refused",
			"configfault", true, "setting", setting, "value", value, "reason", reason)
		return disabled(identityModeOff, idclient.ErrDisabled)
	}
	switch backend {
	case "":
		logger.InfoContext(ctx, "identity service off: not configured", "setting", "RASPUTIN_IDENTITY_BACKEND")
		return disabled(identityModeOff, idclient.ErrDisabled)
	case identityModeMock:
		if release {
			return configFault("RASPUTIN_IDENTITY_BACKEND", backend, "the mock is refused on a release build")
		}
		logger.WarnContext(ctx, "identity service is the mock: every identity call is refused",
			"setting", "RASPUTIN_IDENTITY_BACKEND")
		return disabled(identityModeMock, idclient.ErrMock)
	case identityModeKeycloak:
		if run == nil || runIn == nil || restored == nil {
			return identityWiring{}, errors.New("identity service: a command runner or the restored holder is nil under keycloak")
		}
	default:
		return configFault("RASPUTIN_IDENTITY_BACKEND", backend, `not "keycloak" or "mock"`)
	}

	u, err := looptls.ParseAddr(addr)
	if err != nil {
		return configFault("RASPUTIN_IDENTITY_ADDR", addr, err.Error())
	}
	mu, err := looptls.ParseAddr(mgmtAddr)
	if err != nil {
		return configFault("RASPUTIN_IDENTITY_MGMT_ADDR", mgmtAddr, err.Error())
	}
	if ca == nil {
		return configFault("RASPUTIN_IDENTITY_BACKEND", backend, "the identity CA did not load")
	}
	paths := tlsca.LeafPathsIn(filepath.Join(dataDir, "tls", identityAPIClientLeafName))
	tlsCfg, err := looptls.NewClientTLS(ca.CertPEM, paths.CertPath, paths.KeyPath)
	if err != nil {
		return configFault("RASPUTIN_IDENTITY_BACKEND", backend, err.Error())
	}
	client, err := idclient.New(idclient.Config{Addr: u, MgmtAddr: mu, TLS: tlsCfg, CallTimeout: identityCallTimeout, Logger: logger})
	if err != nil {
		return configFault("RASPUTIN_IDENTITY_ADDR", addr, err.Error())
	}
	session, err := identitySession(client, logger)
	if err != nil {
		return identityWiring{}, err
	}
	rec, err := recoveradmin.New(recoveradmin.Deps{
		Identity:     client,
		Units:        identityUnits{run: run},
		Unit:         identityUnit,
		Bootstrap:    identityBootstrap(runIn),
		ReadBaseline: func() ([]byte, error) { return os.ReadFile(identityBaseline) },
		Rand:         rand.Reader,
		Restored:     restoredVia(restored),
		Log:          logger,
		StepTimeout:  identityRecoverStepTimeout,
	})
	if err != nil {
		return identityWiring{}, fmt.Errorf("identity service: %w", err)
	}
	return identityWiring{
		mode: identityModeKeycloak, client: client, session: session, recoverer: rec,
		reload: func(context.Context, tlsca.LeafPaths) error {
			client.CloseIdleConnections()
			return nil
		},
	}, nil
}

// identitySession is the api's Admin API session as rasputin-admin over c.
func identitySession(c identityClient, logger *slog.Logger) (*idclient.Session, error) {
	s, err := idclient.NewSession(idclient.SessionConfig{
		Login: c, Admin: c, Realm: identityRealm, ClientID: identityAdminClient, Log: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("identity service: %w", err)
	}
	return s, nil
}

// identityBootstrap runs the recovery launcher for clientID with the secret
// as one line on its stdin, never an argument, an environment entry or a
// file. The line is a copy, zeroed on return; the caller's Value is left
// as it was.
func identityBootstrap(runIn runInFunc) func(ctx context.Context, clientID string, clientSecret secret.Value) error {
	return func(ctx context.Context, clientID string, clientSecret secret.Value) error {
		in := make([]byte, 0, clientSecret.Len()+1)
		in = append(append(in, clientSecret.Reveal()...), '\n')
		defer clear(in)
		_, err := runIn(ctx, []string{identityLauncherPath}, in, identityRecoverLauncher, "run", clientID)
		return err
	}
}

// identityUnits is keycloak.service through systemctl.
type identityUnits struct{ run runFunc }

// Stop stops the unit.
func (u identityUnits) Stop(ctx context.Context) error {
	_, err := u.run(ctx, "systemctl", "stop", identityUnit)
	return err
}

// Start starts the unit.
func (u identityUnits) Start(ctx context.Context) error {
	_, err := u.run(ctx, "systemctl", "start", identityUnit)
	return err
}

// Active reports whether the unit is active or still starting. systemctl
// is-active exits non-zero for every other state, so its printed state is
// read first; a failure that printed no known state is an error.
func (u identityUnits) Active(ctx context.Context) (bool, error) {
	out, err := u.run(ctx, "systemctl", "is-active", identityUnit)
	switch strings.TrimSpace(string(out)) {
	case "active", "activating", "reloading":
		return true, nil
	case "inactive", "failed", "deactivating":
		return false, nil
	}
	if err == nil {
		err = errors.New("an unknown state")
	}
	return false, fmt.Errorf("reading whether %s is active: %w", identityUnit, err)
}
