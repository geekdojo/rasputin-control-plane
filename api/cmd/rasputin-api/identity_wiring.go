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
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The identity service's client wiring (geekdojo/geekdojo-brain#978,
// Identity 3.2).
//
// RASPUTIN_IDENTITY_BACKEND selects the identity service, and nothing infers
// one:
//
//   - unset or empty: off (idclient.Disabled with ErrDisabled), at INFO;
//   - exactly "mock": idclient.Disabled with ErrMock, at WARN; the mock's
//     behaviour is Identity 3.6's (#982);
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
	identityAdminClient = "rasputin-admin"

	// identityCallTimeout bounds one call to the identity service. It bounds
	// I/O on a loopback socket and decides no state.
	identityCallTimeout = 30 * time.Second
	// identityRecoverStepTimeout bounds identity.recover_admin's one step:
	// a stop, a JVM run of kc.sh, a start and a few Admin API calls take a
	// few minutes at most. It only marks the job dead when it is far outside
	// that, and decides nothing else.
	identityRecoverStepTimeout = 15 * time.Minute

	// The identity service's installed files on an appliance (rasputin-os,
	// #973) and the baseline the api tarball installs
	// (scripts/build-release.sh).
	identityKCSh       = "/usr/lib/keycloak/bin/kc.sh"
	identityKCConf     = "/etc/rasputin/identity/keycloak.conf"
	identityBaseline   = "/usr/share/rasputin/identity/realm-baseline.json"
	identityConfigFlag = "--config-file=" + identityKCConf
)

// identityBootstrapEnv is kc.sh's whole environment for the recovery
// command, before the secret's variable: PATH, and keycloak.service's JVM
// variables (platform.md §3.2). Nothing is inherited from the api's own
// environment (F-978-03).
var identityBootstrapEnv = []string{
	"PATH=/usr/bin:/bin",
	"JAVA_HOME=/usr/lib/temurin-jre",
	"MALLOC_ARENA_MAX=2",
	"JAVA_OPTS_KC_HEAP=-Xms128m -Xmx384m",
	"JAVA_OPTS_APPEND=-XX:-UsePerfData -XX:ErrorFile=/dev/null -XX:-CreateCoredumpOnCrash -Djava.awt.headless=true " +
		"-Djava.net.preferIPv4Stack=true " +
		"-Dcom.arjuna.ats.internal.arjuna.utils.processImplementation=com.arjuna.ats.internal.arjuna.utils.UuidProcessId",
}

// runEnvFunc runs a command with exactly env as its environment and returns
// its combined output (execrun.CombinedOutputEnv's shape).
type runEnvFunc func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

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

// wireIdentity selects the identity service from backend and builds its
// client. It never reads the leaf files: a leaf absent at wiring is every
// first boot, minted moments later by the identity leaf sweep. It returns an
// error only for a programming error, which main treats as fatal; every
// refused setting is a configfault and the off client.
func wireIdentity(ctx context.Context, logger *slog.Logger, backend, addr, mgmtAddr string, ca *tlsca.CA, dataDir string,
	run runFunc, runEnv runEnvFunc) (identityWiring, error) {
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
		logger.WarnContext(ctx, "identity service is the mock: every identity call is refused",
			"setting", "RASPUTIN_IDENTITY_BACKEND")
		return disabled(identityModeMock, idclient.ErrMock)
	case identityModeKeycloak:
		if run == nil || runEnv == nil {
			return identityWiring{}, errors.New("identity service: a command runner is nil under keycloak")
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
		Bootstrap:    identityBootstrap(runEnv),
		ReadBaseline: func() ([]byte, error) { return os.ReadFile(identityBaseline) },
		Rand:         rand.Reader,
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

// identityBootstrap runs kc.sh's recovery command with the installed config
// file and identityBootstrapEnv plus env, which carries the temporary secret;
// the secret never reaches an argument.
func identityBootstrap(runEnv runEnvFunc) func(ctx context.Context, args, env []string) error {
	return func(ctx context.Context, args, env []string) error {
		full := append(append([]string{}, identityBootstrapEnv...), env...)
		defer clear(full)
		_, err := runEnv(ctx, full, identityKCSh, append([]string{identityConfigFlag}, args...)...)
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
