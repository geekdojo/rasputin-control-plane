package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The secret store's wiring (ADR-0010; geekdojo/geekdojo-brain#758).
//
// RASPUTIN_SECRETSTORE_BACKEND selects the store, and nothing infers one:
//
//   - unset or empty: the store is off (secretstore.Disabled), at INFO;
//   - exactly "mock": the in-memory secretstore.Mock, at WARN;
//   - exactly "openbao": the real client, and the two store-CA leaves it
//     needs, registered with a sweeper of their own;
//   - anything else, a refused address, or no store CA: off, with one ERROR
//     record carrying configfault=true and the setting. The api still starts,
//     as the agent's configfault rule has it.
//
// The CA, the leaves and their paths are derived from the trust and data dirs:
// the api mints these files itself, and a path setting could only make the
// client trust or present something other than what was minted (Q-758-A).

const (
	// storeServerLeafName and storeClientLeafName are the store leaves' names
	// in the leaf sweep and its job report.
	storeServerLeafName = "openbao-server"
	storeClientLeafName = "openbao-client"
	// storeClientCN is the client leaf's CommonName. The store's cert role
	// (#804) pins allowed_common_names to it.
	storeClientCN = "rasputin-api"
	// storeUnit is the systemd unit rasputin-os ships for the store (#755).
	storeUnit = "openbao.service"
	// storeCallTimeout bounds one call to the store, a sys/health question
	// included. It bounds I/O on a loopback socket and decides no state.
	storeCallTimeout = 10 * time.Second
)

// The store modes main logs.
const (
	storeModeOff     = "off"
	storeModeMock    = "mock"
	storeModeOpenBao = "openbao"
)

// secretStore is the composition root's view of whichever store was
// selected. Consumers (#759, #761) declare their own narrower interfaces.
type secretStore interface {
	Health(ctx context.Context) (secretstore.Health, error)
	Read(ctx context.Context, token secret.Value, p secretstore.KVPath, version int) (secretstore.KV, error)
	Write(ctx context.Context, token secret.Value, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error)
	Versions(ctx context.Context, token secret.Value, p secretstore.KVPath) (secretstore.Metadata, error)
}

// storeWiring is what wireSecretStore built.
type storeWiring struct {
	mode  string
	store secretStore
	// client and sweeper are set only in the openbao mode.
	client  *secretstore.Client
	sweeper *tlsca.LeafSweeper
}

// registeredNames are the store leaves registered for renewal: none unless
// the store is openbao.
func (w storeWiring) registeredNames() []string {
	if w.sweeper == nil {
		return nil
	}
	return w.sweeper.RegisteredNames()
}

// runFunc runs a command and returns its combined output (execrun's shape).
type runFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// wireSecretStore selects the store from backend and builds it. It never reads
// the leaf files: a leaf absent at wiring is every first boot, minted
// moments later by startStoreSweep (F-758-01). It returns an error only when a
// leaf consumer will not register, which main treats as fatal; every refused
// setting is a configfault and a Disabled store.
func wireSecretStore(ctx context.Context, logger *slog.Logger, backend, addr string, storeCA *tlsca.CA, dataDir string, run runFunc) (storeWiring, error) {
	off := storeWiring{mode: storeModeOff, store: secretstore.Disabled{}}
	configFault := func(setting, value, reason string) (storeWiring, error) {
		logger.ErrorContext(ctx, "secret store off: configuration refused",
			"configfault", true, "setting", setting, "value", value, "reason", reason)
		return off, nil
	}
	switch backend {
	case "":
		logger.InfoContext(ctx, "secret store off: not configured", "setting", "RASPUTIN_SECRETSTORE_BACKEND")
		return off, nil
	case storeModeMock:
		logger.WarnContext(ctx, "secret store is the in-memory mock: nothing it holds survives a restart",
			"setting", "RASPUTIN_SECRETSTORE_BACKEND")
		return storeWiring{mode: storeModeMock, store: secretstore.NewMock(time.Now)}, nil
	case storeModeOpenBao:
	default:
		return configFault("RASPUTIN_SECRETSTORE_BACKEND", backend, `not "openbao" or "mock"`)
	}

	u, err := secretstore.ParseAddr(addr)
	if err != nil {
		return configFault("RASPUTIN_SECRETSTORE_ADDR", addr, err.Error())
	}
	if storeCA == nil {
		return configFault("RASPUTIN_SECRETSTORE_BACKEND", backend, "the store CA did not load")
	}
	clientDir := filepath.Join(dataDir, "tls", storeClientLeafName)
	clientPaths := tlsca.LeafPathsIn(clientDir)
	tlsCfg, err := secretstore.NewTLSConfig(storeCA.CertPEM, clientPaths.CertPath, clientPaths.KeyPath)
	if err != nil {
		return configFault("RASPUTIN_SECRETSTORE_BACKEND", backend, err.Error())
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: tlsCfg, CallTimeout: storeCallTimeout, Logger: logger})
	if err != nil {
		return configFault("RASPUTIN_SECRETSTORE_ADDR", addr, err.Error())
	}

	sweeper := tlsca.NewLeafSweeper(storeCA)
	if err := sweeper.Register(tlsca.LeafConsumer{
		Name:   storeServerLeafName,
		Dir:    filepath.Join(dataDir, "tls", storeServerLeafName),
		Spec:   func() (tlsca.LeafSpec, error) { return storeServerLeafSpec(), nil },
		Reload: restartStoreUnit(run),
	}); err != nil {
		return off, fmt.Errorf("secret store: %w", err)
	}
	if err := sweeper.Register(tlsca.LeafConsumer{
		Name: storeClientLeafName,
		Dir:  clientDir,
		Spec: func() (tlsca.LeafSpec, error) { return storeClientLeafSpec(), nil },
		Reload: func(context.Context, tlsca.LeafPaths) error {
			client.CloseIdleConnections()
			return nil
		},
	}); err != nil {
		return off, fmt.Errorf("secret store: %w", err)
	}
	return storeWiring{mode: storeModeOpenBao, store: client, client: client, sweeper: sweeper}, nil
}

// storeServerLeafSpec is the store listener's leaf: serverAuth, for the one
// loopback address it binds.
func storeServerLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{
		Usage:       tlsca.UsageServer,
		CommonName:  "rasputin secret store",
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
}

// storeClientLeafSpec is the api's client leaf at the store: clientAuth, with
// the CommonName the store's cert role allows. The client reads it from disk
// at every handshake (secretstore.NewTLSConfig), so a call made while it is
// absent is refused rather than sent unauthenticated.
func storeClientLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: storeClientCN}
}

// restartStoreUnit is the server leaf's reload: the store reads its leaf only
// at start, through LoadCredential. On first boot the unit was skipped because
// the leaf did not exist, and after a crash loop it sits in failed, so the
// recovery #755 hands over is reset-failed and then restart; try-restart would
// leave the skipped, inactive unit alone. It runs only on the fact of a fresh
// mint.
func restartStoreUnit(run runFunc) func(context.Context, tlsca.LeafPaths) error {
	return func(ctx context.Context, _ tlsca.LeafPaths) error {
		for _, verb := range []string{"reset-failed", "restart"} {
			if _, err := run(ctx, "systemctl", verb, storeUnit); err != nil {
				return err
			}
		}
		return nil
	}
}

// startStoreSweep mints and renews the store leaves once, now, in a goroutine
// of its own, so both leaves exist soon after start whether or not HTTPS is
// configured (F-758-02). Start never waits on it: a mint waits on the store
// CA's LeafClock (the clock gate), and a restart on systemd. The scheduled
// leaf sweep renews them after that. It does nothing, and returns nil, when
// no store sweeper was built. The channel yields the one report, for tests.
func startStoreSweep(ctx context.Context, sweeper *tlsca.LeafSweeper, logger *slog.Logger) <-chan tlsca.LeafSweepReport {
	if sweeper == nil {
		return nil
	}
	done := make(chan tlsca.LeafSweepReport, 1)
	go func() {
		defer close(done)
		done <- sweeper.Sweep(ctx, func(level, msg string) {
			lvl := slog.LevelInfo
			if level == "warn" {
				lvl = slog.LevelWarn
			}
			logger.Log(ctx, lvl, msg, "component", "secretstore")
		})
	}()
	return done
}
