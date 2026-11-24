package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/restart"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The break-glass wiring (geekdojo/geekdojo-brain#321): identity.restart, the
// break-glass service, its repair-code socket and the no-last-resort
// warning.

// identityRestartWiring is identity.restart under keycloak, with
// identity.recover's two guards: the monitor's quiesce hold and the restore
// in progress. It is nil off keycloak, where there is no service to
// restart.
func identityRestartWiring(mon *identitystate.Monitor, restores interface{ Active() (string, bool) }, run runFunc,
	log *slog.Logger) (*restart.Restarter, error) {
	if mon == nil {
		return nil, nil
	}
	return restart.New(restart.Deps{
		Run: run, Held: mon.Held, Restoring: restores.Active, DBUnit: identityDBUnit, Unit: identityUnit,
		Log: log, StepTimeout: identityRecoverStepTimeout,
	})
}

// breakglassDeps is what the break-glass wiring takes from main.
type breakglassDeps struct {
	// monitor and restarter are nil off keycloak.
	monitor   *identitystate.Monitor
	restarter *restart.Restarter
	alerts    breakglass.Alerts
	jobs      breakglass.Jobs
	host      string
	primaryIP func() net.IP
	dataDir   string
	// identityCA is whether the identity CA loaded, so the socket's leaf
	// exists.
	identityCA bool
	log        *slog.Logger
}

// breakglassWiring is what wireBreakglass built: both nil when break-glass
// is off.
type breakglassWiring struct {
	svc    *breakglass.Service
	socket *breakglass.Socket
}

// wireBreakglass builds the service and its socket. It does no I/O; main
// serves the socket (Socket.Start). With no cluster id (a dev run) there is no console
// origin to type a code at, so break-glass is off, at INFO. An error is a
// programming error, which main treats as fatal.
func wireBreakglass(ctx context.Context, d breakglassDeps) (breakglassWiring, error) {
	if d.alerts == nil || d.jobs == nil || d.primaryIP == nil || d.log == nil || d.dataDir == "" {
		return breakglassWiring{}, errors.New("break-glass: a collaborator is nil")
	}
	if d.host == "" {
		d.log.InfoContext(ctx, "break-glass off: no cluster id", "component", "breakglass", "setting", "RASPUTIN_CLUSTER_ID")
		return breakglassWiring{}, nil
	}
	deps := breakglass.Deps{
		Now: time.Now, Rand: rand.Reader, IDs: rand.Text, Log: d.log, Alerts: d.alerts, Jobs: d.jobs,
		Busy: func(context.Context) (string, bool) { return "", false },
		Facts: breakglass.Facts{ConsoleHost: d.host, PrimaryIP: d.primaryIP,
			BMCHost: markerPresent(filepath.Join(d.dataDir, "bmc-host"))},
	}
	// A nil *Monitor in the interface would read as a sign-in service.
	if d.monitor != nil && d.restarter != nil {
		deps.Identity, deps.Busy = d.monitor, d.restarter.Busy
	}
	svc, err := breakglass.New(deps)
	if err != nil {
		return breakglassWiring{}, err
	}
	var leaf *tlsca.LeafPaths
	if d.identityCA {
		p := tlsca.LeafPathsIn(filepath.Join(d.dataDir, "tls", identityRepairCodeLeafName))
		leaf = &p
	}
	sock, err := breakglass.NewSocket(breakglass.SocketDeps{
		Issuer: svc, Log: d.log, Leaf: leaf, Dir: repairSocketDir, OwnerUID: os.Geteuid(),
		PeerUID: breakglass.PeerUID, Linux: runtime.GOOS == "linux",
	})
	if err != nil {
		return breakglassWiring{}, err
	}
	return breakglassWiring{svc: svc, socket: sock}, nil
}

// markerPresent reports whether the marker file at path exists now.
func markerPresent(path string) func() bool {
	return func() bool {
		_, err := os.Stat(path)
		return err == nil
	}
}

// lastResortAlerts is the no-last-resort warning over the console password
// store and the control plane's own authorized_keys at akPath.
func lastResortAlerts(console interface {
	CurrentHashID(ctx context.Context) (string, error)
}, akPath string) func(ctx context.Context, now time.Time) []proto.Alert {
	return alerts.LastResort{ConsoleHash: console.CurrentHashID, KeyLines: authorizedKeyLines(akPath)}.Alerts
}

// authorizedKeyLines reads the valid key lines of the authorized_keys file
// at path when asked; an absent file has none.
func authorizedKeyLines(path string) func() ([]string, error) {
	return func() ([]string, error) {
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return setup.AuthorizedKeyLines(data), nil
	}
}
