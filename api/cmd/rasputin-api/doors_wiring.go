package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The sign-in doors' wiring (geekdojo/geekdojo-brain#983). main builds the
// door table once from the cluster id, then hands the same table and the one
// withheld predicate to the nameserver's DoorSource, the mesh projection, the
// two door leaves and the :443 certificate selection. Serving the doors'
// pages is Identity 4.3 and 4.4; this wires their names, records and leaves.

// The door leaves' names in the one leaf sweep.
const (
	signInHomeLeafName = doors.HomeName
	signInAppLeafName  = doors.AppName
)

// wireDoorTable resolves the door table and logs what it decided. It reports
// false, doors off, for an absent or empty cluster id (INFO) and for a refused
// one (ERROR, a configfault); the api starts either way.
func wireDoorTable(ctx context.Context, logger *slog.Logger, table doors.Table, err error) bool {
	var refused *doors.RefusedError
	switch {
	case err == nil:
		logger.InfoContext(ctx, "sign-in doors on", "home", table.Home.Host, "app", table.App.Host)
		return true
	case errors.Is(err, doors.ErrNoClusterID):
		logger.InfoContext(ctx, "sign-in doors off: no cluster id", "setting", "RASPUTIN_CLUSTER_ID")
	case errors.As(err, &refused):
		logger.ErrorContext(ctx, "sign-in doors off: cluster id refused",
			"configfault", true, "setting", "RASPUTIN_CLUSTER_ID", "cluster_id", refused.ClusterID, "reason", refused.Reason)
	default:
		logger.ErrorContext(ctx, "sign-in doors off: cluster id refused",
			"configfault", true, "setting", "RASPUTIN_CLUSTER_ID", "err", err.Error())
	}
	return false
}

// appLister is what the withheld predicate reads: the apps store.
type appLister interface {
	List(ctx context.Context) ([]*apps.App, error)
}

// appDoorWithholding is the one decision whether the app door is withheld:
// while any app holds a reserved name (doors.WithheldBy), or while the apps
// list cannot be read, in which case it logs WARN and withholds (fail closed).
// Every consumer reads it through check or withheld, so none of them can
// disagree about a store error.
type appDoorWithholding struct {
	ctx  context.Context
	apps appLister
	log  *slog.Logger
}

// check returns the reserved app name withholding the door, and whether it is
// withheld. A store error is withheld with app "" and err set.
func (w appDoorWithholding) check() (app string, withheld bool, err error) {
	list, err := w.apps.List(w.ctx)
	if err != nil {
		w.log.WarnContext(w.ctx, "app sign-in address withheld: the apps list could not be read", "err", err.Error())
		return "", true, err
	}
	names := make([]string, 0, len(list))
	for _, a := range list {
		names = append(names, a.Name)
	}
	app = doors.WithheldBy(names)
	return app, app != "", nil
}

// withheld is the predicate the nameserver and the mesh projection take.
func (w appDoorWithholding) withheld() bool {
	_, withheld, _ := w.check()
	return withheld
}

// appDoorSpec is the app door's leaf spec while the door is not withheld, and
// an error naming the reason while it is, so neither the start load nor the
// sweep mints a leaf for a withheld door.
func appDoorSpec(table doors.Table, w appDoorWithholding) func() (tlsca.LeafSpec, error) {
	return func() (tlsca.LeafSpec, error) {
		app, withheld, err := w.check()
		switch {
		case err != nil:
			return tlsca.LeafSpec{}, fmt.Errorf("app sign-in address withheld: the apps list could not be read: %w", err)
		case withheld:
			return tlsca.LeafSpec{}, fmt.Errorf("app sign-in address withheld: app %q holds a reserved name", app)
		}
		return table.App.LeafSpec(), nil
	}
}

// warnIfWithheld logs the one start-up WARN naming the app that withholds the
// app door. After start the sweep's spec line and the app-reserved-name alert
// carry it.
func warnIfWithheld(ctx context.Context, logger *slog.Logger, w appDoorWithholding) {
	if app, withheld, err := w.check(); withheld && err == nil {
		logger.WarnContext(ctx, "app sign-in address withheld", "app", app,
			"reason", "an app holds a name kept for the cluster's sign-in addresses")
	}
}

// doorLeaf is one door's leaf holder and the sweep consumer that renews it.
type doorLeaf struct {
	door     doors.Door
	holder   *apiLeaf
	consumer tlsca.LeafConsumer
}

// newDoorLeaf builds door's holder, kept in <dataDir>/tls/<door name>. Its
// mint goes through cpCA.MintLeafToDisk, so it reuses a usable leaf and
// waits on the CA's clock gate; spec is re-read on every mint and every sweep.
// While nothing is loaded, a handshake for the door is refused with an error
// naming it, never answered with the api leaf.
func newDoorLeaf(cpCA *tlsca.CA, dataDir string, door doors.Door, spec func() (tlsca.LeafSpec, error)) doorLeaf {
	dir := filepath.Join(dataDir, "tls", door.Name)
	holder := &apiLeaf{
		refusal: fmt.Errorf("rasputin-api: sign-in door %s (%s): no leaf loaded", door.Name, door.Host),
		mint: func(net.IP) (tlsca.LeafPaths, error) {
			if cpCA == nil {
				return tlsca.LeafPaths{}, errors.New("no controlplane CA")
			}
			s, err := spec()
			if err != nil {
				return tlsca.LeafPaths{}, err
			}
			return cpCA.MintLeafToDisk(dir, s)
		},
	}
	return doorLeaf{
		door:   door,
		holder: holder,
		consumer: tlsca.LeafConsumer{
			Name: door.Name,
			Dir:  dir,
			Spec: spec,
			Reload: func(context.Context, tlsca.LeafPaths) error {
				return holder.refresh(nil)
			},
		},
	}
}

// doorLeaves are both doors' leaves, built only when HTTPS and doors are on.
type doorLeaves struct {
	home, app doorLeaf
}

func newDoorLeaves(cpCA *tlsca.CA, dataDir string, table doors.Table, w appDoorWithholding) doorLeaves {
	home := table.Home
	return doorLeaves{
		home: newDoorLeaf(cpCA, dataDir, home, func() (tlsca.LeafSpec, error) { return home.LeafSpec(), nil }),
		app:  newDoorLeaf(cpCA, dataDir, table.App, appDoorSpec(table, w)),
	}
}

func (d doorLeaves) all() []doorLeaf { return []doorLeaf{d.home, d.app} }

// register adds both consumers to the one leaf sweep.
func (d doorLeaves) register(sweeper *tlsca.LeafSweeper) error {
	for _, l := range d.all() {
		if err := sweeper.Register(l.consumer); err != nil {
			return err
		}
	}
	return nil
}

// load loads each door's leaf once, after the clock gate. A failure leaves the
// holder empty, so its handshakes are refused, and is logged at WARN.
func (d doorLeaves) load(ctx context.Context, logger *slog.Logger) {
	for _, l := range d.all() {
		if err := l.holder.refresh(nil); err != nil {
			logger.WarnContext(ctx, "sign-in leaf not loaded", "door", l.door.Name, "err", err.Error())
		}
	}
}

// byHost maps each door's host to its holder, for sniCertificate.
func (d doorLeaves) byHost() map[string]*apiLeaf {
	return map[string]*apiLeaf{d.home.door.Host: d.home.holder, d.app.door.Host: d.app.holder}
}

// sniCertificate is :443's certificate selection. A door's host, compared
// lowercased with any trailing dot trimmed, gets its own holder's leaf, or the
// holder's refusal while it is empty: a door name is never answered with the
// api leaf. Every other SNI, and none, gets the api leaf. The node listener
// (:8443, nodeListenerCert) never serves a door leaf.
func sniCertificate(api *apiLeaf, doorsByHost map[string]*apiLeaf) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
		if d, ok := doorsByHost[name]; ok {
			return d.getCertificate(hello)
		}
		return api.getCertificate(hello)
	}
}

// appDeletedHandler is the AppDeleted fact's handler: with the reserved app
// gone the app door may no longer be withheld, so it refreshes the app door's
// holder (appHolder, nil with HTTPS off), which mints and loads its leaf once
// nothing withholds it, and re-runs the tailnet projection. Failures are
// logged at WARN; the leaf sweep and the mesh reconcile stay the safety nets.
func appDeletedHandler(ctx context.Context, logger *slog.Logger, appHolder *apiLeaf, reconcile func(context.Context) error) nats.MsgHandler {
	return func(m *nats.Msg) {
		if appHolder != nil {
			if err := appHolder.refresh(nil); err != nil {
				logger.WarnContext(ctx, "app sign-in leaf not loaded after an app was removed", "subject", m.Subject, "err", err.Error())
			}
		}
		if err := reconcile(ctx); err != nil {
			logger.WarnContext(ctx, "tailnet DNS projection failed after an app was removed", "subject", m.Subject, "err", err.Error())
		}
	}
}

// subscribeAppDeleted subscribes h to every app's AppDeleted event, the one
// the app.delete saga publishes once the row is gone.
func subscribeAppDeleted(conn *nats.Conn, h nats.MsgHandler) (*nats.Subscription, error) {
	return conn.Subscribe(proto.AppChangeSubject("*", proto.AppDeleted), h)
}

// deviceRenamedFunc raises the tailnet-device-renamed alert.
type deviceRenamedFunc func(ctx context.Context, hsID, from, to string) error

// deviceRenamedVia is mesh.Config.DeviceRenamed, late-bound through holder
// because the alerts service is built after the mesh service. While the holder
// is unset it only logs, the rename itself having been logged by the mesh.
func deviceRenamedVia(holder *atomic.Pointer[deviceRenamedFunc], logger *slog.Logger) func(ctx context.Context, hsID, from, to string) {
	return func(ctx context.Context, hsID, from, to string) {
		f := holder.Load()
		if f == nil {
			logger.WarnContext(ctx, "tailnet device renamed before alerts were wired: no alert raised", "hs_id", hsID, "from", from, "to", to)
			return
		}
		if err := (*f)(ctx, hsID, from, to); err != nil {
			logger.WarnContext(ctx, "tailnet device renamed: alert not raised", "hs_id", hsID, "err", err.Error())
		}
	}
}
