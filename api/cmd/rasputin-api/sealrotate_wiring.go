package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// kernelUUID is the key-id source rasputin-seal-key.sh uses (#803).
const kernelUUID = "/proc/sys/kernel/random/uuid"

// sealRotateDeps is what the seal-key rotation's wiring takes from main
// (geekdojo/geekdojo-brain#830).
type sealRotateDeps struct {
	mode    string
	addr    string
	storeCA *tlsca.CA
	// store is the api's own store client, for sys/health.
	store sealrotate.Store
	run   runFunc
	// monitor is the store's readiness monitor; it is nil when no backend
	// was requested, and required under openbao.
	monitor    *storestate.Monitor
	restores   sealrotate.Restores
	jobRunning func(ctx context.Context, jobID string) (bool, error)
	rand       io.Reader
	now        func() time.Time
	log        *slog.Logger
	// afterStoreRestart runs once after each store restart the rotation
	// performs (#833, F-833-01); required under openbao.
	afterStoreRestart func(context.Context)
}

// sealRotate is what sealRotateWiring built.
type sealRotate struct {
	// workflow is registered in every mode, so a run submitted when the
	// backend is not openbao becomes a job that fails at validate with a
	// sentence and a job-failed alert (F-830-04). It has no scheduler entry
	// in any mode: an operator starts it.
	workflow jobs.Workflow
	// gate and alerts are set only under openbao.
	gate   *sealrotate.Gate
	alerts func(ctx context.Context, now time.Time) []proto.Alert
	// restart is the store restart the rotator was given (Deps.Restart);
	// set only under openbao.
	restart func(ctx context.Context) error
}

// captureLock is the backup's capture lock: the gate under openbao, nil (no
// lock) otherwise. A nil *Gate is never handed over as a non-nil interface.
func (w sealRotate) captureLock() storage.CaptureLock {
	if w.gate == nil {
		return nil
	}
	return w.gate
}

// sealGuard is the restore's seal check: the gate under openbao, nil (no
// check) otherwise. A nil *Gate is never handed over as a non-nil interface.
func (w sealRotate) sealGuard() storage.SealGuard {
	if w.gate == nil {
		return nil
	}
	return w.gate
}

// storeAlerts is the alert source SetStoreAlerts receives: readiness's,
// joined with the incomplete-rotation alert under openbao. Nil when there is
// no readiness source.
func (w sealRotate) storeAlerts(readiness func(context.Context, time.Time) []proto.Alert) func(context.Context, time.Time) []proto.Alert {
	if readiness == nil {
		return nil
	}
	if w.alerts == nil {
		return readiness
	}
	rot := w.alerts
	return func(ctx context.Context, now time.Time) []proto.Alert {
		return append(readiness(ctx, now), rot(ctx, now)...)
	}
}

// sealRotateWiring builds the rotator in every mode. Under openbao it gets
// the real collaborators: a rotation client presenting a fresh store-CA leaf
// for the rasputin-seal-rotate role on each handshake, the seal files at
// their production paths, the capture gate, the store unit's restart and the
// readiness monitor's quiesce. In any other mode it gets refusing stand-ins,
// which its validate never reaches.
func sealRotateWiring(d sealRotateDeps) (sealRotate, error) {
	if d.log == nil {
		return sealRotate{}, errors.New("seal rotation: the logger is nil")
	}
	if d.mode != storeModeOpenBao {
		rot, err := sealrotate.NewRotator(sealrotate.Config{Enabled: false, UnsealWait: sealrotate.UnsealWait}, offSealDeps(d.log))
		if err != nil {
			return sealRotate{}, fmt.Errorf("seal rotation: %w", err)
		}
		return sealRotate{workflow: rot.Workflow()}, nil
	}
	switch {
	case d.storeCA == nil:
		return sealRotate{}, errors.New("seal rotation: the store CA is nil under openbao")
	case d.monitor == nil:
		return sealRotate{}, errors.New("seal rotation: the readiness monitor is nil under openbao")
	case d.store == nil || d.run == nil || d.restores == nil || d.jobRunning == nil || d.rand == nil || d.now == nil || d.afterStoreRestart == nil:
		return sealRotate{}, errors.New("seal rotation: a collaborator is nil")
	}
	u, err := secretstore.ParseAddr(d.addr)
	if err != nil {
		return sealRotate{}, fmt.Errorf("seal rotation: %w", err)
	}
	tlsCfg, err := secretstore.NewMintedTLSConfig(d.storeCA.CertPEM, sealrotate.MintRotationLeaf(d.storeCA))
	if err != nil {
		return sealRotate{}, fmt.Errorf("seal rotation: %w", err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: tlsCfg, CallTimeout: storeCallTimeout, Logger: d.log})
	if err != nil {
		return sealRotate{}, fmt.Errorf("seal rotation: %w", err)
	}
	files, err := sealrotate.NewFiles(sealrotate.ProductionPaths())
	if err != nil {
		return sealRotate{}, fmt.Errorf("seal rotation: %w", err)
	}
	gate, err := sealrotate.NewGate(files, d.jobRunning, d.log)
	if err != nil {
		return sealRotate{}, fmt.Errorf("seal rotation: %w", err)
	}
	unit := restartStoreUnit(d.run, d.afterStoreRestart)
	restart := func(ctx context.Context) error { return unit(ctx, tlsca.LeafPaths{}) }
	rot, err := sealrotate.NewRotator(sealrotate.Config{Enabled: true, UnsealWait: sealrotate.UnsealWait}, sealrotate.Deps{
		Store:      d.store,
		Rotate:     client,
		Restart:    restart,
		Files:      files,
		Gate:       gate,
		Quiesce:    d.monitor.Quiesce,
		Restores:   d.restores,
		Rand:       d.rand,
		KeyID:      sealrotate.KernelKeyID(kernelUUID),
		Log:        d.log,
		JobRunning: d.jobRunning,
		Now:        d.now,
	})
	if err != nil {
		return sealRotate{}, fmt.Errorf("seal rotation: %w", err)
	}
	return sealRotate{workflow: rot.Workflow(), gate: gate, alerts: rot.Alerts, restart: restart}, nil
}

// errSealRotateOff is every stand-in's refusal.
var errSealRotateOff = errors.New("seal rotation: the secret store is not openbao")

// offSealDeps are the stand-ins a rotator outside openbao is built with.
// Each refuses; validate refuses before any is called.
func offSealDeps(log *slog.Logger) sealrotate.Deps {
	off := offSeal{}
	return sealrotate.Deps{
		Store: secretstore.Disabled{}, Rotate: off, Files: off, Gate: off, Restores: off, Rand: off,
		Restart:    func(context.Context) error { return errSealRotateOff },
		Quiesce:    func(string, storestate.QuiesceReason) func() { return func() {} },
		KeyID:      func() (sealrotate.KeyID, error) { return "", errSealRotateOff },
		Log:        log,
		JobRunning: func(context.Context, string) (bool, error) { return false, errSealRotateOff },
		Now:        time.Now,
	}
}

// offSeal is the refusing stand-in for every interface the rotator takes.
type offSeal struct{}

func (offSeal) CertLogin(context.Context, string) (secret.Value, error) {
	return secret.Value{}, errSealRotateOff
}
func (offSeal) RotateRoot(context.Context, secret.Value) error        { return errSealRotateOff }
func (offSeal) State() (sealrotate.Tree, error)                       { return sealrotate.Tree{}, errSealRotateOff }
func (offSeal) WriteRotationKey(sealrotate.KeyID, secret.Value) error { return errSealRotateOff }
func (offSeal) WriteSealKey(secret.Value) error                       { return errSealRotateOff }
func (offSeal) ReadRotationKey(sealrotate.KeyID) (secret.Value, error) {
	return secret.Value{}, errSealRotateOff
}
func (offSeal) WriteFragment(sealrotate.Fragment) error { return errSealRotateOff }
func (offSeal) RemoveRotation() error                   { return errSealRotateOff }
func (offSeal) TryAcquire(string) error                 { return errSealRotateOff }
func (offSeal) Release(string)                          {}
func (offSeal) RotationHolder() string                  { return "" }
func (offSeal) Active() (string, bool)                  { return "", false }
func (offSeal) Read([]byte) (int, error)                { return 0, errSealRotateOff }
