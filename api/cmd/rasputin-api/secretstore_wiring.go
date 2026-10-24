package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The secret store's wiring (ADR-0010; geekdojo/geekdojo-brain#758).
//
// RASPUTIN_SECRETSTORE_BACKEND selects the store, and nothing infers one:
//
//   - unset or empty: the store is off (secretstore.Disabled), at INFO;
//   - exactly "mock": the in-memory secretstore.Mock, at WARN;
//   - exactly "openbao": the real client, the two store-CA leaves it needs
//     and the store provisioner's leaf (#805), registered with a sweeper of
//     their own;
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
	// storeProvisionerLeafName is the store provisioner's leaf (#805), which
	// rasputin-os's rasputin-store-provision oneshot presents at the store.
	storeProvisionerLeafName = "openbao-provisioner"
	// storeClientCN is the client leaf's CommonName. The store's cert role
	// (#804) pins allowed_common_names to it.
	storeClientCN = "rasputin-api"
	// storeProvisionerCN is the provisioner leaf's CommonName. The store's
	// rasputin-provisioner cert role (#805) pins allowed_common_names to it.
	storeProvisionerCN = "rasputin-provisioner"
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
	Delete(ctx context.Context, token secret.Value, p secretstore.KVPath) error
}

// storeWiring is what wireSecretStore built.
type storeWiring struct {
	mode  string
	store secretStore
	// login is the store's cert login (#759): the client under openbao, the
	// same Mock under mock, and Disabled when the store is off or refused.
	login storesession.Login
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
// setting is a configfault and a Disabled store. afterStoreRestart runs once
// each time the server leaf's reload restarts the store (#833); it is
// required under openbao.
func wireSecretStore(ctx context.Context, logger *slog.Logger, backend, addr string, storeCA *tlsca.CA, dataDir string, run runFunc, afterStoreRestart func(context.Context)) (storeWiring, error) {
	off := storeWiring{mode: storeModeOff, store: secretstore.Disabled{}, login: secretstore.Disabled{}}
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
		mock := secretstore.NewMock(time.Now)
		return storeWiring{mode: storeModeMock, store: mock, login: mock}, nil
	case storeModeOpenBao:
		if afterStoreRestart == nil {
			return off, errors.New("secret store: the after-restart hook is nil under openbao")
		}
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
	// The provisioner's leaf first: a sweep mints in registration order, and
	// the server leaf's reload restarts the store, whose start pulls in the
	// provisioner oneshot that loads this leaf (#805). It has no reload: the
	// oneshot reads it through LoadCredential= at each run.
	if err := sweeper.Register(tlsca.LeafConsumer{
		Name: storeProvisionerLeafName,
		Dir:  filepath.Join(dataDir, "tls", storeProvisionerLeafName),
		Spec: func() (tlsca.LeafSpec, error) { return storeProvisionerLeafSpec(), nil },
	}); err != nil {
		return off, fmt.Errorf("secret store: %w", err)
	}
	if err := sweeper.Register(tlsca.LeafConsumer{
		Name:   storeServerLeafName,
		Dir:    filepath.Join(dataDir, "tls", storeServerLeafName),
		Spec:   func() (tlsca.LeafSpec, error) { return storeServerLeafSpec(), nil },
		Reload: restartStoreUnit(run, afterStoreRestart),
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
	return storeWiring{mode: storeModeOpenBao, store: client, login: client, client: client, sweeper: sweeper}, nil
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

// storeProvisionerLeafSpec is the store provisioner's leaf (#805): clientAuth,
// with the CommonName the store's rasputin-provisioner cert role allows. The
// api mints and renews it; rasputin-store-provision.service reads it through
// LoadCredential=, so only the store's unit user and root read the copy.
func storeProvisionerLeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: storeProvisionerCN}
}

// restartStoreUnit is the server leaf's reload: the store reads its leaf only
// at start, through LoadCredential. On first boot the unit was skipped because
// the leaf did not exist, and after a crash loop it sits in failed, so the
// recovery #755 hands over is reset-failed and then restart; try-restart would
// leave the skipped, inactive unit alone. It runs only on the fact of a fresh
// mint, or of a seal-key rotation's restart.
//
// after runs exactly once when the pair returns, whether or not it
// succeeded: every store start re-runs the store's oneshots, whose outcome
// records the hook reads (#833). The pair's error is still returned.
func restartStoreUnit(run runFunc, after func(context.Context)) func(context.Context, tlsca.LeafPaths) error {
	return func(ctx context.Context, _ tlsca.LeafPaths) error {
		defer after(ctx)
		for _, verb := range []string{"reset-failed", "restart"} {
			if _, err := run(ctx, "systemctl", verb, storeUnit); err != nil {
				return err
			}
		}
		return nil
	}
}

// startStoreSweep mints and renews the store leaves once, now, in a goroutine
// of its own, so the leaves exist soon after start whether or not HTTPS is
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

// storeDataDirName is the secret store's data directory under the data dir,
// where rasputin-os's openbao.service keeps its PebbleDB storage.
const storeDataDirName = "openbao"

// storeDataPresent reports whether the store's data directory holds anything.
// A directory that cannot be read is present: the CA guard and the
// empty-store marker both fail closed on it (#765).
func storeDataPresent(dir string) bool {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return err != nil || len(ents) > 0
}

// backupSources adds the store's data and seal directories to the backup's
// identity sources when the store is captured (#765).
func backupSources(src storage.IdentitySources, captured storage.SecretStore, storeDataDir string) storage.IdentitySources {
	if captured != nil {
		src.StoreDataDir = storeDataDir
		src.SealDir = sealrotate.ProductionSealDir
	}
	return src
}

// sealTree is the one seal-files call the backup's adapter makes.
type sealTree interface {
	State() (sealrotate.Tree, error)
}

// storeBackupControl is storage.SecretStore over the composition root's
// collaborators (#765): the readiness monitor's state and quiesce, the
// store's sys/health, the seal files, and the store unit through systemctl.
// Its reason is the job it quiesces the store for: the backup's capture, or
// an OS update's pre-update copy (geekdojo/geekdojo-brain#800). Main builds
// one of each.
type storeBackupControl struct {
	reason  storestate.QuiesceReason
	monitor *storestate.Monitor
	health  secretstore.HealthReader
	seal    sealTree
	run     runFunc
	start   func(context.Context, tlsca.LeafPaths) error
	wait    time.Duration
	log     *slog.Logger
}

// selfStoreCheckWiring builds the secret-store gate a control plane's update
// of itself passes before it commits (geekdojo/geekdojo-brain#767), which
// also retires the store's pre-update copy once that update commits (#873).
// It keys on retirer, the pre-update copier, so the check runs on exactly
// the hosts whose update copy_store copies: nil with no store requested or
// the mock, and a check otherwise. A store whose configuration was refused
// still gets one; its Disabled store answers ErrDisabled, so such an update
// goes to mark-bad (ERR-CLOSED).
func selfStoreCheckWiring(retirer updater.CopyRetirer, store updater.StoreHealth, log *slog.Logger) (*updater.SelfStoreCheck, error) {
	if retirer == nil {
		return nil, nil
	}
	return updater.NewSelfStoreCheck(store, retirer, log)
}

// storeBackupWiring builds the store's cold-copy control for reason when a
// backend other than the mock is requested, a refused one included: its
// monitor reads unreachable, so every capture fails closed until it is
// fixed. With nothing or the mock requested it returns nil: for a backup, no
// store step and a version-2 archive; for an OS update, no copy.
func storeBackupWiring(requested string, reason storestate.QuiesceReason, monitor *storestate.Monitor, health secretstore.HealthReader, seal sealTree,
	run runFunc, afterStoreRestart func(context.Context), log *slog.Logger) (storage.SecretStore, error) {
	if requested == "" || requested == storeModeMock {
		return nil, nil
	}
	switch {
	case monitor == nil:
		return nil, errors.New("store backup: the readiness monitor is nil")
	case health == nil || seal == nil || run == nil || afterStoreRestart == nil || log == nil:
		return nil, errors.New("store backup: a collaborator is nil")
	}
	return &storeBackupControl{reason: reason, monitor: monitor, health: health, seal: seal, run: run,
		start: restartStoreUnit(run, afterStoreRestart), wait: sealrotate.UnsealWait, log: log}, nil
}

// Readiness is "" when the monitor reads the store ready, else its clause.
func (c *storeBackupControl) Readiness(ctx context.Context) (string, error) {
	st, err := c.monitor.State(ctx)
	if err != nil {
		return "", err
	}
	if st == storestate.Ready {
		return "", nil
	}
	return storestate.Clause(st), nil
}

// SealKeyID is the Clean fragment's key id; any other shape refuses.
func (c *storeBackupControl) SealKeyID() (string, error) {
	tree, err := c.seal.State()
	if err != nil {
		return "", err
	}
	if tree.Fragment.Shape != sealrotate.Clean {
		return "", fmt.Errorf("the seal fragment is %s, not clean", tree.Fragment.Shape)
	}
	return tree.Fragment.Current.String(), nil
}

// Version is the running store's release from sys/health.
func (c *storeBackupControl) Version(ctx context.Context) (string, error) {
	h, err := c.health.Health(ctx)
	if kind := secretstore.InactiveReason(h, err); kind != "" {
		return "", fmt.Errorf("the secret store is %s", kind)
	}
	return h.Version, nil
}

// Stop stops the store unit for its cold copy.
func (c *storeBackupControl) Stop(ctx context.Context) error {
	c.log.InfoContext(ctx, "secret store stopping for its cold copy", "component", "secretstore",
		"event", "secretstore.backup_stop", "job_id", jobs.JobIDFromContext(ctx), "unit", storeUnit, "reason", c.reason.String())
	if out, err := c.run(ctx, "systemctl", "stop", storeUnit); err != nil {
		return fmt.Errorf("systemctl stop %s: %w: %s", storeUnit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Start starts it again through the server leaf's own restart, which runs
// the after-restart outcome read (F-765-10).
func (c *storeBackupControl) Start(ctx context.Context) error {
	c.log.InfoContext(ctx, "secret store starting after its cold copy", "component", "secretstore",
		"event", "secretstore.backup_start", "job_id", jobs.JobIDFromContext(ctx), "unit", storeUnit, "reason", c.reason.String())
	return c.start(ctx, tlsca.LeafPaths{})
}

// WaitReady waits for sys/health to answer 200 unsealed (K24).
func (c *storeBackupControl) WaitReady(ctx context.Context) error {
	return secretstore.WaitReady(ctx, c.health, c.wait)
}

// Quiesce holds the store quiesced for the control's reason.
func (c *storeBackupControl) Quiesce(jobID string) func() {
	return c.monitor.Quiesce(jobID, c.reason)
}

// storeRollbackCreatedBy is who the reference check's job names as its
// submitter.
const storeRollbackCreatedBy = "store-ready"

// rollbackRunner is the runner as storeRollbackWiring uses it.
type rollbackRunner interface {
	Register(w jobs.Workflow)
	Submit(ctx context.Context, kind string, spec any, createdBy string) (*jobs.Job, error)
}

// readyReader is the readiness monitor as the reference check's trigger
// uses it.
type readyReader interface {
	OnFirstReady(ctx context.Context, fn func(context.Context))
	State(ctx context.Context) (storestate.State, error)
}

// storeRollbackDeps is what the store's rollback wiring takes from main
// (geekdojo/geekdojo-brain#800).
type storeRollbackDeps struct {
	// mode is the wired store's mode; the reference check runs only under
	// openbao.
	mode string
	// copyStore is the store's cold-copy control quiescing for an OS
	// update, nil when no backend or the mock was requested.
	copyStore storage.SecretStore
	// lock is the capture gate under openbao, nil otherwise.
	lock         storage.UpdateLock
	storeDataDir string
	copyPath     string
	refs         appsecret.RefLister
	secrets      appsecret.SecretChecker
	monitor      readyReader
	runner       rollbackRunner
	log          *slog.Logger
}

// storeRollback is what storeRollbackWiring built.
type storeRollback struct {
	// copier is updater.Config.StoreCopy: nil when there is no store.
	copier updater.StoreCopier
	// retirer is the same copier, as the self-update store check retires
	// its copy at the commit (#873): nil with copier.
	retirer updater.CopyRetirer
	// arm, run once after runner.Recover, submits the reference check on
	// the first reading that finds the store ready; it does nothing when the
	// check is not wired.
	arm func(ctx context.Context)
}

// noStoreRotationLock is the copy's lock when a backend other than the mock
// was requested but refused: no seal-key rotation can run then, so there is
// nothing to wait for, and the store reads unreachable, so the copy refuses
// at its readiness check (fail closed).
type noStoreRotationLock struct{}

func (noStoreRotationLock) AcquireForUpdate(context.Context, string) error { return nil }
func (noStoreRotationLock) Release(string)                                 {}

// storeRollbackWiring builds the OS update's copy of the store and the
// reference check that runs after a store's data is put back
// (geekdojo/geekdojo-brain#800). The copier exists whenever copyStore does;
// the check is registered, and armed, only under openbao.
func storeRollbackWiring(d storeRollbackDeps) (storeRollback, error) {
	off := storeRollback{arm: func(context.Context) {}}
	if d.log == nil {
		return off, errors.New("store rollback: the logger is nil")
	}
	out := off
	if d.copyStore != nil {
		lock := d.lock
		if lock == nil {
			lock = noStoreRotationLock{}
		}
		c, err := storage.NewPreUpdateCopier(storage.PreUpdateCopierDeps{
			Store: d.copyStore, Lock: lock, DataDir: d.storeDataDir, CopyPath: d.copyPath, Log: d.log,
		})
		if err != nil {
			return off, fmt.Errorf("store rollback: %w", err)
		}
		out.copier, out.retirer = c, c
	}
	if d.mode != storeModeOpenBao {
		return out, nil
	}
	if d.monitor == nil || d.runner == nil {
		return off, errors.New("store rollback: the readiness monitor or the runner is nil under openbao")
	}
	wf, err := appsecret.ReferenceCheckWorkflow(appsecret.ReferenceCheckDeps{Refs: d.refs, Secrets: d.secrets, Log: d.log})
	if err != nil {
		return off, fmt.Errorf("store rollback: %w", err)
	}
	d.runner.Register(wf)
	out.arm = func(ctx context.Context) {
		d.monitor.OnFirstReady(ctx, func(ctx context.Context) {
			if _, err := d.runner.Submit(ctx, appsecret.ReferenceCheckKind, nil, storeRollbackCreatedBy); err != nil {
				d.log.ErrorContext(ctx, "secret store reference check not submitted",
					"component", "appsecret", "event", "appsecret.reference_check_submit_failed", "err", err.Error())
			}
		})
		// One reading now, under the client's own per-call bound: a store
		// already ready submits the check at once; otherwise the next ready
		// reading by any reader does. Its answer is recorded by the monitor.
		if _, err := d.monitor.State(ctx); err != nil {
			d.log.WarnContext(ctx, "secret store readiness not read at start; the next reading arms the reference check",
				"component", "appsecret", "err", err.Error())
		}
	}
	return out, nil
}
