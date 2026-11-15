package identitytest

// The pair helper for the real-systemd identity tests (TC-979-02, TC-979-04,
// geekdojo/geekdojo-brain#979): the pinned PostgreSQL and Keycloak as two
// transient units under the runner's real systemd, related the way
// keycloak-db.service and keycloak.service are (Requires= and After=), so
// systemd's own states are what the tests read. It needs root, systemd as the
// init system and docker. It skips without them, and fails instead under
// RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required, as CI's root step sets it
// (docs/testing-identity.md).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// systemdSwitchEnv set to functest.Required turns the real-systemd tests'
// skips into failures. Only CI's root step sets it.
const systemdSwitchEnv = "RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL"

// cleanupReserve is the part of the test binary's -test.timeout kept back
// from a real-systemd test's waits. A wait that never sees its fact then ends
// with an error naming that fact, and the cleanup still has time to stop the
// units, remove the container and unmount the partition, instead of the
// binary's timeout panic skipping it and leaving them on the runner. It bounds
// the waits only; no state changes on it.
const cleanupReserve = 2 * time.Minute

// systemdPreflight checks for root, systemd as the init system, the systemd
// tools and docker, and reports the first one missing through SkipOrFail.
func systemdPreflight(t *testing.T) (Config, bool) {
	t.Helper()
	p := NewPackage(ConfigFromEnv)
	cfg, err := p.loadConfig()
	if err != nil {
		functest.SkipOrFail(t, systemdSwitchEnv, "%v", err)
		return Config{}, false
	}
	if uid := os.Geteuid(); uid != 0 {
		functest.SkipOrFail(t, systemdSwitchEnv, "the real-systemd identity tests need root, and this is uid %d", uid)
		return Config{}, false
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		functest.SkipOrFail(t, systemdSwitchEnv, "systemd is not the init system: %v", err)
		return Config{}, false
	}
	for _, bin := range []string{"systemd-run", "systemctl", "mount", "umount"} {
		if _, err := exec.LookPath(bin); err != nil {
			functest.SkipOrFail(t, systemdSwitchEnv, "the real-systemd identity tests need %s: %v", bin, err)
			return Config{}, false
		}
	}
	if _, err := exec.LookPath(cfg.DockerBin); err != nil {
		functest.SkipOrFail(t, systemdSwitchEnv, "the real-systemd identity tests need docker: %q: %v", cfg.DockerBin, err)
		return Config{}, false
	}
	return cfg, true
}

// waitCtx is t's context with a deadline cleanupReserve before the test
// binary's own, when it has one.
func waitCtx(t *testing.T) context.Context {
	t.Helper()
	ctx := t.Context()
	if dl, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl.Add(-cleanupReserve))
		t.Cleanup(cancel)
	}
	return ctx
}

// unitProps is `systemctl show --property=<props> <unit>` as a map.
func unitProps(ctx context.Context, run CmdRunner, unit string, props ...string) (map[string]string, error) {
	out, err := run(ctx, "systemctl", "show", "--property="+strings.Join(props, ","), unit)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m, nil
}

// unitState is a unit's ActiveState/SubState, as "active/running".
func unitState(ctx context.Context, run CmdRunner, unit string) (string, error) {
	m, err := unitProps(ctx, run, unit, "ActiveState", "SubState")
	if err != nil {
		return "", err
	}
	return m["ActiveState"] + "/" + m["SubState"], nil
}

// systemdPair is the database unit and, once started, the Keycloak unit.
type systemdPair struct {
	t   *testing.T
	cfg Config
	d   docker
	run CmdRunner

	tag    string // the random suffix every name carries
	root   string // the pair's temporary root
	DBUnit string
	KCUnit string
	// PGData is the size-limited tmpfs the database's data directory lives
	// on.
	PGData string
	DBPort int

	dbPassword secret.Value
	mounted    bool
}

// newPair makes the pair's names and root, and registers the cleanup, which
// runs even when a start fails half way: it stops and resets both units,
// removes the container and unmounts the tmpfs, then shows each one gone.
func newPair(t *testing.T, cfg Config) *systemdPair {
	t.Helper()
	tag, err := randomHex(cfg.Rand, 6)
	if err != nil {
		t.Fatalf("pair names: %v", err)
	}
	p := &systemdPair{
		t: t, cfg: cfg, d: docker{bin: cfg.DockerBin, run: cfg.Run}, run: cfg.Run, tag: tag,
		root:   t.TempDir(),
		DBUnit: "rasputin-idst-db-" + tag + ".service",
		KCUnit: "rasputin-idst-kc-" + tag + ".service",
	}
	p.PGData = filepath.Join(p.root, "pgdata")
	t.Cleanup(p.cleanup)
	return p
}

// label is the docker label on every container the database unit runs:
// `docker run --rm` gives each restart a new container, so they are found by
// label rather than by name.
func (p *systemdPair) label() string { return "rasputin-idst=" + p.tag }

// StartDB mounts a sizeMiB tmpfs at PGData and runs the pinned PostgreSQL on
// it as a transient unit with Restart=always, on a fixed loopback port so
// every restart serves the same address. It returns once the unit is active
// and pg_isready answers.
func (p *systemdPair) StartDB(ctx context.Context, sizeMiB int) error {
	if err := os.MkdirAll(p.PGData, 0o700); err != nil {
		return fmt.Errorf("pgdata dir: %w", err)
	}
	if out, err := p.run(ctx, "mount", "-t", "tmpfs", "-o", "size="+strconv.Itoa(sizeMiB)+"m,mode=0700", "tmpfs", p.PGData); err != nil {
		return fmt.Errorf("mount the tmpfs: %w: %s", err, out)
	}
	p.mounted = true
	pw, err := randomSecret(p.cfg.Rand)
	if err != nil {
		return fmt.Errorf("database password: %w", err)
	}
	p.dbPassword = pw
	envFile := filepath.Join(p.root, "pg.env")
	env := []byte("POSTGRES_USER=" + dbUser + "\nPOSTGRES_DB=" + dbName + "\nPOSTGRES_PASSWORD=")
	env = append(env, pw.Reveal()...)
	env = append(env, '\n')
	err = atrest.WriteSecretFile(envFile, env)
	clear(env)
	if err != nil {
		return fmt.Errorf("database env file: %w", err)
	}
	if p.DBPort, err = proctest.FreePort(); err != nil {
		return err
	}
	if out, err := p.run(ctx, "systemd-run", "--unit="+p.DBUnit,
		"--description=identitytest database "+p.tag, "--property=Restart=always", "--",
		p.cfg.DockerBin, "run", "--rm", "--label", p.label(),
		"-p", "127.0.0.1:"+strconv.Itoa(p.DBPort)+":5432",
		"-v", p.PGData+":/var/lib/postgresql", "--env-file", envFile, PostgresImage); err != nil {
		return fmt.Errorf("start the database unit: %w: %s", err, out)
	}
	return p.awaitDBReady(ctx)
}

// awaitDBReady returns once the database unit is active and pg_isready
// answers inside its current container.
func (p *systemdPair) awaitDBReady(ctx context.Context) error {
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		state, err := unitState(ctx, p.run, p.DBUnit)
		if err != nil {
			return false, "", err
		}
		if state != "active/running" {
			return false, "unit " + state, nil
		}
		id, err := p.DBContainer(ctx)
		if err != nil || id == "" {
			return false, "no container yet", err
		}
		out, err := p.d.exec(ctx, id, "pg_isready", "-h", "127.0.0.1", "-U", dbUser, "-d", dbName)
		return err == nil, strings.TrimSpace(string(out)), nil
	}, func(last string) {
		p.cfg.Logger.Debug("identity database unit not ready yet", "unit", p.DBUnit, "last", last)
	})
	if err != nil {
		return fmt.Errorf("the database unit %s never became active with pg_isready answering: %w", p.DBUnit, err)
	}
	p.cfg.Logger.Info("identity database unit started", "unit", p.DBUnit, "port", p.DBPort, "pgdata", p.PGData)
	return nil
}

// DBContainer is the id of the database unit's current container, or "".
func (p *systemdPair) DBContainer(ctx context.Context) (string, error) {
	out, err := p.run(ctx, p.cfg.DockerBin, "ps", "-q", "--filter", "label="+p.label())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Fill writes zeros into a file on the tmpfs until the kernel answers
// ENOSPC, so the partition holds no free block.
func (p *systemdPair) Fill() error {
	f, err := os.Create(p.fillPath())
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		if _, err := f.Write(buf); err != nil {
			cerr := f.Close()
			if !errors.Is(err, syscall.ENOSPC) {
				return errors.Join(fmt.Errorf("fill the tmpfs: %w", err), cerr)
			}
			return cerr
		}
	}
}

// Free removes the fill file.
func (p *systemdPair) Free() error { return os.Remove(p.fillPath()) }

func (p *systemdPair) fillPath() string { return filepath.Join(p.PGData, "fill") }

// cleanup stops and resets both units, removes any container still carrying
// the label, unmounts the tmpfs, and then shows each one gone: both units
// LoadState=not-found, no container listed, the mount point not mounted.
func (p *systemdPair) cleanup() {
	t := p.t
	ctx := context.Background() // t.Context() has ended by now
	var errs []error
	for _, u := range []string{p.KCUnit, p.DBUnit} {
		_, _ = p.run(ctx, "systemctl", "stop", u)         // a unit never started has nothing to stop
		_, _ = p.run(ctx, "systemctl", "reset-failed", u) // nor anything to reset
	}
	if ids, err := p.DBContainer(ctx); err != nil {
		errs = append(errs, fmt.Errorf("list the database containers: %w", err))
	} else {
		for _, id := range strings.Fields(ids) {
			if err := p.d.rm(ctx, id); err != nil {
				errs = append(errs, fmt.Errorf("remove container %s: %w", id, err))
			}
		}
	}
	if p.mounted {
		if out, err := p.run(ctx, "umount", p.PGData); err != nil {
			errs = append(errs, fmt.Errorf("unmount %s: %w: %s", p.PGData, err, out))
		}
	}
	p.dbPassword.Destroy()
	// The proof.
	for _, u := range []string{p.KCUnit, p.DBUnit} {
		m, err := unitProps(ctx, p.run, u, "LoadState")
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("cannot show unit %s is gone: %w", u, err))
		case m["LoadState"] != "not-found":
			errs = append(errs, fmt.Errorf("cleanup left unit %s behind: LoadState=%s", u, m["LoadState"]))
		}
	}
	if ids, err := p.DBContainer(ctx); err != nil {
		errs = append(errs, fmt.Errorf("cannot show no database container is left: %w", err))
	} else if ids != "" {
		errs = append(errs, fmt.Errorf("cleanup left containers behind: %s", ids))
	}
	if mounts, err := os.ReadFile("/proc/self/mounts"); err != nil {
		errs = append(errs, fmt.Errorf("cannot show the tmpfs is unmounted: %w", err))
	} else if strings.Contains(string(mounts), " "+p.PGData+" ") {
		errs = append(errs, fmt.Errorf("cleanup left %s mounted", p.PGData))
	}
	if err := errors.Join(errs...); err != nil {
		t.Errorf("pair cleanup: %v", err)
		return
	}
	t.Logf("pair cleanup: units %s and %s not-found, no container, %s unmounted", p.DBUnit, p.KCUnit, p.PGData)
}

// errNamed is a wait's failure naming the fact that never came true.
func errNamed(fact string, err error) error {
	return fmt.Errorf("never saw the fact %q: %w", fact, err)
}
