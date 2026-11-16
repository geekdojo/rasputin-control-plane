package identitytest

// The pair helper for the real-systemd identity tests (TC-979-02, TC-979-04,
// geekdojo/geekdojo-brain#979): the pinned PostgreSQL and Keycloak as two
// runtime units under the runner's real systemd, related the way
// keycloak-db.service and keycloak.service are (Requires= and After=), so the
// states the tests read are systemd's own. It needs root, systemd as the init
// system and docker. It skips without them, and fails instead under
// RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required, as CI's root step sets it
// (docs/testing-identity.md).
//
// The units are unit files under /run/systemd/system, not systemd-run
// transient units: systemd garbage-collects a transient unit as soon as it is
// inactive, so `systemctl restart` of a Keycloak unit its failed database had
// stopped, which is what identity.recover runs, would answer "not found". A
// unit file stays loadable, as keycloak.service does on an appliance.
//
// What the units do not carry: #973's hooks. Keycloak's unit has no
// ExecStartPost= start wait and no start-hold ExecStartPre=, so it reads
// active from the JVM's start, not from /health/started, and its start timeout
// is systemd's default, never infinity. Its ExecStopPost= is
// testdata/exit-record-standin.sh, a minimal stand-in for #973's exit-record
// hook that writes the contract's record and `last` from systemd's real
// environment, without the hook's cap. The real hooks, their cap and the start
// wait that exits once $MAINPID is gone are #973's to prove (NOT RUN here).

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

// unitDir is where the pair's unit files go: the runtime unit directory, a
// tmpfs systemd reads on daemon-reload.
const unitDir = "/run/systemd/system"

// cleanupReserve is the part of the test binary's -test.timeout kept back
// from a real-systemd test's waits. A wait that never sees its fact then ends
// with an error naming that fact, and the cleanup still has time to stop the
// units, remove the container and unmount the partition, instead of the
// binary's timeout panic skipping it and leaving them on the runner. It bounds
// the waits only; no state changes on it.
const cleanupReserve = 2 * time.Minute

// systemdPreflight checks for root, systemd as the init system, the systemd
// tools, docker and the installed identity service, and reports the first one
// missing through SkipOrFail.
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
	for _, bin := range []string{"systemctl", "mount", "umount", cfg.DockerBin} {
		if _, err := exec.LookPath(bin); err != nil {
			functest.SkipOrFail(t, systemdSwitchEnv, "the real-systemd identity tests need %s: %v", bin, err)
			return Config{}, false
		}
	}
	if kcsh := filepath.Join(cfg.KeycloakHome, "bin", "kc.sh"); !executable(kcsh) {
		functest.SkipOrFail(t, systemdSwitchEnv, "the identity service (Keycloak) is not installed: no executable %s", kcsh)
		return Config{}, false
	}
	return cfg, true
}

// waitCtx is t's context with a deadline cleanupReserve before the test
// binary's own. A binary run with no -test.timeout has none, so CI's root
// step passes one.
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

// errNamed is a wait's failure naming the fact that never came true.
func errNamed(fact string, err error) error {
	return fmt.Errorf("never saw the fact %q: %w", fact, err)
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
	// Target Wants= both units, as multi-user.target wants the appliance's:
	// it keeps an inactive Keycloak unit loaded, so reset-failed and restart
	// find it.
	Target string
	// PGData is the size-limited tmpfs the database's data directory lives
	// on.
	PGData string
	DBPort int
	// Exits is the Keycloak unit's exit-record directory.
	Exits string
	// KC is the Keycloak unit's files: its TLS, home and config. Its ports
	// are fixed, so its management URL holds across restarts.
	KC *Env

	dbPassword secret.Value
	mounted    bool
	units      []string // unit files written, for the cleanup
}

// newPair makes the pair's names and root, and registers the cleanup, which
// runs even when a start fails half way.
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
		Target: "rasputin-idst-" + tag + ".target",
	}
	p.PGData = filepath.Join(p.root, "pgdata")
	p.Exits = filepath.Join(p.root, "exits")
	t.Cleanup(p.cleanup)
	return p
}

// label is the docker label on every container the database unit runs:
// `docker run --rm` gives each restart a new container, so they are found by
// label rather than by name.
func (p *systemdPair) label() string { return "rasputin-idst=" + p.tag }

// writeUnit writes a runtime unit file and reloads systemd.
func (p *systemdPair) writeUnit(ctx context.Context, name, body string) error {
	path := filepath.Join(unitDir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	p.units = append(p.units, name)
	if out, err := p.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, out)
	}
	return nil
}

// StartDB mounts a sizeMiB tmpfs at PGData and runs the pinned PostgreSQL on
// it as a unit with Restart=always, on a fixed loopback port so every
// restart serves the same address. startLimitBurst, when not zero, is the
// unit's StartLimitBurst=, with StartLimitIntervalSec=infinity, so a crash
// loop ends in failed on systemd's own start limit however fast it runs. It
// returns once the unit is active and pg_isready answers. The mount point is 0755 root, as /var/lib/postgresql's
// parent is: the image's entrypoint makes PGDATA under it and gives it to the
// postgres user, which must be able to reach it.
func (p *systemdPair) StartDB(ctx context.Context, sizeMiB, startLimitBurst int) error {
	if err := os.MkdirAll(p.PGData, 0o755); err != nil {
		return fmt.Errorf("pgdata dir: %w", err)
	}
	if out, err := p.run(ctx, "mount", "-t", "tmpfs", "-o", "size="+strconv.Itoa(sizeMiB)+"m,mode=0755", "tmpfs", p.PGData); err != nil {
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
	limit := ""
	if startLimitBurst > 0 {
		limit = "StartLimitBurst=" + strconv.Itoa(startLimitBurst) + "\nStartLimitIntervalSec=infinity\n"
	}
	unit := "[Unit]\nDescription=identitytest database " + p.tag + "\n" + limit + "\n[Service]\nRestart=always\n" +
		"ExecStart=" + strings.Join([]string{p.cfg.DockerBin, "run", "--rm", "--label", p.label(),
		"-p", "127.0.0.1:" + strconv.Itoa(p.DBPort) + ":5432", "-v", p.PGData + ":/var/lib/postgresql",
		"--env-file", envFile, PostgresImage}, " ") + "\n"
	if err := p.writeUnit(ctx, p.DBUnit, unit); err != nil {
		return err
	}
	if out, err := p.run(ctx, "systemctl", "start", p.DBUnit); err != nil {
		return fmt.Errorf("start the database unit: %w: %s", err, out)
	}
	return p.AwaitDBReady(ctx)
}

// AwaitDBReady returns once the database unit is active and pg_isready
// answers inside its current container. A unit that reads failed will not
// become ready by itself, so the wait ends at once with its state.
func (p *systemdPair) AwaitDBReady(ctx context.Context) error {
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		state, err := unitState(ctx, p.run, p.DBUnit)
		if err != nil {
			return false, "", err
		}
		if strings.HasPrefix(state, "failed/") {
			return false, state, &proctest.Final{Err: fmt.Errorf("the database unit is %s: %s", state, p.journalTail(ctx, p.DBUnit))}
		}
		if state != "active/running" {
			return false, "unit " + state, nil
		}
		id, err := p.DBContainer(ctx)
		if err != nil || id == "" {
			return false, "no container yet", err
		}
		out, err := p.d.exec(ctx, strings.Fields(id)[0], "pg_isready", "-h", "127.0.0.1", "-U", dbUser, "-d", dbName)
		return err == nil, strings.TrimSpace(string(out)), nil
	}, func(last string) {
		p.cfg.Logger.Info("identity database unit not ready yet", "unit", p.DBUnit, "last", last)
	})
	if err != nil {
		return errNamed("the database unit "+p.DBUnit+" is active and pg_isready answers", err)
	}
	p.cfg.Logger.Info("identity database unit started", "unit", p.DBUnit, "port", p.DBPort, "pgdata", p.PGData)
	return nil
}

// journalTail is a unit's last journal lines, for a failure message only: the
// test reports why a unit failed, and decides nothing on it.
func (p *systemdPair) journalTail(ctx context.Context, unit string) string {
	out, _ := p.run(ctx, "journalctl", "--no-pager", "-n", "20", "-u", unit)
	return strings.TrimSpace(string(out))
}

// DBContainer is the ids of the database unit's containers, or "".
func (p *systemdPair) DBContainer(ctx context.Context) (string, error) {
	out, err := p.run(ctx, p.cfg.DockerBin, "ps", "-q", "--filter", "label="+p.label())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// KeycloakOptions are what a test changes in the Keycloak unit.
type KeycloakOptions struct {
	// Heap is JAVA_OPTS_KC_HEAP; empty is the unit's own.
	Heap string
	// StartLimitBurst, when not zero, is the unit's StartLimitBurst=, with
	// StartLimitIntervalSec=infinity, so the restart loop ends on systemd's
	// own start limit.
	StartLimitBurst int
	// StandIn is the ExecStopPost= exit-record stand-in, or empty for none.
	StandIn string
}

// StartKeycloak builds a Keycloak home, TLS and config for the pair's
// database under fixed loopback ports, writes it as a unit with Requires= and
// After= on the database, Restart=always, SuccessExitStatus=143 and the
// unit's JVM environment, and starts it through the pair's target. It
// returns once systemctl start returns, which for a unit with no start wait
// is as soon as the JVM is spawned.
func (p *systemdPair) StartKeycloak(ctx context.Context, opt KeycloakOptions) error {
	h, err := New(p.cfg)
	if err != nil {
		return err
	}
	e := &Env{h: h, log: p.cfg.Logger, docker: p.d, root: filepath.Join(p.root, "kc"), ports: &reportedPorts{}}
	p.KC = e
	if err := atrest.EnsureSecretDir(e.root); err != nil {
		return err
	}
	if err := e.makeTLS(); err != nil {
		return err
	}
	if e.password, err = randomSecret(p.cfg.Rand); err != nil {
		return err
	}
	https, err := proctest.FreePort()
	if err != nil {
		return err
	}
	mgmt, err := proctest.FreePort()
	if err != nil {
		return err
	}
	e.ports.https, e.ports.mgmt = https, mgmt
	home, err := e.makeKeycloakHome()
	if err != nil {
		return err
	}
	conf := filepath.Join(e.root, "keycloak.conf")
	body := renderKeycloakConf(kcPaths{
		CertFile:  filepath.Join(e.root, "server", "leaf.pem"),
		KeyFile:   filepath.Join(e.root, "server", "leaf.key"),
		TrustFile: filepath.Join(e.root, "ca", caCertFile),
		VaultDir:  filepath.Join(e.root, "vault"),
	}, kcPorts{HTTPS: https, Mgmt: mgmt, DB: p.DBPort}, "https://127.0.0.1:"+strconv.Itoa(https), p.dbPassword)
	err = atrest.WriteSecretFile(conf, body)
	clear(body)
	if err != nil {
		return err
	}
	for _, d := range []string{filepath.Join(e.root, "vault"), filepath.Join(home, "data", "import")} {
		if err := atrest.EnsureSecretDir(d); err != nil {
			return err
		}
	}
	rendered, err := renderRealm(UserName, e.password)
	if err != nil {
		return err
	}
	realm, err := withAdminClient(rendered)
	clear(rendered)
	if err != nil {
		return err
	}
	err = atrest.WriteSecretFile(filepath.Join(home, "data", "import", Realm+"-realm.json"), realm)
	clear(realm)
	if err != nil {
		return err
	}

	envs := e.kcEnv()
	if opt.Heap != "" {
		for i, kv := range envs {
			if strings.HasPrefix(kv, "JAVA_OPTS_KC_HEAP=") {
				envs[i] = "JAVA_OPTS_KC_HEAP=" + opt.Heap
			}
		}
	}
	var u strings.Builder
	u.WriteString("[Unit]\nDescription=identitytest identity service " + p.tag + "\n")
	u.WriteString("Requires=" + p.DBUnit + "\nAfter=" + p.DBUnit + "\n")
	if opt.StartLimitBurst > 0 {
		u.WriteString("StartLimitBurst=" + strconv.Itoa(opt.StartLimitBurst) + "\nStartLimitIntervalSec=infinity\n")
	}
	u.WriteString("\n[Service]\nRestart=always\nSuccessExitStatus=143\nWorkingDirectory=" + home + "\n")
	for _, kv := range envs {
		u.WriteString("Environment=\"" + kv + "\"\n")
	}
	u.WriteString("StandardOutput=append:" + filepath.Join(p.root, "kc.out") + "\nStandardError=append:" + filepath.Join(p.root, "kc.out") + "\n")
	u.WriteString("ExecStart=" + filepath.Join(home, "bin", "kc.sh") + " --config-file=" + conf + " start --optimized --import-realm\n")
	if opt.StandIn != "" {
		u.WriteString("ExecStopPost=" + opt.StandIn + " " + p.Exits + "\n")
	}
	if err := p.writeUnit(ctx, p.KCUnit, u.String()); err != nil {
		return err
	}
	target := "[Unit]\nDescription=identitytest identity pair " + p.tag + "\nWants=" + p.KCUnit + " " + p.DBUnit + "\n"
	if err := p.writeUnit(ctx, p.Target, target); err != nil {
		return err
	}
	if out, err := p.run(ctx, "systemctl", "start", p.Target); err != nil {
		return fmt.Errorf("start the identity pair's target: %w: %s", err, out)
	}
	return nil
}

// KCOutput is the tail of everything the Keycloak unit's runs printed, for a
// failure message.
func (p *systemdPair) KCOutput() string {
	b, _ := os.ReadFile(filepath.Join(p.root, "kc.out"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return strings.Join(lines[max(0, len(lines)-20):], "\n")
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

// cleanup stops both units, removes their files, reloads and resets them,
// removes any container still carrying the label, unmounts the tmpfs, removes
// Keycloak's files, and then shows each one gone: both units
// LoadState=not-found, no container listed, the mount point not mounted, and
// no process naming Keycloak's root.
func (p *systemdPair) cleanup() {
	t := p.t
	ctx := context.Background() // t.Context() has ended by now
	var errs []error
	for _, u := range []string{p.Target, p.KCUnit, p.DBUnit} {
		_, _ = p.run(ctx, "systemctl", "stop", u) // a unit never started has nothing to stop
	}
	for _, u := range p.units {
		if err := os.Remove(filepath.Join(unitDir, u)); err != nil {
			errs = append(errs, err)
		}
	}
	if len(p.units) > 0 {
		if out, err := p.run(ctx, "systemctl", "daemon-reload"); err != nil {
			errs = append(errs, fmt.Errorf("systemctl daemon-reload: %w: %s", err, out))
		}
	}
	for _, u := range []string{p.KCUnit, p.DBUnit} {
		_, _ = p.run(ctx, "systemctl", "reset-failed", u) // a unit that never failed has nothing to reset
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
	if p.KC != nil {
		// No process, container or front of its own: Close removes its root
		// and proves no live process names it.
		errs = append(errs, p.KC.Close(ctx))
	}
	// The proof.
	for _, u := range []string{p.Target, p.KCUnit, p.DBUnit} {
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
