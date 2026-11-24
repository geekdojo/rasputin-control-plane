package identitytest

// The console stack test (geekdojo/geekdojo-brain#989, TC-989-40; F-989-01):
// the real rasputin-api, built from this tree, in keycloak mode with the
// doors on and serving the UI export, against the pinned Keycloak and
// PostgreSQL run as keycloak.service and keycloak-db.service under the
// runner's real systemd, with the api's own identity CA, leaves and realm
// baseline. A synthetic fixture account, made through the Admin API with the
// api's rasputin-admin leaf, signs in through the launcher's route:
//
//   - in CI, in the pinned Chrome, from https://ci.local/login, and the
//     console's / is screenshotted;
//   - in hold mode (RASPUTIN_CONSOLE_RIG=hold, scripts/identity-on-mac.sh),
//     with the Go headless client, and the run then holds the stack up until
//     a stop file appears or a component dies, for the recipe's screenshots.
//
// Both assert /api/auth/me 200 with the fixture's subject and role, and
// write session.cookie (0600), me.json, api-spki and ready to the output
// directory.
//
// It needs root, systemd as init, docker, the installed identity service,
// RASPUTIN_IDENTITY_THEME, RASPUTIN_UI_DIR and RASPUTIN_API_BIN. Without them
// it skips, and under RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required it fails.
// It refuses to run where /usr/share/rasputin, /var/lib/rasputin or a
// keycloak.service unit exists, so a real appliance is never touched.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The console stack test's settings.
const (
	// ConsoleRigEnv set to "hold" signs in with the Go client and holds the
	// stack up until the stop file appears (the Mac recipe).
	ConsoleRigEnv = "RASPUTIN_CONSOLE_RIG"
	// ConsoleOutEnv is the output directory; a temporary one when unset.
	ConsoleOutEnv = "RASPUTIN_CONSOLE_OUT"
	// ConsolePortEnv is the api's https port; 443 when unset, where the
	// identity service's back-channel logout reaches it.
	ConsolePortEnv = "RASPUTIN_CONSOLE_PORT"
	// ConsoleAPIEnvEnv is extra settings for the api, one K=V per line.
	ConsoleAPIEnvEnv = "RASPUTIN_CONSOLE_API_ENV"
	// ConsoleKCPlatformEnv, when set (linux/amd64), runs keycloak.service's
	// Keycloak in a container of that platform beside this one: on Apple
	// silicon the x64 JRE has no loader in the arm64 container.
	ConsoleKCPlatformEnv = "RASPUTIN_CONSOLE_KC_PLATFORM"
	// UIDirEnv and APIBinEnv are the UI export and the api binary.
	UIDirEnv  = "RASPUTIN_UI_DIR"
	APIBinEnv = "RASPUTIN_API_BIN"
)

// The appliance paths the api reads, and the units it reads by name.
var applianceDirs = []string{"/usr/share/rasputin", "/var/lib/rasputin"}

var applianceUnits = []string{
	"/etc/systemd/system/keycloak.service", "/run/systemd/system/keycloak.service",
	"/usr/lib/systemd/system/keycloak.service", "/lib/systemd/system/keycloak.service",
}

const (
	consoleFixture = "console-stack-fixture"
	consoleCID     = "ci"
)

// consoleStack is the running stack.
type consoleStack struct {
	t       *testing.T
	cfg     Config
	out     string
	work    string
	dataDir string
	port    string
	kcHTTPS int
	kcMgmt  int
	api     *exec.Cmd
	apiDone chan struct{}
	pair    *systemdPair
	// fixturePassword is the synthetic fixture's password.
	fixturePassword secret.Value
}

func TestIdentitySystemd_ConsoleSignIn(t *testing.T) {
	cfg, ok := systemdPreflight(t)
	if !ok {
		return
	}
	theme, uiDir, apiBin := os.Getenv(ThemeEnv), os.Getenv(UIDirEnv), os.Getenv(APIBinEnv)
	switch {
	case theme == "" || checkThemeDir(theme) != nil:
		functest.SkipOrFail(t, systemdSwitchEnv, "the console stack test needs the built sign-in theme in %s (node ui/identity-theme/build.mjs)", ThemeEnv)
		return
	case uiDir == "":
		functest.SkipOrFail(t, systemdSwitchEnv, "the console stack test needs the UI export in %s (npm run build in ui/)", UIDirEnv)
		return
	case apiBin == "" || !executable(apiBin):
		functest.SkipOrFail(t, systemdSwitchEnv, "the console stack test needs a rasputin-api binary in %s (go build ./api/cmd/rasputin-api)", APIBinEnv)
		return
	}
	if _, err := os.Stat(filepath.Join(uiDir, "index.html")); err != nil {
		functest.SkipOrFail(t, systemdSwitchEnv, "%s holds no UI export: %v", UIDirEnv, err)
		return
	}
	for _, p := range append(append([]string(nil), applianceDirs...), applianceUnits...) {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("refusing to run: %s exists, so this may be an appliance", p)
		}
	}
	hold := os.Getenv(ConsoleRigEnv) == "hold"
	cfg.ThemeDir = theme
	s := &consoleStack{t: t, cfg: cfg, port: cmpOr(os.Getenv(ConsolePortEnv), "443"), out: cmpOr(os.Getenv(ConsoleOutEnv), t.TempDir())}
	s.work = filepath.Join(s.out, "work")
	if err := atrest.EnsureSecretDir(s.work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(s.work); err != nil {
			t.Errorf("remove %s: %v", s.work, err)
		}
	})
	s.dataDir = filepath.Join(s.work, "api-data")
	ctx := waitCtx(t)

	s.layOut(uiDir, theme)
	var err error
	if s.kcHTTPS, err = proctest.FreePort(); err != nil {
		t.Fatal(err)
	}
	if s.kcMgmt, err = proctest.FreePort(); err != nil {
		t.Fatal(err)
	}
	s.startAPI(apiBin)
	s.awaitFiles(ctx, "the api minted the identity CA and its leaves",
		filepath.Join(s.dataDir, "trust", "identity-ca.pem"), filepath.Join(s.dataDir, "trust", "mesh-ca.pem"),
		filepath.Join(s.dataDir, "tls", "identity-server", "leaf.pem"), filepath.Join(s.dataDir, "tls", "identity-api-client", "leaf.pem"),
		filepath.Join(s.dataDir, "tls", "api", "leaf.pem"), filepath.Join(s.dataDir, "tls", "signin-home", "leaf.pem"))

	s.pair = newConsolePair(t, cfg, s.work, os.Getenv(ConsoleKCPlatformEnv) != "")
	if err := s.pair.StartDB(ctx, 1024, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.startKeycloak(ctx); err != nil {
		t.Fatalf("%v\n%s", err, s.pair.KCOutput())
	}

	admin := s.adminSession(t)
	s.awaitReady(ctx, admin)
	sub := s.fixture(t, admin)
	pw := s.fixturePassword
	defer pw.Destroy()

	var cookie string
	if hold {
		cookie = s.signInGo(ctx, pw)
	} else {
		cookie = s.signInBrowser(ctx, pw)
	}
	s.checkMe(cookie, sub)
	s.writeOutputs(cookie)
	if hold {
		s.hold(ctx)
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// layOut writes the appliance paths the api reads, and removes them, with
// proof, at cleanup.
func (s *consoleStack) layOut(uiDir, theme string) {
	t := s.t
	t.Cleanup(func() {
		var errs []error
		for _, p := range append(append([]string(nil), applianceDirs...), "/run/rasputin-identity-exits", "/run/rasputin-identity-start-hold") {
			if err := os.RemoveAll(p); err != nil {
				errs = append(errs, err)
			}
			if _, err := os.Lstat(p); err == nil {
				errs = append(errs, fmt.Errorf("cleanup left %s behind", p))
			}
		}
		if err := errors.Join(errs...); err != nil {
			t.Errorf("appliance paths: %v", err)
		}
	})
	share := "/usr/share/rasputin/identity"
	for _, d := range []string{share, "/var/lib/rasputin/identity", "/run/rasputin-identity-exits", "/run/rasputin-identity-start-hold"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"realm-baseline.json", "keycloak-build.conf"} {
		if err := copyFile(filepath.Join("..", "..", "..", "identity", f), filepath.Join(share, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(theme, filepath.Join(share, "theme")); err != nil {
		t.Fatal(err)
	}
	_ = uiDir // the api is pointed at it with RASPUTIN_UI_DIR
}

// startAPI starts the api binary under test, logging to <out>/api.log, and
// stops it at cleanup.
func (s *consoleStack) startAPI(bin string) {
	t := s.t
	logf, err := os.OpenFile(filepath.Join(s.out, "api.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://127.0.0.1:1"
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + s.work,
		"RASPUTIN_DATA_DIR=" + s.dataDir,
		"RASPUTIN_CLUSTER_ID=" + consoleCID,
		"RASPUTIN_HTTP_ADDR=127.0.0.1:0",
		"RASPUTIN_HTTPS_ADDR=127.0.0.1:" + s.port,
		"RASPUTIN_NATS_HOST=127.0.0.1", "RASPUTIN_NATS_PORT=-1",
		"RASPUTIN_OBS_INGEST_ADDR=127.0.0.1:0",
		"RASPUTIN_MESH_BACKEND=mock", "RASPUTIN_DNS=off",
		"RASPUTIN_IDENTITY_BACKEND=keycloak",
		"RASPUTIN_IDENTITY_ADDR=https://127.0.0.1:" + strconv.Itoa(s.kcHTTPS),
		"RASPUTIN_IDENTITY_MGMT_ADDR=https://127.0.0.1:" + strconv.Itoa(s.kcMgmt),
		"RASPUTIN_UI_DIR=" + os.Getenv(UIDirEnv),
		"RASPUTIN_CP_AUTHORIZED_KEYS=" + filepath.Join(s.work, "no-authorized-keys"),
		"RASPUTIN_RELEASE_API_BASE=" + dead, "RASPUTIN_RELEASE_DOWNLOAD_BASE=" + dead, "RASPUTIN_CATALOG_API_BASE=" + dead,
	}
	for _, line := range strings.Split(os.Getenv(ConsoleAPIEnvEnv), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			env = append(env, line)
		}
	}
	cmd := exec.Command(bin) // G204: the binary the recipe or CI built from this tree
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the api: %v", err)
	}
	s.api, s.apiDone = cmd, make(chan struct{})
	go func() { _ = cmd.Wait(); close(s.apiDone) }()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-s.apiDone:
		case <-time.After(30 * time.Second): // bounds the stop only
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-s.apiDone
		}
		_ = logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(s.out, "api.log"))
			t.Logf("--- api log (tail) ---\n%s", tail(b, 60))
		}
	})
}

// apiAlive is nil while the api runs.
func (s *consoleStack) apiAlive() error {
	select {
	case <-s.apiDone:
		return fmt.Errorf("the api exited: %v", s.api.ProcessState)
	default:
		return nil
	}
}

// awaitFiles waits on the fact that every path exists, and on the api
// staying up.
func (s *consoleStack) awaitFiles(ctx context.Context, fact string, paths ...string) {
	s.t.Helper()
	err := proctest.Await(ctx, nil, func(context.Context) (bool, string, error) {
		if err := s.apiAlive(); err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				return false, "no " + p, nil
			}
		}
		return true, "", nil
	}, func(last string) { s.cfg.Logger.Info("console stack: waiting", "fact", fact, "last", last) })
	if err != nil {
		s.t.Fatal(errNamed(fact, err))
	}
}

// newConsolePair is the pair under the product's unit names, rooted in
// work, so the units' files live where a sibling container sees them.
func newConsolePair(t *testing.T, cfg Config, work string, container bool) *systemdPair {
	t.Helper()
	tag, err := randomHex(cfg.Rand, 6)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(work, "pair")
	if err := atrest.EnsureSecretDir(root); err != nil {
		t.Fatal(err)
	}
	p := &systemdPair{
		t: t, cfg: cfg, d: docker{bin: cfg.DockerBin, run: cfg.Run}, run: cfg.Run, tag: tag, root: root,
		DBUnit: identityDBUnitName, KCUnit: identityUnitName, Target: "rasputin-console-idst-" + tag + ".target",
		noTmpfs: container,
	}
	p.PGData = filepath.Join(root, "pgdata")
	p.Exits = filepath.Join(root, "exits")
	t.Cleanup(p.cleanup)
	return p
}

// The product's unit names, which the api reads.
const (
	identityDBUnitName = "keycloak-db.service"
	identityUnitName   = "keycloak.service"
)

// startKeycloak builds Keycloak's home and config on the api's PKI,
// imports the repo's realm baseline, and starts keycloak.service.
func (s *consoleStack) startKeycloak(ctx context.Context) error {
	p := s.pair
	h, err := New(s.cfg)
	if err != nil {
		return err
	}
	e := &Env{h: h, log: s.cfg.Logger, docker: p.d, root: filepath.Join(s.work, "kc-env"), ports: &reportedPorts{}}
	p.KC = e
	if err := atrest.EnsureSecretDir(e.root); err != nil {
		return err
	}
	e.ports.https, e.ports.mgmt = s.kcHTTPS, s.kcMgmt
	home, err := e.makeKeycloakHome()
	if err != nil {
		return err
	}
	for _, d := range []string{filepath.Join(e.root, "vault"), filepath.Join(home, "data")} {
		if err := atrest.EnsureSecretDir(d); err != nil {
			return err
		}
	}
	trust := filepath.Join(s.dataDir, "trust")
	conf := filepath.Join(e.root, "keycloak.conf")
	body := renderKeycloakConf(kcPaths{
		CertFile:      filepath.Join(s.dataDir, "tls", "identity-server", "leaf.pem"),
		KeyFile:       filepath.Join(s.dataDir, "tls", "identity-server", "leaf.key"),
		TrustFile:     filepath.Join(trust, "identity-ca.pem"),
		OutboundTrust: filepath.Join(trust, "identity-ca.pem") + "," + filepath.Join(trust, "mesh-ca.pem"),
		VaultDir:      filepath.Join(e.root, "vault"),
	}, kcPorts{HTTPS: s.kcHTTPS, Mgmt: s.kcMgmt, DB: p.DBPort}, "", p.dbPassword)
	err = atrest.WriteSecretFile(conf, body)
	clear(body)
	if err != nil {
		return err
	}
	baseline := filepath.Join(e.root, "rasputin-realm.json")
	if err := copyFile(filepath.Join("..", "..", "..", "identity", "realm-baseline.json"), baseline); err != nil {
		return err
	}
	importCmd := s.kcExec(e, home, conf, "import", "--optimized", "--file", baseline)
	if out, err := s.cfg.Run(ctx, importCmd[0], importCmd[1:]...); err != nil {
		return fmt.Errorf("import the realm baseline: %w\n%s", err, tail(out, 40))
	}
	start := s.kcExec(e, home, conf, "start", "--optimized")
	var u strings.Builder
	u.WriteString("[Unit]\nDescription=identitytest console stack identity service\nRequires=" + p.DBUnit + "\nAfter=" + p.DBUnit + "\n")
	u.WriteString("\n[Service]\nRestart=no\nSuccessExitStatus=143\nWorkingDirectory=" + home + "\n")
	u.WriteString("StandardOutput=append:" + filepath.Join(p.root, "kc.out") + "\nStandardError=append:" + filepath.Join(p.root, "kc.out") + "\n")
	u.WriteString("ExecStart=" + strings.Join(start, " ") + "\n")
	if err := p.writeUnit(ctx, p.KCUnit, u.String()); err != nil {
		return err
	}
	target := "[Unit]\nDescription=identitytest console stack\nWants=" + p.KCUnit + " " + p.DBUnit + "\n"
	if err := p.writeUnit(ctx, p.Target, target); err != nil {
		return err
	}
	if out, err := p.run(ctx, "systemctl", "start", p.Target); err != nil {
		return fmt.Errorf("start the console stack's target: %w: %s", err, out)
	}
	return nil
}

// kcExec is the command that runs kc.sh with args: directly, through env
// -i with the unit's JVM environment, or, with a platform set, in a
// container of that platform on the pinned PostgreSQL image as its glibc
// base, with every path it reads mounted at the same place.
func (s *consoleStack) kcExec(e *Env, home, conf string, args ...string) []string {
	kc := append([]string{filepath.Join(home, "bin", "kc.sh"), "--config-file=" + conf}, args...)
	platform := os.Getenv(ConsoleKCPlatformEnv)
	if platform == "" {
		return append(append([]string{"/usr/bin/env", "-i"}, e.kcEnv()...), kc...)
	}
	cmd := []string{s.cfg.DockerBin, "run", "--rm", "--label", s.pair.label(), "--platform", platform, "--network", "host",
		"--entrypoint", kc[0], "-w", home}
	seen := map[string]bool{}
	for _, dir := range []string{s.work, s.cfg.KeycloakHome, s.cfg.JavaHome, s.cfg.ThemeDir} {
		if dir != "" && !seen[dir] {
			seen[dir] = true
			cmd = append(cmd, "-v", dir+":"+dir)
		}
	}
	for _, kv := range e.kcEnv() {
		if !strings.HasPrefix(kv, "PATH=") {
			cmd = append(cmd, "-e", kv)
		}
	}
	return append(append(cmd, PostgresImage), kc[1:]...)
}

// adminSession is the Admin API as rasputin-admin over the api's own
// identity client leaf.
func (s *consoleStack) adminSession(t *testing.T) *idclient.Session {
	t.Helper()
	ca, err := os.ReadFile(filepath.Join(s.dataDir, "trust", "identity-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(s.dataDir, "tls", "identity-api-client")
	tlsCfg, err := looptls.NewClientTLS(ca, filepath.Join(leaf, "leaf.pem"), filepath.Join(leaf, "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://127.0.0.1:" + strconv.Itoa(s.kcHTTPS))
	m, _ := url.Parse("https://127.0.0.1:" + strconv.Itoa(s.kcMgmt))
	c, err := idclient.New(idclient.Config{Addr: u, MgmtAddr: m, TLS: tlsCfg, CallTimeout: time.Minute, Logger: s.cfg.Logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	sess, err := idclient.NewSession(idclient.SessionConfig{Login: c, Admin: c, Realm: baselineRealm, ClientID: baselineAdminClient, Log: s.cfg.Logger})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// client reaches the api's https listener as ci.local and sso-ci.local,
// trusting only the api's controlplane CA. Names are not checked: the
// leaves are the api's own, and the CA is this run's.
func (s *consoleStack) client(jar http.CookieJar) *http.Client {
	pool := x509.NewCertPool()
	if b, err := os.ReadFile(filepath.Join(s.dataDir, "trust", "mesh-ca.pem")); err == nil {
		pool.AppendCertsFromPEM(b)
	}
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no certificate")
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
		return err
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:"+s.port)
		},
		// The chain is checked against this run's CA by VerifyConnection.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: verify}, // #nosec G402 -- verified against the run's CA
	}
	return &http.Client{Transport: tr, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// awaitReady waits on the facts that /api/auth/status says ready and that
// converge has written the console's redirect URI.
func (s *consoleStack) awaitReady(ctx context.Context, admin *idclient.Session) {
	s.t.Helper()
	c := s.client(nil)
	want := "https://" + consoleCID + ".local/api/auth/callback"
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		if err := s.apiAlive(); err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		if st, err := unitState(ctx, s.pair.run, s.pair.KCUnit); err == nil && strings.HasPrefix(st, "failed/") {
			return false, "", &proctest.Final{Err: fmt.Errorf("keycloak.service is %s:\n%s", st, s.pair.KCOutput())}
		}
		resp, err := c.Get("https://" + consoleCID + ".local/api/auth/status")
		if err != nil {
			return false, err.Error(), nil
		}
		var st struct {
			Ready bool `json:"ready"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&st)
		_ = resp.Body.Close()
		if !st.Ready {
			return false, "status ready:false", nil
		}
		var clients []struct {
			RedirectURIs []string `json:"redirectUris"`
		}
		if _, err := admin.Admin(ctx, http.MethodGet, "/admin/realms/"+baselineRealm+"/clients?clientId="+baselineConsole, nil, &clients); err != nil {
			return false, err.Error(), nil
		}
		if len(clients) != 1 || !slices.Contains(clients[0].RedirectURIs, want) {
			return false, "converge has not written the console's redirect URI", nil
		}
		return true, "", nil
	}, func(last string) { s.cfg.Logger.Info("console stack: waiting for ready", "last", last) })
	if err != nil {
		s.t.Fatal(errNamed("the api is ready to sign in and converge wrote the console's redirect URI", err))
	}
}

// fixture makes the synthetic fixture account with a password and the
// console's viewer role, and returns its subject. Not admin or operator:
// the sign-in rules refuse a password alone for those (TC-987-01).
func (s *consoleStack) fixture(t *testing.T, admin *idclient.Session) string {
	t.Helper()
	pw, err := randomSecret(s.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	s.fixturePassword = pw
	ctx := t.Context()
	resp, err := admin.Admin(ctx, http.MethodPost, "/admin/realms/"+baselineRealm+"/users", map[string]any{
		"username": consoleFixture, "enabled": true, "email": consoleFixture + "@console.invalid", "emailVerified": true,
		"firstName": "Console", "lastName": "Fixture",
		"credentials": []map[string]any{{"type": "password", "value": string(pw.Reveal()), "temporary": false}},
	}, nil)
	if err != nil {
		t.Fatalf("create the fixture: %v", err)
	}
	id := resp.Location[strings.LastIndex(resp.Location, "/")+1:]
	var clients []struct {
		ID string `json:"id"`
	}
	if _, err := admin.Admin(ctx, http.MethodGet, "/admin/realms/"+baselineRealm+"/clients?clientId="+baselineConsole, nil, &clients); err != nil || len(clients) != 1 {
		t.Fatalf("the console client: %v", err)
	}
	var role map[string]any
	if _, err := admin.Admin(ctx, http.MethodGet, "/admin/realms/"+baselineRealm+"/clients/"+clients[0].ID+"/roles/viewer", nil, &role); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Admin(ctx, http.MethodPost, "/admin/realms/"+baselineRealm+"/users/"+id+"/role-mappings/clients/"+clients[0].ID, []any{role}, nil); err != nil {
		t.Fatal(err)
	}
	return id
}

// signInGo signs the fixture in with the Go client through the launcher's
// route and returns the session cookie's value.
func (s *consoleStack) signInGo(ctx context.Context, pw secret.Value) string {
	s.t.Helper()
	c := s.client(nil)
	jar, pages, err := signin.ConsoleSignIn(ctx, signin.Console{Origin: "https://" + consoleCID + ".local", Transport: c.Transport, Logger: s.cfg.Logger},
		consoleFixture, pw)
	if err != nil {
		s.t.Fatalf("the console sign-in (pages %v): %v", pages, err)
	}
	u, _ := url.Parse("https://" + consoleCID + ".local/")
	for _, ck := range jar.Cookies(u) {
		if ck.Name == auth.SessionCookieName {
			return ck.Value
		}
	}
	s.t.Fatal("the sign-in left no console session")
	return ""
}

// browser starts a harness Env holding only the browser, with the cluster's
// names mapped to the api's listener and its leaves trusted by SPKI.
func (s *consoleStack) browser(ctx context.Context) context.Context {
	t := s.t
	h, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{h: h, log: s.cfg.Logger, root: filepath.Join(s.work, "browser")}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	if err := atrest.EnsureSecretDir(e.root); err != nil {
		t.Fatal(err)
	}
	e.frontLeaf.CertPath = filepath.Join(s.dataDir, "tls", "api", "leaf.pem")
	home, err := spkiHash(filepath.Join(s.dataDir, "tls", "signin-home", "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	e.browserSPKI = []string{home}
	e.browserRules = "MAP " + consoleCID + ".local:443 127.0.0.1:" + s.port + ",MAP sso-" + consoleCID + ".local:443 127.0.0.1:" + s.port
	t.Cleanup(func() {
		if err := e.Close(context.Background()); err != nil {
			t.Errorf("the browser's teardown: %v", err)
		}
	})
	bctx, _, err := e.Browser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return bctx
}

// signInBrowser signs the fixture in in the pinned Chrome from the UI's
// launcher, screenshots the console's /, and returns the session cookie.
func (s *consoleStack) signInBrowser(ctx context.Context, pw secret.Value) string {
	t := s.t
	tb := newTab(t, s.browser(ctx), "https://"+consoleCID+".local")
	tb.navigate("https://" + consoleCID + ".local/login")
	tb.step(chromedp.WaitVisible(chromedp.CSS(`a[href="/api/auth/signin"]`)), "wait for the launcher's SIGN IN")
	if got := tb.submit(chromedp.Click(chromedp.CSS(`a[href="/api/auth/signin"]`)), "press SIGN IN"); got != "login-login" {
		t.Fatalf("SIGN IN led to %q", got)
	}
	signIn(tb, consoleFixture, pw)
	status := evalT[float64](tb, `fetch('/api/auth/me', {credentials: 'same-origin'}).then((r) => r.status)`)
	if status != http.StatusOK {
		t.Fatalf("/api/auth/me in the browser answered %v after the sign-in", status)
	}
	tb.navigate("https://" + consoleCID + ".local/")
	if path := evalT[string](tb, `location.pathname`); path == "/login" {
		t.Fatal("the console's / sent the signed-in browser to /login")
	}
	sctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	png, err := chromedp.Run(sctx, chromedp.FullScreenshot(90))
	if err != nil {
		t.Fatalf("screenshot: %v", err)
	}
	shot := filepath.Join(s.out, "shots", "root.png")
	if err := os.MkdirAll(filepath.Dir(shot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shot, png, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("screenshot of the signed-in console's /: %s (%d bytes)", shot, len(png))
	// The session cookie is HttpOnly: it is read over CDP.
	cctx, ccancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer ccancel()
	res, err := chromedp.Call(cctx, network.GetCookies, network.GetCookiesParams{URLs: []string{"https://" + consoleCID + ".local/"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cookies {
		if c.Name == auth.SessionCookieName {
			return c.Value
		}
	}
	t.Fatal("the browser holds no console session")
	return ""
}

// checkMe asserts /api/auth/me answers 200 with the fixture's subject and
// role for cookie.
func (s *consoleStack) checkMe(cookie, sub string) {
	t := s.t
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://" + consoleCID + ".local/")
	jar.SetCookies(u, []*http.Cookie{{Name: auth.SessionCookieName, Value: cookie, Path: "/", Secure: true}})
	resp, err := s.client(jar).Get(u.String() + "api/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var me struct {
		Sub   string   `json:"sub"`
		Name  string   `json:"name"`
		Roles []string `json:"roles"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &me) != nil || me.Sub != sub || !slices.Contains(me.Roles, "viewer") {
		t.Fatalf("/api/auth/me = %d %s, want 200 with the fixture's subject %s and role viewer", resp.StatusCode, b, sub)
	}
	if err := os.WriteFile(filepath.Join(s.out, "me.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("/api/auth/me: %s", b)
}

// writeOutputs writes session.cookie (0600), the api leaf's SPKI hash, and
// the ready marker last.
func (s *consoleStack) writeOutputs(cookie string) {
	t := s.t
	if err := atrest.WriteSecretFile(filepath.Join(s.out, "session.cookie"), []byte(cookie+"\n")); err != nil {
		t.Fatal(err)
	}
	spki, err := spkiHash(filepath.Join(s.dataDir, "tls", "api", "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.out, "api-spki"), []byte(spki+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.out, "ready"), []byte(s.port+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// hold waits on two facts: the stop file appearing, which ends the run
// cleanly, or a component dying, which fails it. The binary's
// -test.timeout, which the recipe sets, bounds it.
func (s *consoleStack) hold(ctx context.Context) {
	stop := filepath.Join(s.out, "stop")
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		if _, err := os.Stat(stop); err == nil {
			return true, "", nil
		}
		if err := s.apiAlive(); err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		for _, u := range []string{s.pair.KCUnit, s.pair.DBUnit} {
			st, err := unitState(ctx, s.pair.run, u)
			if err != nil {
				return false, "", err
			}
			if st != "active/running" {
				return false, "", &proctest.Final{Err: fmt.Errorf("%s is %s", u, st)}
			}
		}
		return false, "holding", nil
	}, func(string) {})
	if err != nil {
		s.t.Fatal(errNamed("the stop file appears while the stack runs", err))
	}
	s.cfg.Logger.Info("console stack: stop file seen; tearing down", "file", stop)
}
