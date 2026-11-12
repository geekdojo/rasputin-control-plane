// Package identitytest runs the real, pinned identity service for a test
// package: Keycloak 26.8.2 from the pinned tarball on the pinned Temurin JRE,
// built with the production build options (identity/keycloak-build.conf),
// against digest-pinned PostgreSQL 18.6 in a container. Headscale, at the
// image mesh-images.json pins, and Chrome for Testing, driven by chromedp,
// start on demand. A test package gets one of each through Package
// (package.go), and its TestMain tears them down with proof: no process, no
// container and no directory are left behind (geekdojo/geekdojo-brain#966,
// docs/testing-identity.md).
//
// Readiness is the service's own answer, /health/ready on the management port
// over mutual TLS with a test CA, never a duration. Keycloak listens on ports
// the kernel assigns, which it reports in its start line, so no port is
// guessed before it binds.
//
// The front is an httptest TLS server whose reverse proxy presents the client
// leaf to Keycloak. It stands in for the door (Identity 4.3) and is not the
// door: it forwards everything. It exists because https-client-auth=required
// holds for every caller, a browser included.
//
// Tests import it; nothing in a shipped binary does.
package identitytest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	// Realm is the realm the harness imports; ClientID its public client;
	// RedirectURI the client's one redirect URI. The client never follows the
	// redirect, so nothing listens there.
	Realm       = "harness"
	ClientID    = "harness-public"
	RedirectURI = "https://127.0.0.1/callback"
	// UserName is the realm's one user.
	UserName = "harness-user"

	// outputTail is how many of Keycloak's last output lines an early-exit
	// error carries. Keycloak logs to stdout, so both streams are kept.
	outputTail = 5

	dbName = "keycloak"
	dbUser = "keycloak"
)

// The unit's JVM environment (platform.md §3.2, keycloak.service), so the
// service under test starts the way the product's does. UuidProcessId keeps
// Narayana from holding a third loopback port.
const (
	mallocArenaMax = "2"
	javaOptsHeap   = "-Xms128m -Xmx384m"
	javaOptsAppend = "-XX:-UsePerfData -XX:ErrorFile=/dev/null -XX:-CreateCoredumpOnCrash -Djava.awt.headless=true " +
		"-Djava.net.preferIPv4Stack=true " +
		"-Dcom.arjuna.ats.internal.arjuna.utils.processImplementation=com.arjuna.ats.internal.arjuna.utils.UuidProcessId"
)

// CmdRunner runs a command and returns its combined output; mesh.CmdRunner's
// signature, so the same runner drives the Headscale supervisor. The default
// is execrun.CombinedOutput.
type CmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ProcInfo is one live process, as the teardown proof sees it.
type ProcInfo struct {
	Pid     int
	Cmdline string
	Cwd     string
}

// ProcLister lists the live processes the caller can see. ScanProc reads
// /proc.
type ProcLister func() ([]ProcInfo, error)

// Config is everything the harness needs, passed in by the test package's
// composition root (ConfigFromEnv).
type Config struct {
	// KeycloakHome is the installed, already-built Keycloak distribution
	// (bin/kc.sh). It is never written: each Env runs from a home of its own
	// whose bin/ is a copy and whose other entries link here.
	KeycloakHome string
	// JavaHome is the Temurin JRE (bin/java).
	JavaHome string
	// ChromePath is the Chrome for Testing binary.
	ChromePath string
	// DockerBin is the docker CLI.
	DockerBin string
	// TempParent is where each Env makes its temporary root.
	TempParent string
	// Logger receives the harness's records and, at DEBUG, each line
	// Keycloak writes.
	Logger *slog.Logger
	// Now dates the test CA and its leaves.
	Now func() time.Time
	// Rand feeds the CA keys, the passwords, PKCE, state, nonce and the
	// container name suffixes.
	Rand io.Reader
	// Run runs docker and kc.sh --version.
	Run CmdRunner
	// Procs lists live processes for the teardown proof.
	Procs ProcLister
}

// Harness starts Envs. It holds only its Config.
type Harness struct {
	cfg Config
}

// New checks cfg and returns a Harness. It does no I/O.
func New(cfg Config) (*Harness, error) {
	missing := ""
	switch {
	case cfg.KeycloakHome == "":
		missing = "KeycloakHome is empty"
	case cfg.JavaHome == "":
		missing = "JavaHome is empty"
	case cfg.ChromePath == "":
		missing = "ChromePath is empty"
	case cfg.DockerBin == "":
		missing = "DockerBin is empty"
	case cfg.TempParent == "":
		missing = "TempParent is empty"
	case cfg.Logger == nil:
		missing = "Logger is nil"
	case cfg.Now == nil:
		missing = "Now is nil"
	case cfg.Rand == nil:
		missing = "Rand is nil"
	case cfg.Run == nil:
		missing = "Run is nil"
	case cfg.Procs == nil:
		missing = "Procs is nil"
	}
	if missing != "" {
		return nil, errors.New("identitytest: Config." + missing)
	}
	return &Harness{cfg: cfg}, nil
}

// Env is one running identity service with its database and front, and the
// on-demand mesh coordinator and browser.
type Env struct {
	h      *Harness
	log    *slog.Logger
	docker docker
	root   string

	ca        *tlsca.CA
	clientTLS *tls.Config
	frontLeaf tlsca.LeafPaths

	password   secret.Value // the realm user's
	dbPassword secret.Value

	pgID   string // the PostgreSQL container id, once it exists
	kc     *proctest.Proc
	ports  *reportedPorts
	front  *httptest.Server
	issuer string

	// ctx is cancelled by Close; the browser's allocator lives under it.
	ctx    context.Context
	cancel context.CancelFunc

	hsOnce sync.Once
	hs     *headscaleEnv
	hsErr  error

	brOnce sync.Once
	br     *browserEnv
	brErr  error

	closeOnce sync.Once
	closeErr  error
}

// Issuer is the realm's issuer, <FrontURL>/realms/harness: Keycloak's
// hostname is the front's URL.
func (e *Env) Issuer() string { return e.issuer }

// FrontURL is the front's https://127.0.0.1:<port>.
func (e *Env) FrontURL() string { return e.front.URL }

// ManagementURL is Keycloak's management interface, which serves
// /health/ready and requires a client certificate.
func (e *Env) ManagementURL() string {
	_, mgmt := e.ports.get()
	return "https://127.0.0.1:" + strconv.Itoa(mgmt)
}

// ClientTLS trusts only the test CA, speaks TLS 1.3 and presents the
// test-CA client leaf. It reaches Keycloak directly and the front. Each call
// returns a fresh copy.
func (e *Env) ClientTLS() *tls.Config { return e.clientTLS.Clone() }

// Roots is a pool holding only the test CA.
func (e *Env) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(e.ca.Cert)
	return p
}

// User is the realm's one user and its password. The password is the Env's
// own; a caller must not Destroy it.
func (e *Env) User() (name string, password secret.Value) { return UserName, e.password }

// reportedPorts holds the ports Keycloak reports it bound.
type reportedPorts struct {
	mu          sync.Mutex
	https, mgmt int
}

func (r *reportedPorts) get() (https, mgmt int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.https, r.mgmt
}

// listeningRE is Keycloak's start line: "... started in 1.9s. Listening on:
// https://127.0.0.1:55679. Management interface listening on
// https://127.0.0.1:55678." (26.8.2, measured).
var listeningRE = regexp.MustCompile(`Listening on: https://127\.0\.0\.1:(\d+)\. Management interface listening on https://127\.0\.0\.1:(\d+)\.`)

// watch reads the bound ports from a Keycloak output line.
func (r *reportedPorts) watch(line string) {
	m := listeningRE.FindStringSubmatch(line)
	if m == nil {
		return
	}
	https, err1 := strconv.Atoi(m[1])
	mgmt, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.https, r.mgmt = https, mgmt
}

// Start brings up PostgreSQL, Keycloak and the front, and returns once
// /health/ready answers UP over mutual TLS. On any failure it tears down
// whatever it made and returns the error joined with any teardown error.
//
// ctx bounds the waits. A Keycloak that never becomes ready and never exits is
// the case only ctx can end.
func (h *Harness) Start(ctx context.Context) (*Env, error) {
	version, jvm, err := h.checkKeycloakVersion(ctx)
	if err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(h.cfg.TempParent, "identity-")
	if err != nil {
		return nil, fmt.Errorf("identitytest: temp root: %w", err)
	}
	envCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	e := &Env{
		h: h, log: h.cfg.Logger, docker: docker{bin: h.cfg.DockerBin, run: h.cfg.Run},
		root: root, ports: &reportedPorts{}, ctx: envCtx, cancel: cancel,
	}
	if err := e.start(ctx, version, jvm); err != nil {
		// Teardown waits for Keycloak to honour SIGTERM; the caller's ctx may
		// be what ended, so it runs under one that carries the values only.
		return nil, errors.Join(err, e.Close(context.WithoutCancel(ctx)))
	}
	return e, nil
}

func (e *Env) start(ctx context.Context, version, jvm string) error {
	cfg := e.h.cfg
	if err := atrest.EnsureSecretDir(e.root); err != nil {
		return fmt.Errorf("identitytest: temp root: %w", err)
	}
	if err := e.makeTLS(); err != nil {
		return err
	}
	var err error
	if e.password, err = randomSecret(cfg.Rand); err != nil {
		return fmt.Errorf("identitytest: user password: %w", err)
	}
	if e.dbPassword, err = randomSecret(cfg.Rand); err != nil {
		return fmt.Errorf("identitytest: database password: %w", err)
	}
	dbPort, err := e.startPostgres(ctx)
	if err != nil {
		return err
	}

	// The front's listener is bound now, so its URL is Keycloak's hostname;
	// it serves only once Keycloak is ready.
	front, err := e.newFront()
	if err != nil {
		return err
	}
	e.front = front
	frontURL := "https://" + front.Listener.Addr().String()
	e.issuer = frontURL + "/realms/" + Realm

	home, err := e.makeKeycloakHome()
	if err != nil {
		return err
	}
	confPath := filepath.Join(e.root, "keycloak.conf")
	conf := renderKeycloakConf(kcPaths{
		CertFile:  filepath.Join(e.root, "server", "leaf.pem"),
		KeyFile:   filepath.Join(e.root, "server", "leaf.key"),
		TrustFile: filepath.Join(e.root, "ca", caCertFile),
		VaultDir:  filepath.Join(e.root, "vault"),
	}, kcPorts{DB: dbPort}, frontURL, e.dbPassword)
	defer clear(conf)
	if err := atrest.WriteSecretFile(confPath, conf); err != nil {
		return fmt.Errorf("identitytest: keycloak.conf: %w", err)
	}
	if err := atrest.EnsureSecretDir(filepath.Join(e.root, "vault")); err != nil {
		return fmt.Errorf("identitytest: vault dir: %w", err)
	}
	importDir := filepath.Join(home, "data", "import")
	if err := atrest.EnsureSecretDir(importDir); err != nil {
		return fmt.Errorf("identitytest: realm import dir: %w", err)
	}
	realm, err := renderRealm(UserName, e.password)
	if err != nil {
		return err
	}
	defer clear(realm)
	if err := atrest.WriteSecretFile(filepath.Join(importDir, Realm+"-realm.json"), realm); err != nil {
		return fmt.Errorf("identitytest: realm file: %w", err)
	}

	p, err := proctest.Start(proctest.Spec{
		Bin:  filepath.Join(home, "bin", "kc.sh"),
		Args: []string{"--config-file=" + confPath, "start", "--optimized", "--import-realm"},
		Env: []string{
			"PATH=/usr/bin:/bin",
			"HOME=" + e.root,
			"JAVA_HOME=" + cfg.JavaHome,
			"MALLOC_ARENA_MAX=" + mallocArenaMax,
			"JAVA_OPTS_KC_HEAP=" + javaOptsHeap,
			"JAVA_OPTS_APPEND=" + javaOptsAppend,
		},
		Dir:    home,
		Logger: e.log, Name: "identity service", Source: "keycloak",
		StdoutTail: outputTail, StderrTail: outputTail,
		Group: true,
		Watch: e.ports.watch,
	})
	if err != nil {
		return fmt.Errorf("identitytest: %w", err)
	}
	e.kc = p
	if err := e.awaitReady(ctx); err != nil {
		return err
	}
	https, mgmt := e.ports.get()
	if err := e.serveFront(https); err != nil {
		return err
	}
	e.log.Info("identity service started", "addr", "127.0.0.1:"+strconv.Itoa(https),
		"mgmt_addr", "127.0.0.1:"+strconv.Itoa(mgmt), "pid", p.Pid(), "version", version, "jvm", jvm, "dir", e.root)
	return nil
}

// caCertFile and caKeyFile are the test CA's files under <root>/ca.
const (
	caCertFile = "identitytest-ca.pem"
	caKeyFile  = "identitytest-ca.key"
)

// caConfig is the store CA's code with its name, files and subject
// overridden; it keeps the store CA's lifetime and both usages.
func caConfig() tlsca.Config {
	c := tlsca.StoreConfig()
	c.Name = "identitytest"
	c.CertFile = caCertFile
	c.KeyFile = caKeyFile
	c.SubjectFormat = "Rasputin identitytest CA (%s)"
	return c
}

// makeTLS makes the test CA, Keycloak's server leaf, the front's leaf and
// the client leaf, and the client TLS config.
func (e *Env) makeTLS() error {
	cfg := e.h.cfg
	ca, err := tlsca.Ensure(caConfig(), filepath.Join(e.root, "ca"), "identitytest",
		tlsca.Deps{Now: cfg.Now, Rand: cfg.Rand, Log: cfg.Logger})
	if err != nil {
		return fmt.Errorf("identitytest: test CA: %w", err)
	}
	e.ca = ca
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}
	// One directory per leaf: MintLeafToDisk writes leaf.pem/leaf.key in the
	// directory it is given.
	if _, err := ca.MintLeafToDisk(filepath.Join(e.root, "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "identitytest keycloak", IPAddresses: loopback,
	}); err != nil {
		return fmt.Errorf("identitytest: server leaf: %w", err)
	}
	if e.frontLeaf, err = ca.MintLeafToDisk(filepath.Join(e.root, "front"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "identitytest front", IPAddresses: loopback,
	}); err != nil {
		return fmt.Errorf("identitytest: front leaf: %w", err)
	}
	client, err := ca.MintLeafToDisk(filepath.Join(e.root, "client"), tlsca.LeafSpec{
		Usage: tlsca.UsageClient, CommonName: "identitytest-client",
	})
	if err != nil {
		return fmt.Errorf("identitytest: client leaf: %w", err)
	}
	pair, err := tls.LoadX509KeyPair(client.CertPath, client.KeyPath)
	if err != nil {
		return fmt.Errorf("identitytest: client leaf: %w", err)
	}
	e.clientTLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      e.Roots(),
		Certificates: []tls.Certificate{pair},
	}
	return nil
}

// makeKeycloakHome builds this Env's Keycloak home: bin/ is copied, so kc.sh
// resolves its home here; every other entry of the installed dist links to
// it, and data/ is this Env's own, so two packages can run Keycloak at once.
// Keycloak writes only under data/ (#958), which is why linking lib/ is safe.
func (e *Env) makeKeycloakHome() (string, error) {
	src := e.h.cfg.KeycloakHome
	home := filepath.Join(e.root, "kc")
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o700); err != nil {
		return "", fmt.Errorf("identitytest: keycloak home: %w", err)
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return "", fmt.Errorf("identitytest: keycloak home: %w", err)
	}
	for _, ent := range ents {
		switch ent.Name() {
		case "bin", "data":
			continue
		}
		if err := os.Symlink(filepath.Join(src, ent.Name()), filepath.Join(home, ent.Name())); err != nil {
			return "", fmt.Errorf("identitytest: keycloak home: %w", err)
		}
	}
	bins, err := os.ReadDir(filepath.Join(src, "bin"))
	if err != nil {
		return "", fmt.Errorf("identitytest: keycloak home: %w", err)
	}
	for _, b := range bins {
		if b.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(src, "bin", b.Name()), filepath.Join(home, "bin", b.Name())); err != nil {
			return "", fmt.Errorf("identitytest: keycloak home: %w", err)
		}
	}
	return home, nil
}

// copyFile copies a file of the installed dist, keeping its mode.
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, info.Mode().Perm())
}

// awaitReady returns once /health/ready answers 200 with status UP over
// mutual TLS. Until Keycloak reports its ports there is nothing to ask.
func (e *Env) awaitReady(ctx context.Context) error {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: e.ClientTLS()}}
	defer client.CloseIdleConnections()
	err := proctest.Await(ctx, e.kc, func(ctx context.Context) (bool, string, error) {
		_, mgmt := e.ports.get()
		if mgmt == 0 {
			return false, "ports not reported yet", nil
		}
		return checkReady(ctx, client, "https://127.0.0.1:"+strconv.Itoa(mgmt)+"/health/ready")
	}, func(last string) {
		e.log.Debug("identity service not ready yet", "health", last)
	})
	var notReady *proctest.NotReadyError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &notReady):
		return fmt.Errorf("identitytest: identity service not ready when ctx ended (last health: %s): %w",
			notReady.Last, notReady.Err)
	default:
		return fmt.Errorf("identitytest: identity service exited before it was ready: %w", err)
	}
}

// checkReady asks /health/ready once: 200 with "status":"UP" is ready.
func checkReady(ctx context.Context, client *http.Client, url string) (bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	// The body has been read or its read error reported; a failed close only
	// makes the transport drop the connection.
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return false, fmt.Sprintf("%d, unreadable body: %v", resp.StatusCode, err), nil
	}
	up := strings.Contains(strings.ReplaceAll(string(body), " ", ""), `"status":"UP"`)
	return resp.StatusCode == http.StatusOK && up, fmt.Sprintf("%d up=%t", resp.StatusCode, up), nil
}

// newFront binds the front's listener and gives it the front leaf. It does
// not serve until serveFront.
func (e *Env) newFront() (*httptest.Server, error) {
	pair, err := tls.LoadX509KeyPair(e.frontLeaf.CertPath, e.frontLeaf.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("identitytest: front leaf: %w", err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	srv.Config.ErrorLog = slog.NewLogLogger(e.log.Handler(), slog.LevelDebug)
	return srv, nil
}

// serveFront points the front at Keycloak's https port and starts it. Its
// proxy presents the client leaf and keeps the browser's Host.
func (e *Env) serveFront(httpsPort int) error {
	target, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(httpsPort))
	if err != nil {
		return fmt.Errorf("identitytest: front target: %w", err)
	}
	e.front.Config.Handler = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{TLSClientConfig: e.ClientTLS()},
		ErrorLog:  slog.NewLogLogger(e.log.Handler(), slog.LevelWarn),
	}
	e.front.StartTLS()
	return nil
}

// Close stops everything the Env started, in the order browser, Headscale,
// front, Keycloak, PostgreSQL, then removes the root, and proves teardown: it
// returns the joined errors unless Keycloak was reaped with its whole process
// group, each container is gone, no live process names the root, and the
// root is gone.
//
// Keycloak gets SIGTERM; only if ctx ends first does it get SIGKILL, with a
// WARN. A caller that wants a clean stop passes a ctx that does not end.
// Close is idempotent.
func (e *Env) Close(ctx context.Context) error {
	e.closeOnce.Do(func() { e.closeErr = e.teardown(ctx) })
	return e.closeErr
}

func (e *Env) teardown(ctx context.Context) error {
	var errs []error
	var containers []string
	if e.br != nil {
		errs = append(errs, e.br.close())
	}
	if e.cancel != nil {
		e.cancel()
	}
	if e.hs != nil {
		containers = append(containers, e.hs.id)
		errs = append(errs, e.removeContainer(ctx, e.hs.id, "mesh coordinator"))
	}
	if e.front != nil {
		if e.front.Config.Handler != nil {
			e.front.Close()
		} else if err := e.front.Listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("identitytest: close the front's listener: %w", err))
		}
	}
	if e.kc != nil {
		if err := e.kc.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("identitytest: %w", err))
		}
	}
	if e.pgID != "" {
		containers = append(containers, e.pgID)
		errs = append(errs, e.removeContainer(ctx, e.pgID, "identity database"))
	}
	e.password.Destroy()
	e.dbPassword.Destroy()
	if err := os.RemoveAll(e.root); err != nil {
		errs = append(errs, fmt.Errorf("identitytest: remove %s: %w", e.root, err))
	}
	errs = append(errs, e.prove(ctx, containers))
	return errors.Join(errs...)
}

// removeContainer removes one container and its anonymous volumes.
func (e *Env) removeContainer(ctx context.Context, id, what string) error {
	if err := e.docker.rm(ctx, id); err != nil {
		return fmt.Errorf("identitytest: remove the %s container: %w", what, err)
	}
	e.log.Info(what+" stopped", "container", id)
	return nil
}

// prove is the teardown proof's three checks after the stops: no container
// is still listed, no live process's command line or working directory
// names the root (java, kc.sh, Chrome and its helpers included), and the
// root is gone.
func (e *Env) prove(ctx context.Context, containers []string) error {
	var errs []error
	for _, id := range containers {
		listed, err := e.docker.listed(ctx, id)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("identitytest: cannot show container %s is gone: %w", id, err))
		case listed:
			errs = append(errs, fmt.Errorf("identitytest: teardown left container %s behind", id))
		}
	}
	procs, err := e.h.cfg.Procs()
	if err != nil {
		errs = append(errs, fmt.Errorf("identitytest: cannot show no process is left: %w", err))
	}
	for _, p := range procs {
		if strings.Contains(p.Cmdline, e.root) || p.Cwd == e.root || strings.HasPrefix(p.Cwd, e.root+"/") {
			errs = append(errs, fmt.Errorf("identitytest: teardown left pid %d behind, which names %s: %.200s", p.Pid, e.root, p.Cmdline))
		}
	}
	if _, err := os.Stat(e.root); err == nil {
		errs = append(errs, fmt.Errorf("identitytest: teardown left %s behind", e.root))
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("identitytest: cannot show teardown removed %s: %w", e.root, err))
	}
	return errors.Join(errs...)
}

// ScanProc lists the processes /proc shows: each one's command line, its
// arguments joined by spaces, and its working directory where this user may
// read it. A process that exits during the scan is skipped. A host with no
// /proc cannot prove teardown, so that is an error.
func ScanProc() ([]ProcInfo, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("list /proc: %w", err)
	}
	var out []ProcInfo
	for _, ent := range ents {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join("/proc", ent.Name())
		cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			continue
		}
		cwd, _ := os.Readlink(filepath.Join(dir, "cwd"))
		out = append(out, ProcInfo{
			Pid:     pid,
			Cmdline: strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " ")),
			Cwd:     cwd,
		})
	}
	return out, nil
}

// randomSecret is 24 random bytes as base64url text, which every config
// format the harness writes takes without quoting.
func randomSecret(r io.Reader) (secret.Value, error) {
	s, err := randomToken(r, 24)
	if err != nil {
		return secret.Value{}, err
	}
	return secret.New([]byte(s)), nil
}
