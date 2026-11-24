// Package identitytest runs the real, pinned identity service for a test
// package: Keycloak 26.8.2 from the pinned tarball on the pinned Temurin JRE,
// built with the production build options (identity/keycloak-build.conf),
// against digest-pinned PostgreSQL 18.7 in a container. Headscale, at the
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
// door: it forwards everything except what the door's admin-account guard
// refuses (adminguard, geekdojo/geekdojo-brain#1127). It exists because
// https-client-auth=required holds for every caller, a browser included.
//
// Tests import it; nothing in a shipped binary does.
package identitytest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
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
	// AdminClientID is the realm's administrator client: confidential,
	// service accounts on, no browser flow, authenticated by client-x509 on
	// AdminSubjectDN (the shape #958's K-X509 proved). It admits the api's
	// identity-CA client leaf and refuses the door's (geekdojo/geekdojo-brain#977).
	AdminClientID = "harness-admin"
	// AdminSubjectDN is the subject AdminClientID admits, exactly (no
	// regular expression): the api's identity client leaf's subject.
	AdminSubjectDN = "CN=rasputin-api,O=Rasputin"

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
	// DenylistDir holds the password deny list the realm's policy names,
	// flows.DenylistFile, as scripts/fetch-denylist.sh writes it. Each Env
	// copies it into its Keycloak data directory's password-blacklists/,
	// where rasputin-os stages it on a node (geekdojo/geekdojo-brain#1145).
	DenylistDir string
	// ThemeDir is the built Rasputin login theme (ui/identity-theme's
	// build output), linked as the Env's themes/rasputin, the path Identity
	// 2.3 links on a node. "" runs Keycloak without it; a test that renders
	// the theme treats that as a missing dependency (ThemeEnv).
	ThemeDir string
	// FrontHost is the host name in the front's URL, and so in Keycloak's
	// hostname, the realm's issuer and every page address. "" is 127.0.0.1.
	// A test that registers a passkey sets "localhost": WebAuthn refuses an
	// IP address as its relying party, and localhost is the one name a
	// browser resolves to loopback by itself.
	FrontHost string
	// DoorMode runs Keycloak as it runs behind the sign-in doors: no
	// hostname, the forwarded headers trusted from loopback
	// (renderKeycloakConf). The front still serves, but its addresses follow
	// whatever it forwards; door tests reach Keycloak through ServeDoors.
	DoorMode bool

	// pgRestartable, set only by this package's tests, runs PostgreSQL so a
	// test can docker stop and docker start it under a running Keycloak
	// (TC-979-01): on a fixed loopback port, which a restarted container
	// keeps, and with its data in the image's anonymous volume, which a stop
	// keeps, rather than on a tmpfs, which a stop empties. Teardown's
	// docker rm -v removes the volume.
	pgRestartable bool
}

// Harness starts Envs. It holds only its Config.
type Harness struct {
	cfg Config
}

// New checks cfg and returns a Harness. Its I/O is checking the deny list,
// a non-empty regular file DenylistDir/flows.DenylistFile, and a set
// ThemeDir, a directory holding login/theme.properties, so a missing list or
// a broken theme fails before anything starts.
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
	case cfg.DenylistDir == "":
		missing = "DenylistDir is empty"
	}
	if missing != "" {
		return nil, errors.New("identitytest: Config." + missing)
	}
	if err := checkDenylist(cfg.DenylistDir); err != nil {
		return nil, err
	}
	if cfg.ThemeDir != "" {
		if err := checkThemeDir(cfg.ThemeDir); err != nil {
			return nil, err
		}
	}
	return &Harness{cfg: cfg}, nil
}

// checkDenylist refuses a DenylistDir without a non-empty regular
// flows.DenylistFile, naming the path: the realm's policy names that list,
// and converge cannot apply it without one.
func checkDenylist(dir string) error {
	list := filepath.Join(dir, flows.DenylistFile)
	info, err := os.Stat(list)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("identitytest: the password deny list %s is missing or empty, so the realm's password policy cannot be applied (scripts/install-identity.sh)", list)
	}
	return nil
}

// checkThemeDir refuses a theme that is not a directory holding
// login/theme.properties, naming the path.
func checkThemeDir(dir string) error {
	info, err := os.Stat(dir)
	switch {
	case err != nil:
		return fmt.Errorf("identitytest: the login theme %s cannot be used: %w", dir, err)
	case !info.IsDir():
		return fmt.Errorf("identitytest: the login theme %s is not a directory", dir)
	}
	props := filepath.Join(dir, "login", "theme.properties")
	if info, err := os.Stat(props); err != nil || info.IsDir() {
		return fmt.Errorf("identitytest: the login theme %s holds no login/theme.properties, so it is not a built theme (npm run identity-theme:build)", dir)
	}
	return nil
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

	// kcHome is the Env's own Keycloak home, once Start has made it.
	kcHome string

	pgID   string // the PostgreSQL container id, once it exists
	kc     *proctest.Proc
	ports  *reportedPorts
	front  *httptest.Server
	issuer string
	// frontURL is https://<FrontHost or 127.0.0.1>:<port>, Keycloak's hostname.
	frontURL string
	// refusals counts the requests the front's admin-account guard refused.
	refusals atomic.Int64

	// doorSites are the servers ServeDoors started, and browserRules and
	// browserSPKI the Chrome flags they need; set before Browser starts.
	doorSites    []*httptest.Server
	browserRules string
	browserSPKI  []string

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

// FrontURL is the front's https://127.0.0.1:<port>, or with Config.FrontHost
// as its host.
func (e *Env) FrontURL() string { return e.frontURL }

// FrontRefusals is how many requests the front's admin-account guard has
// refused, each answered 400 and forwarded nowhere.
func (e *Env) FrontRefusals() int64 { return e.refusals.Load() }

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

// CA is the test CA, made from the identity CA's config: Keycloak's trust
// store admits a client leaf only on a chain to it. A test mints the api's
// production identity leaves under it.
func (e *Env) CA() *tlsca.CA { return e.ca }

// KeycloakURL is Keycloak's own https://127.0.0.1:<port>, bypassing the
// front, so a request presents the caller's client leaf and not the front's.
func (e *Env) KeycloakURL() string {
	https, _ := e.ports.get()
	return "https://127.0.0.1:" + strconv.Itoa(https)
}

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
	if cfg.FrontHost != "" {
		_, port, err := net.SplitHostPort(front.Listener.Addr().String())
		if err != nil {
			return fmt.Errorf("identitytest: the front's address: %w", err)
		}
		frontURL = "https://" + net.JoinHostPort(cfg.FrontHost, port)
	}
	e.frontURL = frontURL
	e.issuer = frontURL + "/realms/" + Realm

	home, err := e.makeKeycloakHome()
	if err != nil {
		return err
	}
	e.kcHome = home
	confPath := filepath.Join(e.root, "keycloak.conf")
	hostname := frontURL
	if cfg.DoorMode {
		hostname = ""
	}
	conf := renderKeycloakConf(kcPaths{
		CertFile:  filepath.Join(e.root, "server", "leaf.pem"),
		KeyFile:   filepath.Join(e.root, "server", "leaf.key"),
		TrustFile: filepath.Join(e.root, "ca", caCertFile),
		VaultDir:  filepath.Join(e.root, "vault"),
	}, kcPorts{DB: dbPort}, hostname, e.dbPassword)
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
	rendered, err := renderRealm(UserName, e.password)
	if err != nil {
		return err
	}
	defer clear(rendered)
	realm, err := withAdminClient(rendered)
	if err != nil {
		return err
	}
	defer clear(realm)
	if err := atrest.WriteSecretFile(filepath.Join(importDir, Realm+"-realm.json"), realm); err != nil {
		return fmt.Errorf("identitytest: realm file: %w", err)
	}

	p, err := proctest.Start(e.keycloakSpec(home, confPath, "start", "--optimized", "--import-realm"))
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
		"mgmt_addr", "127.0.0.1:"+strconv.Itoa(mgmt), "pid", p.Pid(), "version", version, "jvm", jvm, "dir", e.root,
		"theme", cfg.ThemeDir)
	return nil
}

// keycloakSpec runs this Env's kc.sh with the config file at conf, then
// args, under the unit's JVM environment and nothing inherited, reporting
// its bound ports to the Env. A test that stops Keycloak and starts it again
// builds its start from the same spec.
func (e *Env) keycloakSpec(home, conf string, args ...string) proctest.Spec {
	return proctest.Spec{
		Bin:    filepath.Join(home, "bin", "kc.sh"),
		Args:   append([]string{"--config-file=" + conf}, args...),
		Env:    e.kcEnv(),
		Dir:    home,
		Logger: e.log, Name: "identity service", Source: "keycloak",
		StdoutTail: outputTail, StderrTail: outputTail,
		Group: true,
		Watch: e.ports.watch,
	}
}

// kcEnv is kc.sh's whole environment: PATH, HOME and the unit's JVM
// variables (platform.md §3.2).
func (e *Env) kcEnv() []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + e.root,
		"JAVA_HOME=" + e.h.cfg.JavaHome,
		"MALLOC_ARENA_MAX=" + mallocArenaMax,
		"JAVA_OPTS_KC_HEAP=" + javaOptsHeap,
		"JAVA_OPTS_APPEND=" + javaOptsAppend,
	}
}

// withAdminClient is the rendered realm with AdminClientID added as its first
// client. It is added here rather than in realm.json.tmpl so the client's
// identifiers come from the constants above, which renderRealm's template data
// does not carry. It refuses a realm whose clients array is not where the
// template puts it. The caller clears the returned bytes, which hold the
// password.
func withAdminClient(realm []byte) ([]byte, error) {
	client, err := json.Marshal(map[string]any{
		"clientId":                  AdminClientID,
		"enabled":                   true,
		"publicClient":              false,
		"clientAuthenticatorType":   "client-x509",
		"standardFlowEnabled":       false,
		"implicitFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    true,
		"protocol":                  "openid-connect",
		"attributes": map[string]string{
			"x509.subjectdn":                      AdminSubjectDN,
			"x509.allow.regex.pattern.comparison": "false",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("identitytest: realm admin client: %w", err)
	}
	anchor := []byte(`"clients": [`)
	if n := bytes.Count(realm, anchor); n != 1 {
		return nil, fmt.Errorf("identitytest: realm: %d clients arrays, want 1", n)
	}
	at := bytes.Index(realm, anchor) + len(anchor)
	var out []byte
	out = append(out, realm[:at]...)
	out = append(out, client...)
	out = append(out, ',')
	return append(out, realm[at:]...), nil
}

// caCertFile and caKeyFile are the test CA's files under <root>/ca.
const (
	caCertFile = "identitytest-ca.pem"
	caKeyFile  = "identitytest-ca.key"
)

// caConfig is the identity CA's code with its name, files and subject
// overridden; it keeps the identity CA's lifetime and both usages, so a test
// mints production leaf specs under it exactly as the api does.
func caConfig() tlsca.Config {
	c := tlsca.IdentityConfig()
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
		Usage: tlsca.UsageServer, CommonName: "identitytest front", IPAddresses: loopback, DNSNames: []string{"localhost"},
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
// With a ThemeDir, themes/ is a directory of its own: each entry of the
// dist's themes/ links into it, and themes/rasputin links to ThemeDir. The
// deny list is copied into data/password-blacklists/, Keycloak's default
// list directory, at 0600 in a 0700 directory, as rasputin-os stages it.
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
	theme := e.h.cfg.ThemeDir
	for _, ent := range ents {
		switch ent.Name() {
		case "bin", "data":
			continue
		case "themes":
			if theme != "" {
				continue
			}
		}
		if err := os.Symlink(filepath.Join(src, ent.Name()), filepath.Join(home, ent.Name())); err != nil {
			return "", fmt.Errorf("identitytest: keycloak home: %w", err)
		}
	}
	if theme != "" {
		if err := linkThemes(filepath.Join(src, "themes"), filepath.Join(home, "themes"), theme); err != nil {
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
	if err := stageDenylist(e.h.cfg.DenylistDir, home); err != nil {
		return "", fmt.Errorf("identitytest: keycloak home: the password deny list: %w", err)
	}
	return home, nil
}

// stageDenylist copies dir's flows.DenylistFile into home's
// data/password-blacklists/.
func stageDenylist(dir, home string) error {
	b, err := os.ReadFile(filepath.Join(dir, flows.DenylistFile))
	if err != nil {
		return err
	}
	if err := atrest.EnsureSecretDir(filepath.Join(home, "data", "password-blacklists")); err != nil {
		return err
	}
	return atrest.WriteSecretFile(denylistPath(home), b)
}

// denylistPath is the staged list's path in a Keycloak home.
func denylistPath(home string) string {
	return filepath.Join(home, "data", "password-blacklists", flows.DenylistFile)
}

// linkThemes makes dst a directory, links each entry of the dist's src into
// it (src may be absent: the dist's own themes are in its jars), and links
// dst/rasputin to theme.
func linkThemes(src, dst, theme string) error {
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	ents, err := os.ReadDir(src)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, ent := range ents {
		if ent.Name() == "rasputin" {
			continue
		}
		if err := os.Symlink(filepath.Join(src, ent.Name()), filepath.Join(dst, ent.Name())); err != nil {
			return err
		}
	}
	return os.Symlink(theme, filepath.Join(dst, "rasputin"))
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
// proxy presents the client leaf and keeps the browser's Host. The door's
// admin-account guard runs first: a request it refuses is answered 400 with
// the guard's sentence, counted, and never forwarded.
func (e *Env) serveFront(httpsPort int) error {
	target, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(httpsPort))
	if err != nil {
		return fmt.Errorf("identitytest: front target: %w", err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{TLSClientConfig: e.ClientTLS()},
		ErrorLog:  slog.NewLogLogger(e.log.Handler(), slog.LevelWarn),
	}
	e.front.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, err := adminguard.FromRequest(r)
		if err == nil {
			err = adminguard.Check(in)
		}
		if err != nil {
			e.refusals.Add(1)
			http.Error(w, adminguard.Sentence(err), http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	e.front.StartTLS()
	return nil
}

// Close stops everything the Env started, in the order browser, Headscale,
// front, Keycloak, PostgreSQL, then removes the root, and proves teardown: it
// returns the joined errors unless Keycloak was reaped (its process group is
// then killed), each container is gone, no live process names the root, and the
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
	for _, s := range e.doorSites {
		s.Close()
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
