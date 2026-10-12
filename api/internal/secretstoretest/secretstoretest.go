// Package secretstoretest runs the real, pinned secret store (OpenBao, see
// pin.go) for a test: S8's transport, S6's storage, a static test seal,
// temporary storage and self-init, with a store-CA client leaf that logs in
// through cert auth. Tests import it; nothing in a shipped binary does.
//
// The store is built from the production store CA code (tlsca.StoreConfig)
// and the harness's rendered config (config.go). Start waits on the store's
// own health answer, never on a duration it picks, and Close proves teardown:
// no process and no temporary directory are left behind
// (geekdojo/geekdojo-brain#753, docs/testing-secret-store.md).
package secretstoretest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	// KVMount is the kv-v2 mount self-init creates, and the name of the policy
	// granting create/read/update under it.
	KVMount = "harness-kv"
	// ClientRole is the cert auth role self-init creates, and the CommonName
	// of the client leaf ClientTLS presents. Log in with name=ClientRole.
	ClientRole = "harness-client"

	// healthRecheckInterval is how often waitHealthy re-asks the store's
	// sys/health. It decides nothing: the wait ends on the store's own answer
	// (200 initialized and unsealed after Start and Restart; 503 initialized
	// and sealed after RestartSealed), a store that exits fails at once, and the
	// wait as a whole is bounded only by the caller's ctx. The interval only
	// sets how soon after the fact becomes true the harness notices it; a
	// PebbleDB store is healthy on its first answer (geekdojo-brain#679 Q4).
	// Timer-audit row K22.
	healthRecheckInterval = 20 * time.Millisecond

	// stderrTail is how many of the store's last stderr lines an early-exit
	// error carries. The cause of an early exit (a lost port race, a config
	// the store refused) is only ever in its stderr.
	stderrTail = 5

	sealKeyBytes = 32
)

// Config is everything the harness needs, passed in by the test.
type Config struct {
	// BinaryPath is the bao binary. Start refuses one that is not the release
	// OpenBaoRelease pins.
	BinaryPath string
	// TempParent is where the harness makes its temporary root (a test passes
	// t.TempDir()). Close removes the root and proves it is gone.
	TempParent string
	// Logger receives the harness's records and, at DEBUG, each line the
	// store writes.
	Logger *slog.Logger
	// Now dates the store CA and its leaves.
	Now func() time.Time
	// Rand feeds the CA, the leaves and the seal key.
	Rand io.Reader
	// Audit turns on a declarative file audit device writing
	// <root>/audit/audit.log (Store.AuditPath). Off by default.
	Audit bool
}

// Harness starts stores. It holds only its Config.
type Harness struct {
	cfg Config
}

// New checks cfg and returns a Harness. It does no I/O.
func New(cfg Config) (*Harness, error) {
	switch {
	case cfg.BinaryPath == "":
		return nil, errors.New("secretstoretest: Config.BinaryPath is empty")
	case cfg.TempParent == "":
		return nil, errors.New("secretstoretest: Config.TempParent is empty")
	case cfg.Logger == nil:
		return nil, errors.New("secretstoretest: Config.Logger is nil")
	case cfg.Now == nil:
		return nil, errors.New("secretstoretest: Config.Now is nil")
	case cfg.Rand == nil:
		return nil, errors.New("secretstoretest: Config.Rand is nil")
	}
	return &Harness{cfg: cfg}, nil
}

// pinnedVersion is the release tag OpenBaoRelease pins: the text after its
// last ':' (v2.7.1), which is how gatereg reads the same const.
func pinnedVersion() string {
	return OpenBaoRelease[strings.LastIndex(OpenBaoRelease, ":")+1:]
}

// Store is one running secret store.
type Store struct {
	h          *Harness
	log        *slog.Logger
	root       string
	url        string
	clientTLS  *tls.Config
	clientLeaf tlsca.LeafPaths
	sealKey    string   // the seal key's path
	auditPath  string   // the audit file, or "" when Config.Audit is off
	args       []string // the store's command line after the binary

	cmd     *exec.Cmd
	stderr  *lineLog
	exited  chan struct{} // closed once cmd.Wait has returned
	waitErr error         // cmd.Wait's result; read only after exited closes

	closeOnce sync.Once
	closeErr  error
}

// URL is the store's API address, https://127.0.0.1:<port>.
func (s *Store) URL() string { return s.url }

// ClientTLS is the production client's TLS config (secretstore.NewTLSConfig):
// it trusts only the store CA, speaks TLS 1.3, and presents the store-CA
// client leaf (CN ClientRole, EKU clientAuth), read from disk at each
// handshake. Each call returns a fresh copy.
func (s *Store) ClientTLS() *tls.Config { return s.clientTLS.Clone() }

// AuditPath is the file the store's audit device writes, or "" when
// Config.Audit is off.
func (s *Store) AuditPath() string { return s.auditPath }

// Reload sends the store SIGHUP, which makes it reopen its audit file. It
// returns once the signal is delivered, as systemctl kill does.
func (s *Store) Reload(context.Context) error {
	select {
	case <-s.exited:
		return errors.New("secretstoretest: Reload: the store is not running")
	default:
	}
	if err := s.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("secretstoretest: SIGHUP pid %d: %w", s.cmd.Process.Pid, err)
	}
	return nil
}

// ClientLeaf is where the client leaf ClientTLS presents lives on disk.
func (s *Store) ClientLeaf() tlsca.LeafPaths { return s.clientLeaf }

// Token logs in through cert auth with the client leaf and returns the token.
// It is test support: production login is geekdojo/geekdojo-brain#759's.
func (s *Store) Token(ctx context.Context) (secret.Value, error) {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: s.ClientTLS()}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/auth/cert/login",
		bytes.NewReader([]byte(`{"name":"`+ClientRole+`"}`)))
	if err != nil {
		return secret.Value{}, fmt.Errorf("secretstoretest: login: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return secret.Value{}, fmt.Errorf("secretstoretest: login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	defer clear(body)
	if err != nil {
		return secret.Value{}, fmt.Errorf("secretstoretest: login: %w", err)
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &login) != nil || login.Auth.ClientToken == "" {
		return secret.Value{}, fmt.Errorf("secretstoretest: login answered %d with no token", resp.StatusCode)
	}
	return secret.New([]byte(login.Auth.ClientToken)), nil
}

// RestartSealed stops the store, overwrites its seal key with fresh random
// bytes, and starts it again on the same data, so it comes up initialised and
// unable to unseal. It returns once sys/health answers 503 with
// initialized=true and sealed=true, which is the fact a sealed store reports;
// if ctx ends first, the error names the last health answer.
func (s *Store) RestartSealed(ctx context.Context) error {
	if err := s.stop(ctx, "RestartSealed"); err != nil {
		return err
	}
	if err := s.h.writeSealKey(s.sealKey); err != nil {
		return err
	}
	if err := s.launch(s.h.cfg.BinaryPath, s.args...); err != nil {
		return err
	}
	if err := s.h.waitHealthy(ctx, s, sealedAndInitialised); err != nil {
		return err
	}
	s.log.Info("secret store restarted sealed", "pid", s.cmd.Process.Pid, "dir", s.root)
	return nil
}

// Stop sends the store SIGTERM and returns once the process has exited. Its
// root, data and seal key stay, so Restart brings the same store back. It is
// how a test takes the store away from a running client
// (geekdojo/geekdojo-brain#760); Close still tears down a stopped store.
func (s *Store) Stop(ctx context.Context) error {
	if err := s.stop(ctx, "Stop"); err != nil {
		return err
	}
	s.log.Info("secret store stopped; data kept", "pid", s.cmd.Process.Pid, "dir", s.root)
	return nil
}

// Restart starts a stopped store again with the same command line and seal
// key, so it unseals itself on the same data, and returns once sys/health
// answers 200 initialized and unsealed. If ctx ends first, the error names the
// last health answer. It refuses a store that is still running.
func (s *Store) Restart(ctx context.Context) error {
	select {
	case <-s.exited:
	default:
		return errors.New("secretstoretest: Restart: the store is still running; Stop it first")
	}
	if err := s.launch(s.h.cfg.BinaryPath, s.args...); err != nil {
		return err
	}
	if err := s.h.waitHealthy(ctx, s, healthyAndUnsealed); err != nil {
		return err
	}
	s.log.Info("secret store restarted", "pid", s.cmd.Process.Pid, "dir", s.root)
	return nil
}

// stop sends SIGTERM and waits for the process to exit, or for ctx to end.
// op names the caller in its errors.
func (s *Store) stop(ctx context.Context, op string) error {
	select {
	case <-s.exited:
		return fmt.Errorf("secretstoretest: %s: the store is not running", op)
	default:
	}
	pid := s.cmd.Process.Pid
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("secretstoretest: SIGTERM pid %d: %w", pid, err)
	}
	select {
	case <-s.exited:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("secretstoretest: pid %d did not stop for %s: %w", pid, op, ctx.Err())
	}
}

// Start brings up a store and returns once it answers healthy. On any failure
// it tears down whatever it made, so nothing is left behind, and returns the
// error joined with any teardown error.
//
// ctx bounds the wait for health. A store that never becomes healthy and
// never exits (a wrong seal key, for one) is the case only ctx can end.
func (h *Harness) Start(ctx context.Context) (*Store, error) {
	version, err := h.checkVersion(ctx)
	if err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(h.cfg.TempParent, "secretstore-")
	if err != nil {
		return nil, fmt.Errorf("secretstoretest: temp root: %w", err)
	}
	s := &Store{h: h, log: h.cfg.Logger, root: root}
	if err := h.start(ctx, s, version); err != nil {
		// Teardown waits for the store to honour SIGTERM. The caller's ctx may
		// be the very thing that ended (a cancelled or expired wait), and a
		// cancelled ctx would turn that wait into an immediate SIGKILL, so the
		// teardown runs under a ctx that carries the values but not the end.
		return nil, errors.Join(err, s.Close(context.WithoutCancel(ctx)))
	}
	return s, nil
}

func (h *Harness) start(ctx context.Context, s *Store, version string) error {
	if err := atrest.EnsureSecretDir(s.root); err != nil {
		return fmt.Errorf("secretstoretest: temp root: %w", err)
	}
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), filepath.Join(s.root, "ca"), "secretstoretest",
		tlsca.Deps{Now: h.cfg.Now, Rand: h.cfg.Rand, Log: h.cfg.Logger})
	if err != nil {
		return fmt.Errorf("secretstoretest: store CA: %w", err)
	}
	// One directory per leaf: MintLeafToDisk always writes leaf.pem/leaf.key
	// in the directory it is given, and re-mints over a leaf of the other
	// usage, so a shared directory would leave only the client leaf.
	loopback := net.IPv4(127, 0, 0, 1)
	server, err := ca.MintLeafToDisk(filepath.Join(s.root, "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "secretstoretest server", IPAddresses: []net.IP{loopback},
	})
	if err != nil {
		return fmt.Errorf("secretstoretest: server leaf: %w", err)
	}
	client, err := ca.MintLeafToDisk(filepath.Join(s.root, "client"), tlsca.LeafSpec{
		Usage: tlsca.UsageClient, CommonName: ClientRole,
	})
	if err != nil {
		return fmt.Errorf("secretstoretest: client leaf: %w", err)
	}
	s.clientLeaf = client
	if s.clientTLS, err = secretstore.NewTLSConfig(ca.CertPEM, client.CertPath, client.KeyPath); err != nil {
		return fmt.Errorf("secretstoretest: client TLS: %w", err)
	}

	paths := serverPaths{
		StoreCA:    filepath.Join(s.root, "ca", tlsca.StoreCertFile),
		ServerCert: server.CertPath,
		ServerKey:  server.KeyPath,
		SealKey:    filepath.Join(s.root, "seal-key"),
		Storage:    filepath.Join(s.root, "data"),
	}
	s.sealKey = paths.SealKey
	if h.cfg.Audit {
		// The store creates the file but would make a missing directory with
		// the file's 0600 mode, which it then cannot enter.
		auditDir := filepath.Join(s.root, "audit")
		if err := atrest.EnsureSecretDir(auditDir); err != nil {
			return fmt.Errorf("secretstoretest: audit dir: %w", err)
		}
		paths.AuditLog = filepath.Join(auditDir, "audit.log")
		s.auditPath = paths.AuditLog
	}
	if err := h.writeSealKey(paths.SealKey); err != nil {
		return err
	}
	if err := atrest.EnsureSecretDir(paths.Storage); err != nil {
		return fmt.Errorf("secretstoretest: storage dir: %w", err)
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	s.url = "https://127.0.0.1:" + strconv.Itoa(port)

	// Both configs are written owner-only: the store runs as this user, and
	// nothing else needs to read them.
	mainPath := filepath.Join(s.root, "main.hcl")
	if err := atrest.WriteSecretFile(mainPath, []byte(renderServerHCL(paths, port))); err != nil {
		return fmt.Errorf("secretstoretest: main config: %w", err)
	}
	initJSON, err := renderInitJSON(ca.CertPEM)
	if err != nil {
		return err
	}
	initPath := filepath.Join(s.root, "init.json")
	if err := atrest.WriteSecretFile(initPath, initJSON); err != nil {
		return fmt.Errorf("secretstoretest: init config: %w", err)
	}

	s.args = []string{"server", "-config", mainPath, "-config", initPath}
	if err := s.launch(h.cfg.BinaryPath, s.args...); err != nil {
		return err
	}
	if err := h.waitHealthy(ctx, s, healthyAndUnsealed); err != nil {
		return err
	}
	s.log.Info("secret store started", "addr", strings.TrimPrefix(s.url, "https://"),
		"pid", s.cmd.Process.Pid, "version", version, "dir", s.root)
	return nil
}

// checkVersion runs `bao version` and refuses any binary but the pinned
// release, so the store under test is the one the const names. It returns
// the pinned tag (v2.7.1).
func (h *Harness) checkVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, h.cfg.BinaryPath, "version").Output()
	if err != nil {
		return "", fmt.Errorf("secretstoretest: %s version: %w", h.cfg.BinaryPath, err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	line = strings.TrimSpace(line)
	want := pinnedVersion()
	if !strings.HasPrefix(line, "OpenBao "+want+" ") {
		return "", fmt.Errorf("secretstoretest: %s is not the pinned release: want OpenBao %s (%s), got %q",
			h.cfg.BinaryPath, want, OpenBaoRelease, line)
	}
	return want, nil
}

// writeSealKey writes a fresh 32-byte static seal key at 0600 and zeroes the
// buffer. The key exists for this store alone and is never logged.
func (h *Harness) writeSealKey(path string) error {
	key := make([]byte, sealKeyBytes)
	defer clear(key)
	if _, err := io.ReadFull(h.cfg.Rand, key); err != nil {
		return fmt.Errorf("secretstoretest: seal key: %w", err)
	}
	if err := atrest.WriteSecretFile(path, key); err != nil {
		return fmt.Errorf("secretstoretest: seal key: %w", err)
	}
	return nil
}

// freePort asks the kernel for a free loopback port and releases it for the
// store to bind. Another process can take it in between; the store then
// exits with "address already in use", which Start reports. It is never
// retried.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("secretstoretest: free port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return 0, fmt.Errorf("secretstoretest: free port: %w", err)
	}
	return port, nil
}

// launch starts the store process. Its stdout and stderr are read a line at
// a time into the logger; the last stderr lines are kept for an early-exit
// error. One goroutine owns cmd.Wait: it waits for both readers to reach EOF
// (exec requires every read from the pipes to finish before Wait), then
// reaps the process and closes s.exited.
func (s *Store) launch(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("secretstoretest: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("secretstoretest: stderr pipe: %w", err)
	}
	out := newLineLog(s.log, "stdout", 0)
	s.stderr = newLineLog(s.log, "stderr", stderrTail)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("secretstoretest: start %s: %w", bin, err)
	}
	s.cmd = cmd
	exited := make(chan struct{})
	s.exited = exited
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); out.consume(stdout) }()
	go func() { defer readers.Done(); s.stderr.consume(stderr) }()
	go func() {
		readers.Wait()
		s.waitErr = cmd.Wait()
		close(exited)
	}()
	return nil
}

// health is one sys/health answer.
type health struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

// healthWant is the sys/health answer a wait ends on.
type healthWant func(code int, hb health) bool

// healthyAndUnsealed is a started store: 200, initialized and unsealed.
func healthyAndUnsealed(code int, hb health) bool {
	return code == http.StatusOK && hb.Initialized && !hb.Sealed
}

// sealedAndInitialised is a store restarted with the wrong seal key: 503,
// initialized and sealed.
func sealedAndInitialised(code int, hb health) bool {
	return code == http.StatusServiceUnavailable && hb.Initialized && hb.Sealed
}

// waitHealthy returns once the store's sys/health answer satisfies want.
// READY=1 is no use here: the store sends it before unseal
// (geekdojo-brain#679 Q4). It fails at once if the store exits, and otherwise
// waits as long as ctx allows.
//
// No request carries a timeout of its own: each runs under a ctx that ends
// when the caller's ctx does or when the store exits, which are the two facts
// that can make an answer never come.
func (h *Harness) waitHealthy(ctx context.Context, s *Store, want healthWant) error {
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.exited:
			cancel()
		case <-reqCtx.Done():
		}
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: s.ClientTLS()}}
	defer client.CloseIdleConnections()

	last := "no answer yet"
	ticker := time.NewTicker(healthRecheckInterval)
	defer ticker.Stop()
	for {
		ok, status, err := s.checkHealth(reqCtx, client, want)
		if ok {
			return nil
		}
		// A request cut short because the store exited or ctx ended says
		// nothing about the store; keep the answer before it.
		if reqCtx.Err() == nil {
			now := status
			if err != nil {
				now = err.Error()
			}
			if now != last {
				last = now
				s.log.Debug("secret store not healthy yet", "health", last)
			}
		}
		select {
		case <-s.exited:
			return s.exitError()
		default:
		}
		select {
		case <-s.exited:
			return s.exitError()
		case <-ctx.Done():
			return fmt.Errorf("secretstoretest: store at %s not healthy when ctx ended (last health: %s): %w",
				s.url, last, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *Store) checkHealth(ctx context.Context, client *http.Client, want healthWant) (ok bool, status string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/sys/health", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	// The close error is dropped on purpose: the body has been read (or its
	// read error is reported below), so there is nothing left to lose, and a
	// failed close only makes the transport discard the connection.
	defer func() { _ = resp.Body.Close() }()
	var hb health
	if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
		return false, fmt.Sprintf("%d, unreadable body: %v", resp.StatusCode, err), nil
	}
	status = fmt.Sprintf("%d initialized=%t sealed=%t", resp.StatusCode, hb.Initialized, hb.Sealed)
	return want(resp.StatusCode, hb), status, nil
}

// exitError is the error for a store that exited before it gave the awaited
// health answer. It
// carries the store's last stderr lines, where the cause is.
func (s *Store) exitError() error {
	return fmt.Errorf("secretstoretest: store exited before it was healthy: %v; last stderr: %s",
		s.waitErr, s.stderr.tail())
}

// Close stops the store and removes its temporary root, then proves both: it
// returns an error unless the process has been reaped and the root is gone.
//
// It sends SIGTERM and waits for the store to exit. Only if ctx ends first is
// the store sent SIGKILL, with a WARN, so a caller that wants a clean stop
// passes a ctx that does not end (context.Background()). A test's t.Context()
// is cancelled before its Cleanup functions run, so it is the wrong ctx for a
// Close in Cleanup.
//
// Close is idempotent: a second call returns the first call's result and
// does nothing.
func (s *Store) Close(ctx context.Context) error {
	s.closeOnce.Do(func() { s.closeErr = s.teardown(ctx) })
	return s.closeErr
}

func (s *Store) teardown(ctx context.Context) error {
	var errs []error
	if s.cmd != nil {
		pid := s.cmd.Process.Pid
		select {
		case <-s.exited:
		default:
			if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
				errs = append(errs, fmt.Errorf("secretstoretest: SIGTERM pid %d: %w", pid, err))
			}
			select {
			case <-s.exited:
			case <-ctx.Done():
				if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					errs = append(errs, fmt.Errorf("secretstoretest: SIGKILL pid %d: %w", pid, err))
				}
				s.log.Warn("secret store ignored SIGTERM; killed", "pid", pid)
				<-s.exited
			}
		}
		if s.cmd.ProcessState == nil {
			errs = append(errs, fmt.Errorf("secretstoretest: teardown left pid %d unreaped", pid))
		} else {
			s.log.Info("secret store stopped", "pid", pid, "exit", s.cmd.ProcessState.String())
		}
	}
	if err := os.RemoveAll(s.root); err != nil {
		errs = append(errs, fmt.Errorf("secretstoretest: remove %s: %w", s.root, err))
	}
	if _, err := os.Stat(s.root); err == nil {
		errs = append(errs, fmt.Errorf("secretstoretest: teardown left %s behind", s.root))
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("secretstoretest: cannot show teardown removed %s: %w", s.root, err))
	}
	return errors.Join(errs...)
}

// lineLog reads the store's stdout or stderr: each line goes to the logger at
// DEBUG, and the last keep lines are kept for an error. It is deliberately not
// an io.Writer: one reader goroutine owns each stream, and tail is read after
// the process exits.
type lineLog struct {
	log    *slog.Logger
	stream string
	keep   int

	mu    sync.Mutex
	lines []string
}

func newLineLog(log *slog.Logger, stream string, keep int) *lineLog {
	return &lineLog{log: log, stream: stream, keep: keep}
}

// consume reads r to EOF, a line at a time, however long a line is. A last
// line with no newline is still a line.
func (l *lineLog) consume(r io.Reader) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			l.emit(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				// The rest of this stream is lost: the DEBUG lines stop and
				// the tail an exit error carries is cut short. Say so.
				l.log.Warn("secret store output read failed", "source", "openbao", "stream", l.stream, "err", err)
			}
			return
		}
	}
}

func (l *lineLog) emit(line string) {
	l.log.Debug("secret store output", "source", "openbao", "stream", l.stream, "line", line)
	if l.keep == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
	if len(l.lines) > l.keep {
		l.lines = l.lines[len(l.lines)-l.keep:]
	}
}

// tail is the kept lines joined with " | ".
func (l *lineLog) tail() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) == 0 {
		return "(none)"
	}
	return strings.Join(l.lines, " | ")
}
