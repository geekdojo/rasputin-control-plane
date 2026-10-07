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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

const (
	// KVMount is the kv-v2 mount self-init creates, and the name of the policy
	// granting create/read/update under it.
	KVMount = "harness-kv"
	// ClientRole is the cert auth role self-init creates, and the CommonName
	// of the client leaf ClientTLS presents. Log in with name=ClientRole.
	ClientRole = "harness-client"

	// healthRecheckInterval is how often waitHealthy re-asks the store's
	// sys/health. It decides nothing: readiness is the store's own answer
	// (200, initialized, unsealed), a store that exits fails at once, and the
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
// last ':' (v2.7.0), which is how gatereg reads the same const.
func pinnedVersion() string {
	return OpenBaoRelease[strings.LastIndex(OpenBaoRelease, ":")+1:]
}

// Store is one running secret store.
type Store struct {
	log       *slog.Logger
	root      string
	url       string
	clientTLS *tls.Config

	cmd     *exec.Cmd
	stderr  *lineLog
	exited  chan struct{} // closed once cmd.Wait has returned
	waitErr error         // cmd.Wait's result; read only after exited closes

	closeOnce sync.Once
	closeErr  error
}

// URL is the store's API address, https://127.0.0.1:<port>.
func (s *Store) URL() string { return s.url }

// ClientTLS is a TLS config that trusts only the store CA and presents the
// store-CA client leaf (CN ClientRole, EKU clientAuth). Each call returns a
// fresh copy.
func (s *Store) ClientTLS() *tls.Config { return s.clientTLS.Clone() }

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
	s := &Store{log: h.cfg.Logger, root: root}
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
	if s.clientTLS, err = clientTLS(ca.CertPEM, client); err != nil {
		return err
	}

	paths := serverPaths{
		StoreCA:    filepath.Join(s.root, "ca", tlsca.StoreCertFile),
		ServerCert: server.CertPath,
		ServerKey:  server.KeyPath,
		SealKey:    filepath.Join(s.root, "seal-key"),
		Storage:    filepath.Join(s.root, "data"),
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

	if err := s.launch(h.cfg.BinaryPath, "server", "-config", mainPath, "-config", initPath); err != nil {
		return err
	}
	if err := h.waitHealthy(ctx, s); err != nil {
		return err
	}
	s.log.Info("secret store started", "addr", strings.TrimPrefix(s.url, "https://"),
		"pid", s.cmd.Process.Pid, "version", version, "dir", s.root)
	return nil
}

// checkVersion runs `bao version` and refuses any binary but the pinned
// release, so the store under test is the one the const names. It returns
// the pinned tag (v2.7.0).
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

func clientTLS(caPEM []byte, leaf tlsca.LeafPaths) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("secretstoretest: store CA PEM holds no certificate")
	}
	cert, err := tls.LoadX509KeyPair(leaf.CertPath, leaf.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("secretstoretest: client leaf: %w", err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// launch starts the store process. Its stdout and stderr go to the logger a
// line at a time; the last stderr lines are kept for an early-exit error. One
// goroutine owns cmd.Wait and closes s.exited when it returns.
func (s *Store) launch(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	s.stderr = newLineLog(s.log, "stderr", stderrTail)
	cmd.Stdout = newLineLog(s.log, "stdout", 0)
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("secretstoretest: start %s: %w", bin, err)
	}
	s.cmd = cmd
	s.exited = make(chan struct{})
	go func() {
		s.waitErr = cmd.Wait()
		close(s.exited)
	}()
	return nil
}

// health is one sys/health answer.
type health struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

// waitHealthy returns once the store answers sys/health with 200,
// initialized and unsealed. READY=1 is no use here: the store sends it before
// unseal (geekdojo-brain#679 Q4). It fails at once if the store exits, and
// otherwise waits as long as ctx allows.
//
// No request carries a timeout of its own: each runs under a ctx that ends
// when the caller's ctx does or when the store exits, which are the two facts
// that can make an answer never come.
func (h *Harness) waitHealthy(ctx context.Context, s *Store) error {
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
		ok, status, err := s.checkHealth(reqCtx, client)
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

func (s *Store) checkHealth(ctx context.Context, client *http.Client) (ok bool, status string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/v1/sys/health", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var hb health
	if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
		return false, fmt.Sprintf("%d, unreadable body: %v", resp.StatusCode, err), nil
	}
	status = fmt.Sprintf("%d initialized=%t sealed=%t", resp.StatusCode, hb.Initialized, hb.Sealed)
	return resp.StatusCode == http.StatusOK && hb.Initialized && !hb.Sealed, status, nil
}

// exitError is the error for a store that exited before it was healthy. It
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
	if _, err := os.Stat(s.root); !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("secretstoretest: teardown left %s behind", s.root))
	}
	return errors.Join(errs...)
}

// lineLog is the io.Writer behind the store's stdout or stderr: each complete
// line goes to the logger at DEBUG, and the last keep lines are kept for an
// error. exec's copy goroutine writes; tail is read after the process exits.
type lineLog struct {
	log    *slog.Logger
	stream string
	keep   int

	mu    sync.Mutex
	part  []byte
	lines []string
}

func newLineLog(log *slog.Logger, stream string, keep int) *lineLog {
	return &lineLog{log: log, stream: stream, keep: keep}
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.part = append(l.part, p...)
	for {
		i := bytes.IndexByte(l.part, '\n')
		if i < 0 {
			return len(p), nil
		}
		l.emit(string(l.part[:i]))
		l.part = l.part[i+1:]
	}
}

func (l *lineLog) emit(line string) {
	line = strings.TrimRight(line, "\r")
	l.log.Debug("secret store output", "source", "openbao", "stream", l.stream, "line", line)
	if l.keep == 0 {
		return
	}
	l.lines = append(l.lines, line)
	if len(l.lines) > l.keep {
		l.lines = l.lines[len(l.lines)-l.keep:]
	}
}

// tail is the kept lines, plus any unterminated last line, joined with " | ".
func (l *lineLog) tail() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines := append([]string(nil), l.lines...)
	if len(l.part) > 0 {
		lines = append(lines, string(l.part))
	}
	if len(lines) == 0 {
		return "(none)"
	}
	return strings.Join(lines, " | ")
}
