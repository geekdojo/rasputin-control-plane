// Package apprelay is the agent's half of the app relay
// (geekdojo/geekdojo-brain#1081): one TLS Unix socket per app granted a
// runtime identity, in a directory the docker backend bind-mounts read-only
// into that app's containers and no others. A call that arrives on the
// socket is that app's: the agent stamps the app's id on it and carries it
// over the bus to the api, which authorizes it (proto/apprelay.go).
//
// Per-app state lives under <dir>/<appID>/:
//
//	key.pem   0600  the socket's ECDSA P-256 key, generated here, never sent
//	cert.pem  0600  the controlplane-CA leaf the api signed over that key
//	mnt/      0755  the only thing mounted into the containers
//	  ca.pem    0644  the controlplane CA, the app's one trust anchor
//	  relay.sock 0666 the socket
package apprelay

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The per-app file names.
const (
	keyFile  = "key.pem"
	certFile = "cert.pem"
	mntDir   = "mnt"
)

// socketMode lets any uid in the app's containers connect. The directory is
// mounted into that app alone; the TLS server certificate is what the app
// verifies.
const socketMode = 0o666

// Forwarder carries an app's call to the api and returns its answer. *Relay
// satisfies it.
type Forwarder interface {
	Forward(appID string, call proto.AppSecretCall, cid string) proto.AppSecretReply
}

// ManagerDeps is everything a Manager needs. Rand is the key's randomness
// (main passes crypto/rand's Reader); IDs gives each agent-side refusal its
// correlation id.
type ManagerDeps struct {
	Dir     string
	Rand    io.Reader
	Forward Forwarder
	IDs     func() string
	Log     *slog.Logger
}

// Manager owns every app's relay state and socket on this node.
type Manager struct {
	d         ManagerDeps
	mu        sync.Mutex
	listeners map[string]*listener
}

// NewManager refuses a ManagerDeps with an empty or nil field. It does no I/O.
func NewManager(d ManagerDeps) (*Manager, error) {
	switch {
	case d.Dir == "":
		return nil, errors.New("apprelay: NewManager: ManagerDeps.Dir is empty")
	case d.Rand == nil:
		return nil, errors.New("apprelay: NewManager: ManagerDeps.Rand is nil")
	case d.Forward == nil:
		return nil, errors.New("apprelay: NewManager: ManagerDeps.Forward is nil")
	case d.IDs == nil:
		return nil, errors.New("apprelay: NewManager: ManagerDeps.IDs is nil")
	case d.Log == nil:
		return nil, errors.New("apprelay: NewManager: ManagerDeps.Log is nil")
	}
	return &Manager{d: d, listeners: map[string]*listener{}}, nil
}

// errBadAppID refuses an app id before any filesystem call: the id arrives on
// the bus and names a directory.
var errBadAppID = errors.New("the app id is not a canonical ULID")

// checkAppID refuses anything but a canonical upper-case ULID.
func checkAppID(appID string) error {
	if !proto.ValidAppID(appID) || strings.ToUpper(appID) != appID {
		return errBadAppID
	}
	return nil
}

func (m *Manager) appDir(appID string) string { return filepath.Join(m.d.Dir, appID) }
func (m *Manager) mnt(appID string) string    { return filepath.Join(m.appDir(appID), mntDir) }
func (m *Manager) keyPath(appID string) string {
	return filepath.Join(m.appDir(appID), keyFile)
}
func (m *Manager) certPath(appID string) string {
	return filepath.Join(m.appDir(appID), certFile)
}

// Prepare makes the app's key if it has none and returns its public half,
// PKIX DER. A key already on disk is reused, unchanged.
func (m *Manager) Prepare(appID string) ([]byte, error) {
	if err := checkAppID(appID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := atrest.EnsureSecretDir(m.d.Dir); err != nil {
		return nil, fmt.Errorf("relay state directory: %w", err)
	}
	if err := atrest.EnsureSecretDir(m.appDir(appID)); err != nil {
		return nil, fmt.Errorf("relay directory of %s: %w", appID, err)
	}
	key, err := m.loadKey(appID)
	if errors.Is(err, os.ErrNotExist) {
		key, err = m.newKey(appID)
	}
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("encode the relay key of %s: %w", appID, err)
	}
	return der, nil
}

// newKey generates the app's key and writes it, owner-only.
func (m *Manager) newKey(appID string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), m.d.Rand)
	if err != nil {
		return nil, fmt.Errorf("generate the relay key of %s: %w", appID, err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode the relay key of %s: %w", appID, err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	clear(der)
	defer clear(b)
	if err := atrest.WriteSecretFile(m.keyPath(appID), b); err != nil {
		return nil, fmt.Errorf("write the relay key of %s: %w", appID, err)
	}
	return key, nil
}

// loadKey reads the app's key. A missing key is os.ErrNotExist.
func (m *Manager) loadKey(appID string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(m.keyPath(appID))
	if err != nil {
		return nil, err
	}
	defer clear(b)
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("the relay key of %s is not PEM", appID)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the relay key of %s does not parse: %w", appID, err)
	}
	return key, nil
}

// Install writes the app's certificate and the CA, and opens its socket if it
// is not open. A certificate over any key but the app's own is refused, and
// nothing is written. An open socket serves the new certificate from its next
// handshake: it reads the files at each one.
func (m *Manager) Install(appID string, certPEM, caPEM []byte) error {
	if err := checkAppID(appID); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.loadKey(appID)
	if err != nil {
		return fmt.Errorf("the app has no relay key on this node; prepare it first: %w", err)
	}
	if err := checkCertKey(certPEM, key.Public()); err != nil {
		return err
	}
	if block, _ := pem.Decode(caPEM); block == nil || block.Type != "CERTIFICATE" {
		return errors.New("the CA is not a PEM certificate")
	}
	if err := atrest.WriteSecretFile(m.certPath(appID), certPEM); err != nil {
		return fmt.Errorf("write the relay certificate of %s: %w", appID, err)
	}
	if err := atrest.EnsurePublicDir(m.mnt(appID)); err != nil {
		return fmt.Errorf("relay mount directory of %s: %w", appID, err)
	}
	if err := atrest.WritePublicFile(filepath.Join(m.mnt(appID), proto.AppRelayCAName), caPEM); err != nil {
		return fmt.Errorf("write the relay CA of %s: %w", appID, err)
	}
	if _, open := m.listeners[appID]; open {
		return nil
	}
	return m.open(appID)
}

// checkCertKey refuses a certificate that does not parse or whose public key
// is not pub.
func checkCertKey(certPEM []byte, pub crypto.PublicKey) error {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("the relay certificate is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("the relay certificate does not parse: %w", err)
	}
	want, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	got, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil || !bytes.Equal(got, want) {
		return errors.New("the relay certificate is not over this app's key")
	}
	return nil
}

// open starts appID's socket. m.mu is held. The key and certificate must
// load as a pair first, so a socket never opens that no handshake could
// complete on.
func (m *Manager) open(appID string) error {
	if _, err := tls.LoadX509KeyPair(m.certPath(appID), m.keyPath(appID)); err != nil {
		return fmt.Errorf("the relay key and certificate of %s do not load: %w", appID, err)
	}
	l, err := listen(appID, filepath.Join(m.mnt(appID), proto.AppRelaySocketName), m.certPath(appID), m.keyPath(appID), m.d.Forward, m.d.IDs, m.d.Log)
	if err != nil {
		return err
	}
	m.listeners[appID] = l
	m.d.Log.Info("app relay socket open", "component", "apprelay", "event", "apprelay.open", "app_id", appID)
	return nil
}

// Remove closes the app's socket and removes its relay state. An app with
// none is success.
func (m *Manager) Remove(appID string) error {
	if err := checkAppID(appID); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, open := m.listeners[appID]; open {
		l.close()
		delete(m.listeners, appID)
		m.d.Log.Info("app relay socket closed", "component", "apprelay", "event", "apprelay.close", "app_id", appID)
	}
	if err := os.RemoveAll(m.appDir(appID)); err != nil {
		return fmt.Errorf("remove the relay state of %s: %w", appID, err)
	}
	return nil
}

// MountDir reports whether appID's socket is open, and the directory the
// docker backend mounts into its containers.
func (m *Manager) MountDir(appID string) (string, bool) {
	if checkAppID(appID) != nil {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, open := m.listeners[appID]; !open {
		return "", false
	}
	return m.mnt(appID), true
}

// Restore reopens, at agent start, the socket of every app whose directory
// holds both a key and a certificate. A directory without a certificate was
// prepared and never installed, and is skipped. One that cannot be reopened
// is logged at ERROR and the rest still open. A missing state directory is a
// node that never had a relay: nothing to do.
func (m *Manager) Restore() {
	entries, err := os.ReadDir(m.d.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		m.d.Log.Error("app relay state could not be read", "component", "apprelay", "event", "apprelay.restore_failed", "dir", m.d.Dir, "err", err.Error())
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range entries {
		appID := e.Name()
		if !e.IsDir() || checkAppID(appID) != nil {
			continue
		}
		if _, err := os.Stat(m.certPath(appID)); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if _, open := m.listeners[appID]; open {
			continue
		}
		if err := m.open(appID); err != nil {
			m.d.Log.Error("app relay socket could not be reopened", "component", "apprelay", "event", "apprelay.restore_failed", "app_id", appID, "err", err.Error())
		}
	}
}

// Close closes every socket. The state stays, for Restore.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, l := range m.listeners {
		l.close()
		delete(m.listeners, id)
	}
}
