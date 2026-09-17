package proxy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultAdminSocket is where the node-local Caddy's admin API listens: a unix
// socket, never TCP.
//
// Caddy runs as root, and its admin API can replace the whole configuration of
// that root process — a file_server rooted at /, a log writer aimed at any path.
// It has no authentication of its own. Until geekdojo-brain#450 it listened on
// TCP localhost:2019, and loopback is not a privilege boundary: every local user
// and every host-network container (the catalog's "elevated" tier, documented as
// NOT root-equivalent) could drive it. A unix socket is reached through the
// filesystem instead, so ordinary file permissions decide who may use it:
//
//   - the directory is 0700 and owned by the agent (root on the appliance), so
//     no other uid can even reach the socket inode;
//   - the socket itself is 0600 (Caddy chmods it right after bind), so it stays
//     closed even if the directory is ever loosened;
//   - /run is outside every container unless a tile bind-mounts it, and any
//     /run mount is already classed host-trusting (tileschema).
//
// /run is tmpfs, so every boot starts with no stale directory or socket. The
// directory is its own top-level entry under /run (like /run/rasputin-seed)
// rather than a subdirectory of a shared one, so making it private never means
// creating or re-moding a parent that other components use.
const DefaultAdminSocket = "/run/rasputin-caddy/admin.sock"

// adminSocketMode and adminDirMode are the permissions described above.
const (
	adminSocketMode fs.FileMode = 0o600
	adminDirMode    fs.FileMode = 0o700
)

// LegacyAdminAddr is the TCP admin address agents before geekdojo-brain#450 gave
// Caddy. The agent only ever talks to it to retire a Caddy still listening
// there (see stopLegacyCaddy); nothing is configured on it.
const LegacyAdminAddr = "localhost:2019"

// adminHost is the Host the admin client sends. Caddy deliberately performs no
// Host/Origin check on a unix-socket admin listener (those checks defend a TCP
// listener against browsers and DNS rebinding, neither of which can reach a
// unix socket), so the value is only a well-formed placeholder.
const adminHost = "caddy"

// AdminListen renders socketPath as a Caddy admin listen address. The
// "unix/<path>|<mode>" form makes Caddy chmod the socket to mode after bind
// (verified in Caddy 2.11.4, the version rasputin-os vendors, and exercised by
// the real-Caddy functional test).
func AdminListen(socketPath string) (string, error) {
	if err := validateAdminSocket(socketPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("unix/%s|%04o", socketPath, uint32(adminSocketMode)), nil
}

func validateAdminSocket(socketPath string) error {
	switch {
	case socketPath == "":
		return errors.New("proxy: caddy admin socket path is empty")
	case !filepath.IsAbs(socketPath):
		return fmt.Errorf("proxy: caddy admin socket %q is not absolute", socketPath)
	case filepath.Clean(socketPath) != socketPath:
		return fmt.Errorf("proxy: caddy admin socket %q is not a clean path", socketPath)
	case strings.ContainsAny(socketPath, "|{}"):
		// '|' separates the mode in Caddy's address syntax; braces are Caddy
		// placeholders. Either would change what Caddy binds.
		return fmt.Errorf("proxy: caddy admin socket %q contains a reserved character", socketPath)
	}
	return nil
}

// PrepareAdminDir makes the socket's directory exist as a real directory, owned
// by this process's effective uid, with mode 0700. Its parent must already
// exist (/run on the appliance); nothing above the directory is created or
// changed. It is run before every Caddy
// start, so a directory that was loosened, replaced or pre-created by someone
// else is caught rather than trusted. It refuses — never repairs — a directory
// it does not own or a symlink: in both cases another principal already had a
// hand in the path, and the right answer is to not start Caddy on it.
func PrepareAdminDir(socketPath string) error {
	if err := validateAdminSocket(socketPath); err != nil {
		return err
	}
	dir := filepath.Dir(socketPath)
	if err := os.Mkdir(dir, adminDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("proxy: create %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("proxy: stat %s: %w", dir, err)
	}
	if !fi.IsDir() {
		// Lstat does not follow links, so a symlink lands here too.
		return fmt.Errorf("proxy: caddy admin dir %s is not a directory (mode %s)", dir, fi.Mode())
	}
	if err := ownedByEUID(fi); err != nil {
		return fmt.Errorf("proxy: caddy admin dir %s: %w", dir, err)
	}
	if fi.Mode().Perm() != adminDirMode {
		if err := os.Chmod(dir, adminDirMode); err != nil {
			return fmt.Errorf("proxy: chmod %s: %w", dir, err)
		}
	}
	return nil
}

// CheckAdminSocket reports whether the socket Caddy created has the expected
// shape: a socket, owned by this process's uid, mode 0600. It is a tripwire for
// a future Caddy that stops honouring the mode suffix — the 0700 directory still
// holds in that case, but the second layer is gone and that must be loud.
func CheckAdminSocket(socketPath string) error {
	fi, err := os.Lstat(socketPath)
	if err != nil {
		return err
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("proxy: caddy admin socket %s is not a socket (mode %s)", socketPath, fi.Mode())
	}
	if err := ownedByEUID(fi); err != nil {
		return fmt.Errorf("proxy: caddy admin socket %s: %w", socketPath, err)
	}
	if perm := fi.Mode().Perm(); perm != adminSocketMode {
		return fmt.Errorf("proxy: caddy admin socket %s has mode %04o, want %04o", socketPath, uint32(perm), uint32(adminSocketMode))
	}
	return nil
}

// newAdminClient returns an HTTP client that reaches Caddy's admin API over the
// unix socket, whatever host the request URL names.
func newAdminClient(socketPath string) *http.Client {
	var d net.Dialer
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return d.DialContext(ctx, "unix", socketPath)
			},
			// No proxy: the environment's HTTP(S)_PROXY must never capture a
			// request meant for a local socket.
			Proxy: nil,
		},
	}
}

func adminURL(path string) string {
	return "http://" + adminHost + path
}
