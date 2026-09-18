package obs

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Grafana's listener, and why it is a unix socket.
//
// Grafana runs in auth-proxy mode: it trusts X-Webauth-User as an identity
// assertion, because the api validates the operator's passkey session and
// then sets that header (api/internal/api/obs_proxy.go). Grafana's own
// trusted-source list for that header is an IP allowlist, and the api
// reaches Grafana over loopback — the same loopback every other local
// process sits on — so the allowlist can express nothing useful. The
// header was therefore honoured from ANY local caller, which made Grafana
// a passwordless bypass of the api's passkey login, up to Grafana server
// admin. geekdojo-brain#453.
//
// So the port goes away. Grafana serves on a unix socket in a 0700
// directory that exactly one uid can enter, and the api dials that socket.
// Reaching Grafana now requires being that uid on the controlplane's own
// filesystem — a host-network container at the `elevated` tier shares the
// host's network namespace but not its filesystem, so it is out entirely.
//
// Verified against grafana/grafana:11.5.1 (2026-09-17):
//   - with `[server] protocol = socket` the container has NO tcp listener
//     in /proc/net/tcp at all, not even during startup;
//   - the socket is created 0600 and the directory stays 0700;
//   - a caller that is not the owning uid gets ECONNREFUSED before any
//     HTTP is spoken;
//   - `[auth.proxy] whitelist` must stay EMPTY: it is matched against the
//     request's source IP, a unix socket has none, and any non-empty value
//     makes every request 401 — measured, not assumed.

// prepareGrafanaSocketDir creates and re-checks the directory Grafana binds
// its socket in. Called on every Start, before compose runs, so a directory
// that was loosened, replaced or re-owned between starts is caught rather
// than inherited.
//
// The checks, in order:
//
//   - the path exists and is a real directory, never a symlink — a symlink
//     would let anything that could create it redirect the socket;
//   - it is owned by the uid that must own it (grafanaSocketOwnerUID);
//   - its mode is 0700, re-tightened if it had been loosened.
func (s *DockerComposeSupervisor) prepareGrafanaSocketDir() error {
	dir := s.cfg.GrafanaSocketDir
	if dir == "" {
		return errors.New("obs supervisor: GrafanaSocketDir empty")
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("obs supervisor: GrafanaSocketDir %q must be absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("obs supervisor: mkdir grafana socket dir %s: %w", dir, err)
	}
	// Lstat, not Stat: Stat follows a symlink and would report the target's
	// mode and owner while Grafana bound the socket somewhere else.
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("obs supervisor: stat grafana socket dir %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("obs supervisor: grafana socket dir %s is a symlink", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("obs supervisor: grafana socket dir %s is not a directory", dir)
	}
	want := s.grafanaSocketOwnerUID()
	uid, err := fileUID(fi)
	if err != nil {
		return fmt.Errorf("obs supervisor: grafana socket dir %s: %w", dir, err)
	}
	if uid != want {
		if err := os.Chown(dir, want, -1); err != nil {
			return fmt.Errorf("obs supervisor: chown grafana socket dir %s to uid %d: %w",
				dir, want, err)
		}
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		log.Printf("obs supervisor: grafana socket dir %s was %#o; re-tightening to 0700",
			dir, perm)
	}
	// Unconditional: MkdirAll applies the process umask, so even a freshly
	// created directory is not guaranteed to be 0700.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("obs supervisor: chmod grafana socket dir %s: %w", dir, err)
	}
	return nil
}

// checkGrafanaSocket warns if the socket Grafana bound is not 0600 owned by
// the expected uid. It is a tripwire, not a gate: the 0700 directory is the
// control, and this catches a future Grafana that stops honouring
// socket_mode. Never fails a Start — the stack is already up and serving by
// the time it runs.
func (s *DockerComposeSupervisor) checkGrafanaSocket() {
	path := s.GrafanaSocketPath()
	if path == "" {
		return
	}
	fi, err := os.Lstat(path)
	if err != nil {
		log.Printf("obs supervisor: grafana socket %s: %v", path, err)
		return
	}
	if fi.Mode()&os.ModeSocket == 0 {
		log.Printf("obs supervisor: WARNING %s is not a socket (mode %v)", path, fi.Mode())
		return
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		log.Printf("obs supervisor: WARNING grafana socket %s is %#o, want 0600", path, perm)
	}
	if uid, err := fileUID(fi); err == nil && uid != s.grafanaSocketOwnerUID() {
		log.Printf("obs supervisor: WARNING grafana socket %s is owned by uid %d, want %d",
			path, uid, s.grafanaSocketOwnerUID())
	}
}

// grafanaContainerUser is the `user:` the compose template renders for the
// Grafana service, or "" to keep the image's own user.
//
// Empty when the api is root: the directory is chowned to the image's uid
// (472) and Grafana stays unprivileged, which is the appliance case. When
// the api is not root it cannot chown to 472, so the container is pinned to
// the api's own uid/gid instead — the directory is then already the right
// owner and Grafana can bind. Verified on grafana/grafana:11.5.1 with
// `--user 1000:1000`: it serves on the socket (it logs one warning that it
// cannot look the uid up in /etc/passwd).
func (s *DockerComposeSupervisor) grafanaContainerUser() string {
	if !s.grafanaSocketEnabled() || os.Geteuid() == 0 {
		return ""
	}
	return fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())
}
