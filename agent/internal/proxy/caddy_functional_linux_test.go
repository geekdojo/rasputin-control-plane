//go:build linux

package proxy

// Functional test for geekdojo-brain#450 against a REAL Caddy binary, driven
// through the agent's own supervisor (Reconciler.RunCaddy). It proves, on the
// running process rather than on rendered JSON:
//
//   - before the agent has pushed any config, a freshly started Caddy already
//     has its admin API on the socket and no TCP listener at all — `caddy run`
//     would otherwise open its built-in default, TCP localhost:2019;
//   - a Caddy a pre-#450 agent left behind (admin on TCP, holding :443) is
//     retired, and the node converges on the socket with no manual step;
//   - the converged Caddy has NO TCP admin listener — its only TCP listener is
//     the app server — and its admin API answers on the socket, for root;
//   - a non-root uid is refused by the 0700 directory, and — with the
//     directory deliberately opened — still refused by the 0600 socket, and a
//     positive control shows the refusal is the permissions and not the harness;
//   - a killed Caddy and a restarted agent both come back to the same state,
//     re-tightening a loosened directory on the way.
//
// It needs root (to be the agent, and to drop to another uid for the refusal)
// and a caddy binary, so it skips unless RASPUTIN_CADDY_BIN is set. CI's
// "caddy admin socket" job sets RASPUTIN_CADDY_FUNCTIONAL=required, which turns
// every skip into a failure so the job can never pass by not running.
//
// Every wait is on a checkable fact with a hard deadline that names what never
// happened.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// appPortOnly is the converged Caddy's whole TCP footprint: the app server.
var appPortOnly = map[int]bool{443: true}

const (
	helperSocketEnv = "RASPUTIN_TEST_DIAL_SOCKET"
	nobodyUID       = 65534
	convergeWithin  = 45 * time.Second
)

// TestHelperDialAdminSocket is not a test: the functional test re-executes the
// test binary as another uid to run it. It dials the socket, makes one admin
// API request, and prints a single marker line.
func TestHelperDialAdminSocket(t *testing.T) {
	sock := os.Getenv(helperSocketEnv)
	if sock == "" {
		t.Skip("helper process only")
	}
	resp, err := newAdminClient(sock).Get(adminURL("/config/"))
	switch {
	case err == nil:
		_ = resp.Body.Close()
		fmt.Printf("DIAL_OK status=%d\n", resp.StatusCode)
	case errors.Is(err, syscall.EACCES):
		fmt.Println("DIAL_ERR EACCES")
	default:
		fmt.Printf("DIAL_ERR other: %v\n", err)
	}
}

func TestCaddyAdminSocket_RealCaddy(t *testing.T) {
	caddyBin := requireFunctional(t)

	base, err := os.MkdirTemp("", "cadm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	// The temp root is 0700 by default; open it so a refusal below can only
	// come from the admin directory and socket, never from above them.
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	// Caddy's autosave and data dirs follow XDG; keep them out of the checkout.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg-config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "xdg-data"))

	sock := filepath.Join(base, "caddy", "admin.sock")
	listen, err := AdminListen(sock)
	if err != nil {
		t.Fatal(err)
	}
	helper := installHelperBinary(t, base)

	// --- 0. before the first push: socket only, no TCP at all ---------------
	// A leaf store whose certs path is a file makes every Reconcile fail, so
	// Caddy is observed exactly as `caddy run` started it.
	unpushable := filepath.Join(base, "unpushable")
	if err := os.MkdirAll(unpushable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unpushable, "certs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r0 := NewReconciler(NewLeafStore(unpushable), sock, func() string { return "" }, func() string { return "127.0.0.1" })
	r0.legacyAdmin = ""
	stop := superviseCaddy(t, r0, caddyBin)
	pid := waitAdminAnswers(t, caddyBin, sock)
	if cfg := adminConfig(t, sock); cfg != "null" {
		t.Fatalf("caddy before any push has config %s, want null (the push should have failed)", cfg)
	}
	assertLockedDown(t, sock, pid, helper, map[int]bool{})
	stop()
	waitFor(t, convergeWithin, "caddy exiting with its supervisor", func() bool {
		return len(caddyPIDs(caddyBin)) == 0
	})

	// --- 1. a pre-#450 Caddy: admin on TCP, holding the app port -------------
	legacyAddr := freeLoopbackAddr(t)
	legacy := exec.Command(caddyBin, "run")
	legacy.Env = append(os.Environ(), "CADDY_ADMIN="+legacyAddr)
	legacy.Stdout, legacy.Stderr = os.Stdout, os.Stderr
	if err := legacy.Start(); err != nil {
		t.Fatalf("start legacy caddy: %v", err)
	}
	legacyExited := make(chan struct{})
	go func() { _ = legacy.Wait(); close(legacyExited) }()
	t.Cleanup(func() { _ = legacy.Process.Kill(); <-legacyExited })

	legacyClient := &http.Client{Timeout: 2 * time.Second}
	waitFor(t, convergeWithin, "legacy caddy admin answering on TCP "+legacyAddr, func() bool {
		resp, err := legacyClient.Get("http://" + legacyAddr + "/config/")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return true
	})
	resp, err := legacyClient.Post("http://"+legacyAddr+"/load", "application/json",
		bytes.NewReader(legacyRenderedConfig(t, legacyAddr, "127.0.0.1")))
	if err != nil {
		t.Fatalf("load legacy config: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy config rejected (%d): %s", resp.StatusCode, body)
	}
	// The baseline this fix removes, observed rather than assumed: TCP admin
	// open alongside the app port.
	_, legacyPort, _ := net.SplitHostPort(legacyAddr)
	if ports := tcpListenPorts(t, legacy.Process.Pid); !ports[443] || !ports[mustAtoi(t, legacyPort)] {
		t.Fatalf("legacy caddy TCP listeners = %v, want %s and 443", ports, legacyPort)
	}

	// --- 2. the agent's supervisor retires it and converges on the socket ----
	newReconciler := func() *Reconciler {
		r := NewReconciler(NewLeafStore(filepath.Join(base, "leaves")), sock,
			func() string { return "" },
			func() string { return "127.0.0.1" })
		r.legacyAdmin = legacyAddr
		return r
	}
	stop = superviseCaddy(t, newReconciler(), caddyBin)

	select {
	case <-legacyExited:
	case <-time.After(convergeWithin):
		t.Fatalf("legacy caddy on TCP %s never exited after the supervisor started", legacyAddr)
	}
	pid = waitConverged(t, caddyBin, sock, listen, 0)
	assertLockedDown(t, sock, pid, helper, appPortOnly)

	// --- 3. a killed Caddy comes back the same way ----------------------------
	// Loosen the directory first: the restart must re-tighten it, not trust it.
	if err := os.Chmod(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill caddy %d: %v", pid, err)
	}
	pid = waitConverged(t, caddyBin, sock, listen, pid)
	assertLockedDown(t, sock, pid, helper, appPortOnly)

	// --- 4. an agent restart: supervisor stops, a new one converges -----------
	stop()
	waitFor(t, convergeWithin, "caddy exiting with its supervisor", func() bool {
		return len(caddyPIDs(caddyBin)) == 0
	})
	stop = superviseCaddy(t, newReconciler(), caddyBin)
	pid = waitConverged(t, caddyBin, sock, listen, pid)
	assertLockedDown(t, sock, pid, helper, appPortOnly)
	stop()
}

// requireFunctional returns the caddy binary, or skips — failing instead when
// RASPUTIN_CADDY_FUNCTIONAL=required.
func requireFunctional(t *testing.T) string {
	t.Helper()
	required := os.Getenv("RASPUTIN_CADDY_FUNCTIONAL") == "required"
	skip := func(why string) {
		if required {
			t.Fatalf("RASPUTIN_CADDY_FUNCTIONAL=required but %s", why)
		}
		t.Skip(why)
	}
	bin := os.Getenv("RASPUTIN_CADDY_BIN")
	if bin == "" {
		skip("RASPUTIN_CADDY_BIN is not set")
	}
	if os.Geteuid() != 0 {
		skip("the real-Caddy admin socket test needs root")
	}
	if _, err := os.Stat(bin); err != nil {
		skip(fmt.Sprintf("caddy binary: %v", err))
	}
	return bin
}

// superviseCaddy runs r.RunCaddy until the returned stop func is called (or the
// test ends); stop waits for the supervisor to return.
func superviseCaddy(t *testing.T, r *Reconciler, caddyBin string) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.RunCaddy(ctx, caddyBin); close(done) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(convergeWithin):
			t.Errorf("RunCaddy did not return within %s of cancel", convergeWithin)
		}
	}
	t.Cleanup(stop)
	return stop
}

// waitConverged waits for exactly one supervised Caddy (not notPID) whose admin
// API answers root on the socket with the agent's pushed config, and returns
// its pid.
func waitConverged(t *testing.T, caddyBin, sock, listen string, notPID int) int {
	t.Helper()
	client := newAdminClient(sock)
	var pid int
	waitFor(t, convergeWithin, "a restarted caddy serving the pushed config on "+sock, func() bool {
		pids := caddyPIDs(caddyBin)
		if len(pids) != 1 || pids[0] == notPID {
			return false
		}
		resp, err := client.Get(adminURL("/config/"))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var cfg struct {
			Admin struct {
				Listen string `json:"listen"`
			} `json:"admin"`
			Apps struct {
				HTTP struct {
					Servers map[string]struct {
						Listen []string `json:"listen"`
					} `json:"servers"`
				} `json:"http"`
			} `json:"apps"`
		}
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&cfg) != nil {
			return false
		}
		lan := cfg.Apps.HTTP.Servers["lan"].Listen
		if cfg.Admin.Listen != listen || len(lan) != 1 || lan[0] != "127.0.0.1:443" {
			return false
		}
		pid = pids[0]
		return true
	})
	return pid
}

// waitAdminAnswers waits for exactly one supervised Caddy whose admin API
// answers root on the socket, and returns its pid.
func waitAdminAnswers(t *testing.T, caddyBin, sock string) int {
	t.Helper()
	client := newAdminClient(sock)
	var pid int
	waitFor(t, convergeWithin, "a supervised caddy answering on "+sock, func() bool {
		pids := caddyPIDs(caddyBin)
		if len(pids) != 1 {
			return false
		}
		resp, err := client.Get(adminURL("/config/"))
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		pid = pids[0]
		return resp.StatusCode == http.StatusOK
	})
	return pid
}

// adminConfig returns Caddy's live config over the socket, trimmed.
func adminConfig(t *testing.T, sock string) string {
	t.Helper()
	resp, err := newAdminClient(sock).Get(adminURL("/config/"))
	if err != nil {
		t.Fatalf("GET /config/ over %s: %v", sock, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(body))
}

// assertLockedDown checks the converged state: the socket's shape, exactly
// wantPorts as TCP listeners (so no admin port of any number), and a non-root
// uid refused at both layers.
func assertLockedDown(t *testing.T, sock string, pid int, helper string, wantPorts map[int]bool) {
	t.Helper()
	dir := filepath.Dir(sock)
	if err := CheckAdminSocket(sock); err != nil {
		t.Errorf("admin socket: %v", err)
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("admin dir %s = %v (err %v), want a 0700 directory", dir, fi.Mode(), err)
	} else if err := ownedByEUID(fi); err != nil {
		t.Errorf("admin dir %s: %v", dir, err)
	}

	if ports := tcpListenPorts(t, pid); !maps.Equal(ports, wantPorts) {
		t.Errorf("caddy %d TCP listeners = %v, want exactly %v", pid, ports, wantPorts)
	}

	// Layer 1: the 0700 directory.
	if got := dialAs(t, helper, sock); got != "DIAL_ERR EACCES" {
		t.Errorf("uid %d through a 0700 dir: %q, want DIAL_ERR EACCES", nobodyUID, got)
	}
	// Layer 2: open the directory for traversal — the 0600 socket alone refuses.
	mustChmod(t, dir, 0o711)
	if got := dialAs(t, helper, sock); got != "DIAL_ERR EACCES" {
		t.Errorf("uid %d with the dir opened, 0600 socket: %q, want DIAL_ERR EACCES", nobodyUID, got)
	}
	// Positive control: with both opened the same helper gets in, so the two
	// refusals above were the permissions and not a broken harness.
	mustChmod(t, sock, 0o666)
	if got := dialAs(t, helper, sock); !strings.HasPrefix(got, "DIAL_OK") {
		t.Errorf("positive control: uid %d with dir 0711 and socket 0666: %q, want DIAL_OK", nobodyUID, got)
	}
	mustChmod(t, sock, 0o600)
	mustChmod(t, dir, 0o700)
}

// dialAs runs the helper binary as nobody against sock and returns its marker.
func dialAs(t *testing.T, helper, sock string) string {
	t.Helper()
	cmd := exec.Command(helper, "-test.run=^TestHelperDialAdminSocket$", "-test.count=1")
	cmd.Env = []string{helperSocketEnv + "=" + sock, "PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: nobodyUID, Gid: nobodyUID, NoSetGroups: true},
	}
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "DIAL_") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("helper as uid %d printed no marker (err %v):\n%s", nobodyUID, err, out)
	return ""
}

// installHelperBinary copies this test binary somewhere nobody can execute it:
// go test's own build directory is private to the building user.
func installHelperBinary(t *testing.T, base string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(base, "dialhelper.test")
	if err := os.WriteFile(dst, src, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

// caddyPIDs lists the live caddy processes this test process started. Callers
// use it only while no legacy Caddy is alive, so it is the Caddy the supervisor
// is running. Identified by
// parentage and executable, not by anything the code under test sets, so a
// supervisor that stopped passing the socket would still be found (and fail).
func caddyPIDs(caddyBin string) []int {
	wantExe, err := filepath.EvalSymlinks(caddyBin)
	if err != nil {
		return nil
	}
	self := os.Getpid()
	entries, _ := os.ReadDir("/proc")
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// Fields after the parenthesised comm: state ppid ...
		i := bytes.LastIndexByte(stat, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(stat[i+1:]))
		if len(f) < 2 || f[0] == "Z" || f[1] != strconv.Itoa(self) {
			continue
		}
		if exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe")); err != nil || exe != wantExe {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// tcpListenPorts returns the TCP ports pid is listening on, by matching its
// socket inodes against /proc/net/tcp{,6}.
func tcpListenPorts(t *testing.T, pid int) map[int]bool {
	t.Helper()
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		t.Fatalf("read %s: %v", fdDir, err)
	}
	inodes := map[string]bool{}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	ports := map[int]bool{}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(table)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			// local_address rem_address state ... inode is field 9.
			if len(f) < 10 || f[3] != "0A" || !inodes[f[9]] {
				continue
			}
			i := strings.LastIndexByte(f[1], ':')
			port, err := strconv.ParseInt(f[1][i+1:], 16, 32)
			if err != nil {
				t.Fatalf("parse %s port %q: %v", table, f[1], err)
			}
			ports[int(port)] = true
		}
	}
	return ports
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never happened within %s: %s", within, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
