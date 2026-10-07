package tailscale

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// withInitSystems pins which init-system markers "exist" for one test.
func withInitSystems(t *testing.T, present ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, p := range present {
		set[p] = true
	}
	orig := initSystemPresent
	initSystemPresent = func(path string) bool { return set[path] }
	t.Cleanup(func() { initSystemPresent = orig })
}

func TestRestartTailscaled_ProcdOnlyBox(t *testing.T) {
	withInitSystems(t, "/etc/init.d/tailscale") // OpenWrt firewall
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte("ok"), nil
	}
	if err := restartTailscaled(context.Background(), run); err != nil {
		t.Fatalf("expected procd restart to succeed: %v", err)
	}
	if len(calls) != 1 || calls[0][0] != "/etc/init.d/tailscale" {
		t.Fatalf("a procd-only box must not shell out to systemctl: %v", calls)
	}
}

// The regression this whole change exists for: on a systemd node the procd
// path can NEVER exist, so attempting it only adds a "no such file" line that
// reads as the cause and isn't. The real cause here is the systemctl failure.
func TestRestartTailscaled_SystemdErrorDoesNotMentionProcd(t *testing.T) {
	withInitSystems(t, "/run/systemd/system") // Buildroot OS
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("exit status 1")
	}
	err := restartTailscaled(context.Background(), run)
	if err == nil {
		t.Fatal("expected an error when systemctl fails")
	}
	if strings.Contains(err.Error(), "init.d") || strings.Contains(err.Error(), "procd") {
		t.Errorf("systemd-node error must not mention the procd fallback, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("error should surface the real systemctl failure, got: %v", err)
	}
}

func TestRestartTailscaled_NoInitSystemIsAClearError(t *testing.T) {
	withInitSystems(t) // neither present
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		t.Fatalf("must not exec anything when no init system is present: %s", name)
		return nil, nil
	}
	err := restartTailscaled(context.Background(), run)
	if err == nil || !strings.Contains(err.Error(), "no supported init system") {
		t.Errorf("want a clear no-init-system error, got: %v", err)
	}
}

func TestRestartTailscaled_SystemdFirstWins(t *testing.T) {
	withInitSystems(t, "/run/systemd/system", "/etc/init.d/tailscale")
	var calls int
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		return []byte("ok"), nil
	}
	if err := restartTailscaled(context.Background(), run); err != nil {
		t.Fatalf("systemd path should succeed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("systemd success should not try procd; calls=%d", calls)
	}
}

// On a firewall image that carries Rasputin's own tailscaled service, that is
// the one to restart: it is the service that passes SSL_CERT_FILE. Restarting
// the stock one, which is still on disk, would start a second, env-less daemon
// on the same state file and port. (geekdojo/geekdojo-brain#542)
func TestRestartTailscaled_PrefersRasputinService(t *testing.T) {
	withInitSystems(t, "/etc/init.d/rasputin-tailscale", "/etc/init.d/tailscale")
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte("ok"), nil
	}
	if err := restartTailscaled(context.Background(), run); err != nil {
		t.Fatalf("expected the rasputin service restart to succeed: %v", err)
	}
	if len(calls) != 1 || calls[0][0] != "/etc/init.d/rasputin-tailscale" {
		t.Fatalf("want exactly one restart, of the rasputin service; got %v", calls)
	}
}

// An image that predates that service still has to work: a newer agent on an
// older firewall image falls back to the stock init.
func TestRestartTailscaled_FallsBackToStockInit(t *testing.T) {
	withInitSystems(t, "/etc/init.d/tailscale")
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte("ok"), nil
	}
	if err := restartTailscaled(context.Background(), run); err != nil {
		t.Fatalf("expected the stock restart to succeed: %v", err)
	}
	if len(calls) != 1 || calls[0][0] != "/etc/init.d/tailscale" {
		t.Fatalf("want exactly one restart, of the stock service; got %v", calls)
	}
}

func TestRestartTailscaled_BothFail(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("nope")
	}
	if err := restartTailscaled(context.Background(), run); err == nil {
		t.Fatal("expected error when neither init system works")
	}
}

// The default init-system probe is a plain existence check: a path that is
// there is present, one that is not is absent.
func TestInitSystemPresent_Default(t *testing.T) {
	dir := t.TempDir()
	if !initSystemPresent(dir) {
		t.Error("an existing path read as absent")
	}
	if initSystemPresent(filepath.Join(dir, "absent")) {
		t.Error("a missing path read as present")
	}
}
