package tailscale

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCAPEM = "-----BEGIN CERTIFICATE-----\nMIIBdummytestcacontent\n-----END CERTIFICATE-----"

func TestInstallMeshCA_WritesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mesh", "ca.pem")

	changed, err := installMeshCA([]byte(testCAPEM), path)
	if err != nil {
		t.Fatalf("installMeshCA (first): %v", err)
	}
	if !changed {
		t.Fatal("first install should report changed=true")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(b) != testCAPEM+"\n" {
		t.Fatalf("unexpected file content: %q", b)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatalf("perm = %o, want 644", info.Mode().Perm())
	}

	// Re-install identical CA → no change (so the caller skips restart).
	changed, err = installMeshCA([]byte(testCAPEM), path)
	if err != nil {
		t.Fatalf("installMeshCA (second): %v", err)
	}
	if changed {
		t.Fatal("re-install of identical CA should report changed=false")
	}

	// A different CA → change again.
	changed, err = installMeshCA([]byte(testCAPEM+"\nextra"), path)
	if err != nil {
		t.Fatalf("installMeshCA (rotate): %v", err)
	}
	if !changed {
		t.Fatal("rotated CA should report changed=true")
	}
}

func TestInstallMeshCA_EmptyIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	changed, err := installMeshCA(nil, path)
	if err != nil || changed {
		t.Fatalf("nil CA should be a noop; changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no file should be written for empty CA")
	}
}

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

func TestRestartTailscaled_BothFail(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("nope")
	}
	if err := restartTailscaled(context.Background(), run); err == nil {
		t.Fatal("expected error when neither init system works")
	}
}

func TestEnsureCAInSystemBundle_AppendsOnceWhenWritable(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "ca-certificates.crt")
	if err := os.WriteFile(bundle, []byte("-----BEGIN CERTIFICATE-----\npublicroot\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cands := []string{bundle}

	changed, err := ensureCAInSystemBundle([]byte(testCAPEM), cands)
	if err != nil || !changed {
		t.Fatalf("first append: changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(bundle)
	if !strings.Contains(string(b), "publicroot") || !strings.Contains(string(b), testCAPEM) {
		t.Fatalf("bundle should keep public roots AND gain mesh CA:\n%s", b)
	}

	// Idempotent: CA already present → no change.
	changed, err = ensureCAInSystemBundle([]byte(testCAPEM), cands)
	if err != nil || changed {
		t.Fatalf("second append should be a noop: changed=%v err=%v", changed, err)
	}
}

func TestEnsureCAInSystemBundle_AbsentBundleIsNotFatal(t *testing.T) {
	// No candidate exists (mirrors a read-only/missing bundle): returns
	// changed=false with an error the caller logs but doesn't treat as fatal.
	changed, err := ensureCAInSystemBundle([]byte(testCAPEM), []string{"/nonexistent/ca.crt"})
	if changed {
		t.Fatal("should not report changed when no writable bundle exists")
	}
	if err == nil {
		t.Fatal("expected a (non-fatal) error when no bundle was writable")
	}
}

func TestCABundlePath_EnvOverride(t *testing.T) {
	t.Setenv("RASPUTIN_MESH_CA_BUNDLE", "/custom/path/ca.pem")
	if got := caBundlePath(); got != "/custom/path/ca.pem" {
		t.Fatalf("env override not honored: %q", got)
	}
	t.Setenv("RASPUTIN_MESH_CA_BUNDLE", "")
	if got := caBundlePath(); got != defaultCABundlePath {
		t.Fatalf("default not used: %q", got)
	}
}
