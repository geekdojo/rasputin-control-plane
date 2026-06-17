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

func TestRestartTailscaled_FallsBackToProcd(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "systemctl" {
			return nil, errors.New("no systemd here")
		}
		return []byte("ok"), nil // procd path succeeds
	}
	if err := restartTailscaled(context.Background(), run); err != nil {
		t.Fatalf("expected procd fallback to succeed: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected systemctl then init.d, got %d calls: %v", len(calls), calls)
	}
	if calls[0][0] != "systemctl" || calls[1][0] != "/etc/init.d/tailscale" {
		t.Fatalf("unexpected restart order: %v", calls)
	}
}

func TestRestartTailscaled_SystemdFirstWins(t *testing.T) {
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
