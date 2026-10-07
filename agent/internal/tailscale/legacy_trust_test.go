package tailscale

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// countingInstaller is a TrustInstaller that records its calls and reports
// changed for the first install of each distinct bundle.
type countingInstaller struct {
	calls int
	last  []byte
}

func (c *countingInstaller) Install(b []byte) (bool, error) {
	c.calls++
	changed := string(b) != string(c.last)
	c.last = append([]byte(nil), b...)
	return changed, nil
}
func (c *countingInstaller) Fingerprint() string { return "fp" }

// TC-741-20: a mesh.enroll carrying a bundle (an api older than
// trust.install) installs it through the injected TrustInstaller and restarts
// tailscaled only when it changed; an enroll with no bundle never calls the
// installer; NewRealBackend reads no bundle path of its own.
func TestRealBackend_LegacyEnrollBundleGoesThroughTheInstaller(t *testing.T) {
	withInitSystems(t, "/run/systemd/system")
	var restarts int
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) == 2 && args[0] == "restart" {
			restarts++
		}
		return nil, nil
	}
	inst := &countingInstaller{}
	b := &RealBackend{binary: fakeTSBin(t, "ok-status"), trust: inst, run: run, log: discardLog()}
	ca := tlstest.NewCA(t, "older-api").PEM
	enroll := func(bundle []byte) {
		t.Helper()
		if _, err := b.Enroll(context.Background(), EnrollInput{LoginServer: "https://hs", AuthKey: "k", LegacyTrustBundlePEM: bundle}); err != nil {
			t.Fatalf("Enroll: %v", err)
		}
	}
	enroll(ca)
	if inst.calls != 1 || restarts != 1 {
		t.Fatalf("first legacy enroll: installs=%d restarts=%d, want 1 and 1", inst.calls, restarts)
	}
	enroll(ca)
	if inst.calls != 2 || restarts != 1 {
		t.Errorf("unchanged legacy enroll: installs=%d restarts=%d, want 2 and still 1", inst.calls, restarts)
	}
	enroll(nil)
	if inst.calls != 2 {
		t.Errorf("an enroll with no bundle called the installer (%d calls)", inst.calls)
	}
	if b.TrustFingerprint() != "fp" {
		t.Error("TrustFingerprint is not the installer's")
	}

	// The constructor takes its trust by injection: the source reads no
	// bundle path and no RASPUTIN_MESH_CA_BUNDLE.
	src, err := os.ReadFile("real.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"RASPUTIN_MESH_CA_BUNDLE", "BundlePath", "tailscaled-ca.pem"} {
		if strings.Contains(string(src), s) {
			t.Errorf("real.go names %q: the backend must not resolve a bundle path itself", s)
		}
	}
}

// The mock installs a legacy bundle through the installer too, and its
// ReloadTrust is a no-op.
func TestMockBackend_LegacyEnrollAndReload(t *testing.T) {
	inst := &countingInstaller{}
	mb, err := NewMockBackend(t.TempDir(), inst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Enroll(context.Background(), EnrollInput{AuthKey: "k", LegacyTrustBundlePEM: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Enroll(context.Background(), EnrollInput{AuthKey: "k"}); err != nil {
		t.Fatal(err)
	}
	if inst.calls != 1 {
		t.Errorf("installs=%d, want 1", inst.calls)
	}
	if err := mb.ReloadTrust(context.Background()); err != nil {
		t.Errorf("ReloadTrust: %v", err)
	}
	if _, err := NewMockBackend(t.TempDir(), nil); err == nil {
		t.Error("a mock with no installer was built")
	}
}

// ReloadTrust restarts tailscaled; a failed restart is its error.
func TestRealBackend_ReloadTrust(t *testing.T) {
	withInitSystems(t, "/run/systemd/system")
	var calls []string
	b := &RealBackend{binary: fakeTSBin(t, "ok-status"), trust: testTrust(t), log: discardLog(),
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "systemctl" {
				return nil, nil
			}
			return []byte("{}"), nil
		}}
	if err := b.ReloadTrust(context.Background()); err != nil {
		t.Fatalf("ReloadTrust: %v", err)
	}
	if len(calls) == 0 || calls[0] != "systemctl restart tailscaled" {
		t.Errorf("calls %v, want a tailscaled restart first", calls)
	}
	withInitSystems(t)
	if err := b.ReloadTrust(context.Background()); err == nil {
		t.Error("ReloadTrust with no init system succeeded")
	}
	// The refusal names the collaborators, so it is the nil check that
	// answered and not the PATH lookup behind it.
	for name, build := range map[string]func() (*RealBackend, error){
		"nil installer": func() (*RealBackend, error) { return NewRealBackend(nil, discardLog()) },
		"nil logger":    func() (*RealBackend, error) { return NewRealBackend(testTrust(t), nil) },
	} {
		if _, err := build(); err == nil || !strings.Contains(err.Error(), "needs a TrustInstaller and a logger") {
			t.Errorf("%s: err %v, want the collaborator refusal", name, err)
		}
	}
}
