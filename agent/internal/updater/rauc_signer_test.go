package updater

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The production Install path, with the production signer check — no test
// seam. This is the assertion that the gate is actually WIRED: every other
// RAUC test in this package overrides verifySigner, and a shipped default that
// returned nil would look identical to a working system right up until an
// unauthorized leaf signed an OS image.
//
// `rauc install` in these cases is the "ok" shim, which succeeds
// unconditionally. So a failure here can only come from the signer check, and
// a pass would mean the bundle reached `rauc install` unchecked.
func TestRAUCInstall_FailsClosedWithoutAnAuthorizedSigner(t *testing.T) {
	trustRoot := filepath.Join(t.TempDir(), "root-ca.pem")
	writeSelfSignedRoot(t, trustRoot)

	// A well-formed verity trailer pointing at bytes that are not a CMS
	// object: the file looks like a bundle and its signature does not parse.
	sigGarbage := make([]byte, 512)
	for i := range sigGarbage {
		sigGarbage[i] = 0x41
	}
	var lenField [8]byte
	binary.BigEndian.PutUint64(lenField[:], uint64(len(sigGarbage)))
	notCMS := append(append(make([]byte, 4096), sigGarbage...), lenField[:]...)

	// No trailer at all — an unsigned file, or one truncated in transit.
	binary.BigEndian.PutUint64(lenField[:], 0)
	zeroSig := append(make([]byte, 4096), lenField[:]...)

	for _, tc := range []struct {
		name      string
		trustRoot string
		bundle    []byte
		wantIn    string
	}{
		{
			name:      "signature is not a CMS object",
			trustRoot: trustRoot,
			bundle:    notCMS,
			wantIn:    "parse bundle signature",
		},
		{
			name:      "bundle declares no signature",
			trustRoot: trustRoot,
			bundle:    zeroSig,
			wantIn:    "signature trailer",
		},
		{
			name:      "file is too short to carry a trailer",
			trustRoot: trustRoot,
			bundle:    []byte("x"),
			wantIn:    "signature trailer",
		},
		{
			name:      "no trust root on the box",
			trustRoot: filepath.Join(t.TempDir(), "absent.pem"),
			bundle:    notCMS,
			wantIn:    "trust root is missing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeRAUC(t, "ok")
			t.Setenv(artifactsig.TrustRootEnv, tc.trustRoot)
			stateDir := t.TempDir()
			b, err := NewRAUCBackend(stateDir)
			if err != nil {
				t.Fatalf("NewRAUCBackend: %v", err)
			}
			if b.verifySigner == nil {
				t.Fatal("the production backend ships with no signer check at all")
			}
			path := filepath.Join(stateDir, "bundles", "bundle.raucb")
			if err := os.WriteFile(path, tc.bundle, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err = b.Install(context.Background(), "b1", path, proto.SlotB, nil)
			if err == nil {
				t.Fatal("Install handed a bundle with no authorized signer to `rauc install`")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}
		})
	}
}

// The check runs BEFORE `rauc install`, which is what keeps an unauthorized
// bundle from reaching the inactive slot at all. The "fail" shim would also
// produce an error, so this pins the ORDER: with a shim that records whether
// it ran, the recording must not happen.
func TestRAUCInstall_SignerCheckRunsBeforeRauc(t *testing.T) {
	fakeRAUC(t, "ok")
	stateDir := t.TempDir()
	b, err := NewRAUCBackend(stateDir)
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	path := filepath.Join(stateDir, "bundles", "bundle.raucb")
	if err := os.WriteFile(path, []byte("not a bundle"), 0o644); err != nil {
		t.Fatal(err)
	}

	ran := false
	b.verifySigner = func(p string) error {
		ran = true
		if p != path {
			t.Errorf("signer check got %q, want the resolved bundle path %q", p, path)
		}
		return errRefusedForTest
	}
	if _, err := b.Install(context.Background(), "b1", path, proto.SlotB, nil); err == nil {
		t.Fatal("Install proceeded past a refused signer")
	}
	if !ran {
		t.Fatal("the signer check never ran")
	}
}

// A path off the bus is resolved against the bundle store BEFORE the signer
// check sees it, so the check can never be pointed at a file outside the
// store — the same property bundlepath.go gives `rauc install` itself.
func TestRAUCInstall_SignerCheckSeesTheResolvedPath(t *testing.T) {
	fakeRAUC(t, "ok")
	stateDir := t.TempDir()
	b, err := NewRAUCBackend(stateDir)
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	seen := ""
	b.verifySigner = func(p string) error { seen = p; return errRefusedForTest }
	_, _ = b.Install(context.Background(), "b1", "/etc/passwd", proto.SlotB, nil)
	if seen != "" {
		t.Fatalf("the signer check was handed %q; an out-of-store path must be refused before it", seen)
	}
}

var errRefusedForTest = errRefused{}

type errRefused struct{}

func (errRefused) Error() string { return "refused by test" }
