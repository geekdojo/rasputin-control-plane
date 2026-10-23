package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// liveStore is a node's own secret store: its data tree, seal files and
// store CA under dataDir, as the restore must keep or replace them.
type liveStore struct {
	data, seal, trust string
}

func seedLiveStore(t *testing.T, dataDir string) liveStore {
	t.Helper()
	ls := liveStore{data: filepath.Join(dataDir, "openbao"), seal: filepath.Join(dataDir, "openbao-seal"), trust: filepath.Join(dataDir, "trust")}
	if err := os.MkdirAll(ls.data, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(ls.data, "000009.log"), "LIVE-STORE-DATA")
	writeSealFixture(t, ls.seal, fixtureKeyID2, fixtureSealKey("LIVE"))
	if err := os.MkdirAll(ls.trust, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(ls.trust, tlsca.StoreKeyFile), "LIVE-STORE-CA-KEY")
	writeTestFile(t, filepath.Join(ls.trust, tlsca.StoreCertFile), "LIVE-STORE-CA-PEM")
	return ls
}

// hashes is every file under each dir, by path, with its sha256.
func hashes(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range dirs {
		_ = filepath.Walk(d, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() {
				b, _ := os.ReadFile(p)
				out[p] = sha(b)
			}
			return nil
		})
	}
	return out
}

func sameHashes(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	if len(before) == 0 {
		t.Fatalf("%s: nothing hashed, so nothing is proved", what)
	}
	for p, h := range before {
		if after[p] != h {
			t.Errorf("%s: %s changed", what, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s: %s appeared", what, p)
		}
	}
}

func storeLayout(dataDir string) RestoreLayout {
	return RestoreLayout{DataDir: dataDir, TrustDir: filepath.Join(dataDir, "trust"), MeshStateDir: filepath.Join(dataDir, "mesh")}
}

// prepareStoreRestore builds a version-3 generation, seeds a fresh install
// with a live store and prepares the restore.
func prepareStoreRestore(t *testing.T) (*restoreHarness, IdentitySources, liveStore) {
	t.Helper()
	var src IdentitySources
	h := newRestoreHarness(t, generationOpts{complete: true, store: true, storeSrc: &src})
	seedFreshInstall(t, h.dataDir)
	ls := seedLiveStore(t, h.dataDir)
	if _, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes())); err != nil {
		t.Fatalf("PrepareRestore: %v", err)
	}
	return h, src, ls
}

// markStoreApplied is #766's hook's last act: it leaves the applied marker.
func markStoreApplied(t *testing.T, dataDir string) {
	t.Helper()
	writeTestFile(t, filepath.Join(dataDir, restorePendingDirName, "store", storeAppliedMarkerName), "")
}

// TC-765-06: a pending version-3 restore whose store the store unit has not
// applied is refused at start, fatally, with nothing moved: the database,
// the controlplane CA and the store CA are byte-identical and no
// restore-replaced directory exists. The refusal names the reboot and the
// journal (F-765-06).
func TestApplyRefusesAStoreRestoreTheStoreDidNotApply(t *testing.T) {
	h, _, ls := prepareStoreRestore(t)
	before := hashes(t, filepath.Join(h.dataDir, "rasputin.db"), ls.trust, ls.data, ls.seal)
	_, applied, err := ApplyPendingRestore(storeLayout(h.dataDir))
	if !errors.Is(err, ErrRestoreApplyFailed) || applied {
		t.Fatalf("apply = (%v, %v), want ErrRestoreApplyFailed", applied, err)
	}
	for _, w := range []string{"Reboot the control plane", "openbao.service journal", "restore-pending/ is untouched"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal %q does not say %q", err, w)
		}
	}
	sameHashes(t, "live files", before, hashes(t, filepath.Join(h.dataDir, "rasputin.db"), ls.trust, ls.data, ls.seal))
	for _, e := range dataDirEntries(t, h.dataDir) {
		if strings.HasPrefix(e, restoreReplacedPrefix) {
			t.Errorf("a refused apply created %s", e)
		}
	}
}

// TC-765-07: with the store unit's applied marker present, the restored
// store CA pair is live and the fresh pair is set aside under
// restore-replaced-*/trust/; the api moved no store/ path. A later member's
// move that fails rolls the fresh store CA pair back.
func TestApplyPlacesTheStoreCAAsAPair(t *testing.T) {
	h, src, ls := prepareStoreRestore(t)
	markStoreApplied(t, h.dataDir)
	liveData := hashes(t, ls.data, ls.seal)
	if _, applied, err := ApplyPendingRestore(storeLayout(h.dataDir)); err != nil || !applied {
		t.Fatalf("apply = (%v, %v)", applied, err)
	}
	for _, f := range []string{tlsca.StoreKeyFile, tlsca.StoreCertFile} {
		want, _ := os.ReadFile(filepath.Join(src.TrustDir, f))
		if got := readString(t, filepath.Join(ls.trust, f)); got != string(want) {
			t.Errorf("live %s = %q, want the archived bytes", f, got)
		}
	}
	replaced := replacedDir(t, h.dataDir)
	if got := readString(t, filepath.Join(replaced, "trust", tlsca.StoreKeyFile)); got != "LIVE-STORE-CA-KEY" {
		t.Errorf("set-aside store-ca.key = %q", got)
	}
	if got := readString(t, filepath.Join(replaced, "trust", tlsca.StoreCertFile)); got != "LIVE-STORE-CA-PEM" {
		t.Errorf("set-aside store-ca.pem = %q", got)
	}
	// The store members are where the restore staged them: the api moved
	// none, and placed none over the live store.
	sameHashes(t, "live store data and seal", liveData, hashes(t, ls.data, ls.seal))
	if _, err := os.Stat(filepath.Join(h.dataDir, restoreAppliedDirName, "store", "data", "000001.log")); err != nil {
		t.Errorf("a staged store data file was moved by the api: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(replaced, "store")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the api set a store path aside: %v", err)
	}

	// Rollback: the mesh tree is the last move, and a mesh dir that is a
	// file makes it fail after the store CA has moved.
	h2, _, ls2 := prepareStoreRestore(t)
	markStoreApplied(t, h2.dataDir)
	badMesh := filepath.Join(h2.dataDir, "mesh-is-a-file")
	writeTestFile(t, badMesh, "not a directory")
	layout := storeLayout(h2.dataDir)
	layout.MeshStateDir = badMesh
	if _, applied, err := ApplyPendingRestore(layout); !errors.Is(err, ErrRestoreApplyFailed) || applied {
		t.Fatalf("apply with a failing mesh move = (%v, %v)", applied, err)
	}
	if got := readString(t, filepath.Join(ls2.trust, tlsca.StoreKeyFile)); got != "LIVE-STORE-CA-KEY" {
		t.Errorf("after the rollback store-ca.key = %q, want the fresh one back", got)
	}
	if got := readString(t, filepath.Join(ls2.trust, tlsca.StoreCertFile)); got != "LIVE-STORE-CA-PEM" {
		t.Errorf("after the rollback store-ca.pem = %q, want the fresh one back", got)
	}
}

// TC-765-08: half a store CA, either half, is refused naming the store CA,
// and nothing moves.
func TestApplyRefusesHalfAStoreCA(t *testing.T) {
	for _, half := range []string{storeCAKeyArchivePath, storeCACertArchivePath} {
		t.Run(half, func(t *testing.T) {
			dataDir := t.TempDir()
			writeTestFile(t, filepath.Join(dataDir, "rasputin.db"), "FRESH-DB")
			ls := seedLiveStore(t, dataDir)
			staged := map[string]string{"rasputin.db": "ARCHIVED-DB", half: "ARCHIVED-HALF"}
			stagePending(t, dataDir, staged, []string{"rasputin.db", half})
			before := hashes(t, filepath.Join(dataDir, "rasputin.db"), ls.trust)
			_, applied, err := ApplyPendingRestore(storeLayout(dataDir))
			if !errors.Is(err, ErrRestoreApplyFailed) || applied || !strings.Contains(err.Error(), "one half of the store CA") {
				t.Fatalf("apply = (%v, %v), want a refusal naming the store CA", applied, err)
			}
			sameHashes(t, "live files", before, hashes(t, filepath.Join(dataDir, "rasputin.db"), ls.trust))
			assertRefusedWithNoResidue(t, dataDir, staged)
		})
	}
}

// sealGeneration seals tarBytes into a generation under mount, as the run
// writes one, with its manifest beside it.
func sealGeneration(t *testing.T, mount string, key testKeypair, tarBytes []byte) *Manifest {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != proto.BackupManifestFile {
		t.Fatalf("fixture's first member: %v %+v", err, hdr)
	}
	raw, _ := io.ReadAll(tr)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if _, err := backupxfer.Seal(&sealed, bytes.NewReader(tarBytes), key.publicB64, restoreKeyID, m.Scope); err != nil {
		t.Fatal(err)
	}
	gen := filepath.Join(mount, proto.BackupGenerationsDir, m.GenerationID)
	if err := os.MkdirAll(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, proto.BackupArchiveFile), sealed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, proto.BackupManifestFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return &m
}

// TC-765-09: version-1 and version-2 archives — the latter written by the
// previous release's own Assemble (testdata/identity-archive-v2026.10.2.tar)
// — prepare and apply on a node with a store. The node's store data, seal
// files and store CA are byte-identical afterwards, no applied marker is
// demanded, and the warning says the current store was kept.
func TestPreStoreArchivesKeepTheCurrentStore(t *testing.T) {
	v2, err := os.ReadFile(filepath.Join("testdata", "identity-archive-v2026.10.2.tar"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		opts    generationOpts
		fixture []byte
		version int
	}{
		{name: "version 1", opts: generationOpts{complete: true, manifestVersion: 1}, version: 1},
		{name: "version 2 from v2026.10.2", opts: generationOpts{complete: true}, fixture: v2, version: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestoreHarness(t, tc.opts)
			if tc.fixture != nil {
				h.manifest = sealGeneration(t, h.mount, h.key, tc.fixture)
			}
			if h.manifest.ManifestVersion != tc.version {
				t.Fatalf("fixture is version %d, want %d", h.manifest.ManifestVersion, tc.version)
			}
			seedFreshInstall(t, h.dataDir)
			ls := seedLiveStore(t, h.dataDir)
			before := hashes(t, ls.data, ls.seal, filepath.Join(ls.trust, tlsca.StoreKeyFile), filepath.Join(ls.trust, tlsca.StoreCertFile))
			report, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
			if err != nil {
				t.Fatalf("PrepareRestore: %v", err)
			}
			if !strings.Contains(report.Warning, "the cluster's current secret store, seal key and store CA were kept") {
				t.Errorf("warning %q lacks the store-kept sentence", report.Warning)
			}
			if _, applied, err := ApplyPendingRestore(storeLayout(h.dataDir)); err != nil || !applied {
				t.Fatalf("apply = (%v, %v)", applied, err)
			}
			sameHashes(t, "the node's store", before, hashes(t, ls.data, ls.seal, filepath.Join(ls.trust, tlsca.StoreKeyFile), filepath.Join(ls.trust, tlsca.StoreCertFile)))
		})
	}
	// A version-3 report carries no store-kept sentence.
	if w := identityRestoreWarning(ManifestVersion, nil); strings.Contains(w, "were kept") {
		t.Errorf("a version-3 warning says the store was kept: %q", w)
	}
}

// dropMember removes path from a generation's tar and manifest, or, for
// storeDataArchivePrefix, every data member.
func dropMember(path string) func(t *testing.T, in []byte, m *Manifest) []byte {
	return func(t *testing.T, in []byte, m *Manifest) []byte {
		drop := func(p string) bool {
			if path == storeDataArchivePrefix {
				return strings.HasPrefix(p, storeDataArchivePrefix)
			}
			return p == path
		}
		kept := m.Entries[:0:0]
		for _, e := range m.Entries {
			if !drop(e.Path) {
				kept = append(kept, e)
			}
		}
		m.Entries = kept
		mj, _ := m.JSON()
		return rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
			if h.Name == proto.BackupManifestFile {
				return h, mj, true
			}
			return h, body, !drop(h.Name)
		}, nil)
	}
}

// TC-765-10: a version-3 archive missing any store member — its one data
// file, the seal key, the seal fragment, the version member, either store CA
// half — is refused naming the member, with no staging directory and no
// restore-pending/ left.
func TestPrepareRefusesAVersionThreeArchiveWithoutTheStore(t *testing.T) {
	for _, member := range []string{storeDataArchivePrefix, storeSealKeyArchivePath, storeSealHCLArchivePath, storeVersionArchivePath, storeCAKeyArchivePath, storeCACertArchivePath} {
		t.Run(member, func(t *testing.T) {
			h := newRestoreHarness(t, generationOpts{complete: true, store: true, storeOneFile: true, tamper: dropMember(member)})
			_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
			if !errors.Is(err, ErrRestoreArchive) || !strings.Contains(err.Error(), "names no "+member+";") {
				t.Fatalf("PrepareRestore = %v, want ErrRestoreArchive naming %s", err, member)
			}
			if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
				t.Errorf("data dir holds %v after the refusal", got)
			}
		})
	}
}

// TC-765-11: a manifest of version 4 is refused, saying which versions this
// build reads, and nothing is staged.
func TestPrepareRefusesAnUnknownManifestVersion(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true, store: true, manifestVersion: 4})
	_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if !errors.Is(err, ErrRestoreArchive) || !strings.Contains(err.Error(), "this build reads versions 1 to 3") {
		t.Fatalf("PrepareRestore = %v, want a refusal reading versions 1 to 3", err)
	}
	if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
		t.Errorf("data dir holds %v after the refusal", got)
	}
}

// refusingGuard is a SealGuard that refuses with its sentence.
type refusingGuard struct{ err error }

func (g refusingGuard) CheckRestore() error { return g.err }

// The seal guard runs before the disk is touched: a refusal is a
// RestoreSealBusyError carrying the guard's sentence, nothing is mounted and
// the data dir is untouched. TC-765-14 covers the HTTP answer.
func TestPrepareRefusesWhileTheSealIsBusy(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true, store: true})
	sentence := errors.New("A seal-key rotation is running, so this restore did not start.")
	cfg := h.cfg
	cfg.SealGuard = refusingGuard{err: sentence}
	cfg.NC = nil // a guard that let it through would fail at the mount instead
	_, err := PrepareRestore(context.Background(), cfg, h.request(h.key.priv.Bytes()))
	var busy *RestoreSealBusyError
	if !errors.Is(err, ErrRestoreSealBusy) || !errors.As(err, &busy) || err.Error() != sentence.Error() {
		t.Fatalf("PrepareRestore = %v, want ErrRestoreSealBusy with the guard's sentence", err)
	}
	if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
		t.Errorf("data dir holds %v", got)
	}
	cfg.SealGuard = refusingGuard{}
	cfg.NC = h.cfg.NC
	if _, err := PrepareRestore(context.Background(), cfg, h.request(h.key.priv.Bytes())); err != nil {
		t.Fatalf("a guard that allows: %v", err)
	}
}
