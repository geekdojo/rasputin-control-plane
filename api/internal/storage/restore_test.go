package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Harness for the restore: a real generation on a real temp "mount" — the
// marker, the sidecar manifest and a sealed identity archive built by the
// same Assemble and Seal the run uses — a fake agent answering the mount and
// enumerate verbs, and a fresh data dir standing in for a re-flashed
// /var/lib/rasputin.

const (
	restoreNodeID   = "n-restore"
	restorePartUUID = "0f3c9a52-01"
	restoreKeyID    = "ak-restore-1"
)

// identityFixture is the identity set the generation captures, kept so a test
// can compare what comes out with what went in.
type identityFixture struct {
	db, caKey, caPem, hsConfig, hsDB []byte
}

func newIdentityFixture() identityFixture {
	return identityFixture{
		db:       []byte("SQLite format 3\x00 stand-in for rasputin.db " + strings.Repeat("row ", 5000)),
		caKey:    []byte("-----BEGIN PRIVATE KEY-----\nMESH-CA-KEY\n-----END PRIVATE KEY-----\n"),
		caPem:    []byte("-----BEGIN CERTIFICATE-----\nMESH-CA-CERT\n-----END CERTIFICATE-----\n"),
		hsConfig: []byte("server_url: https://cp.test\n"),
		hsDB:     []byte("HEADSCALE-STATE"),
	}
}

// generationOpts shapes one built generation.
type generationOpts struct {
	id       string
	scope    string
	complete bool
	// volumes are the fan-out records the manifest carries; a captured one
	// also gets a (fake) member file on the mount.
	volumes []VolumeRecord
	// tamper, when set, rewrites the assembled tar before it is sealed.
	tamper func(t *testing.T, tarBytes []byte, m *Manifest) []byte
	// manifestVersion overrides the version written into the inner manifest.
	manifestVersion int
}

// buildGeneration writes a marker and one generation under mount, sealed to
// key, and returns the manifest it wrote.
func buildGeneration(t *testing.T, mount string, key testKeypair, fx identityFixture, opts generationOpts) *Manifest {
	t.Helper()
	if opts.id == "" {
		opts.id = proto.BackupGenerationID(time.Now(), "job-1", proto.BackupScopeFull)
	}
	if opts.scope == "" {
		opts.scope = proto.BackupScopeFull
	}
	// The marker: what a claim wrote onto the disk.
	marker := proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion, ClusterID: "home1", PartUUID: restorePartUUID,
		KeyID: restoreKeyID, KeyAlg: "X25519;wrap=AES-256-GCM", PublicKey: key.publicB64,
		WrappedByPassphrase: testWrappedPass, WrappedByRecoveryCode: testWrappedRecovery,
		Label: "the archive disk", CreatedAt: time.Now().UTC(),
	}
	mb, _ := json.Marshal(marker)
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, proto.StorageMarkerFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}

	// The identity set on "the old controlplane", assembled by the real
	// assembler from real files.
	src := t.TempDir()
	trust := filepath.Join(src, "trust")
	mesh := filepath.Join(src, "mesh")
	writeTestFile(t, filepath.Join(src, "snapshot.db"), string(fx.db))
	if err := os.MkdirAll(trust, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(trust, "mesh-ca.key"), string(fx.caKey))
	writeTestFile(t, filepath.Join(trust, "mesh-ca.pem"), string(fx.caPem))
	if err := os.MkdirAll(filepath.Join(mesh, "headscale", "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(mesh, "headscale", "config.yaml"), string(fx.hsConfig))
	writeTestFile(t, filepath.Join(mesh, "headscale", "db", "headscale.sqlite"), string(fx.hsDB))

	captured := 0
	for _, v := range opts.volumes {
		if v.Captured {
			captured++
		}
	}
	report := NewAppVolumeReport(AppEnumeration{AppsInstalled: len(opts.volumes), AppsResolved: len(opts.volumes), Catalog: "test"}, opts.volumes, 1)
	var tarBuf bytes.Buffer
	m, err := Assemble(&tarBuf, AssembleOptions{
		Sources:      IdentitySources{TrustDir: trust, MeshStateDir: mesh},
		SnapshotPath: filepath.Join(src, "snapshot.db"),
		GenerationID: opts.id, JobID: "job-1", ClusterID: "home1", KeyID: restoreKeyID,
		Now: time.Now().UTC(), AppVolumes: report, Scope: opts.scope,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if opts.complete != m.Complete {
		// Complete is derived from the records; the caller's expectation is
		// checked rather than forced so a test cannot lie about it.
		t.Fatalf("test setup: manifest complete=%v, opts.complete=%v", m.Complete, opts.complete)
	}
	tarBytes := tarBuf.Bytes()
	if opts.manifestVersion != 0 {
		m.ManifestVersion = opts.manifestVersion
		tarBytes = rewriteManifestInTar(t, tarBytes, m)
	}
	if opts.tamper != nil {
		tarBytes = opts.tamper(t, tarBytes, m)
	}
	var sealed bytes.Buffer
	if _, err := backupxfer.Seal(&sealed, bytes.NewReader(tarBytes), key.publicB64, restoreKeyID, opts.scope); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	gen := filepath.Join(mount, proto.BackupGenerationsDir, opts.id)
	if err := os.MkdirAll(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, proto.BackupArchiveFile), sealed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	mj, _ := m.JSON()
	if err := os.WriteFile(filepath.Join(gen, proto.BackupManifestFile), mj, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, v := range opts.volumes {
		if v.Captured && v.Member != "" {
			p := filepath.Join(gen, filepath.FromSlash(v.Member))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, p, "sealed volume member stand-in")
		}
	}
	return m
}

// capturedVolume and skippedVolume are fan-out records in the shape the run
// leaves them.
func capturedVolume(app, vol, class string) VolumeRecord {
	return VolumeRecord{
		App: app, Volume: vol, Class: class, Node: "n-compute", Captured: true,
		Member: proto.BackupMemberPath(app, vol), SealedSHA256: strings.Repeat("ab", 32), SizeBytes: 1234,
		AppRestored: true,
	}
}

func skippedVolume(app, vol, class, reason string) VolumeRecord {
	return VolumeRecord{App: app, Volume: vol, Class: class, Node: "n-compute", Captured: false, Reason: reason, AppRestored: true}
}

// rewriteTar rebuilds a tar, letting edit change (or drop, by returning
// false) each entry, and add append extras. The manifest entry is passed
// through untouched unless edit changes it.
func rewriteTar(t *testing.T, in []byte, edit func(h *tar.Header, body []byte) (*tar.Header, []byte, bool), extra func(tw *tar.Writer)) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(in))
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for {
		h, err := tr.Next()
		if errors.Is(err, os.ErrNotExist) || err != nil {
			break
		}
		body, _ := readAllTar(t, tr)
		nh, nb, keep := edit(h, body)
		if !keep {
			continue
		}
		nh.Size = int64(len(nb))
		if err := tw.WriteHeader(nh); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(nb); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		extra(tw)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func readAllTar(t *testing.T, tr *tar.Reader) ([]byte, error) {
	t.Helper()
	var b bytes.Buffer
	_, err := b.ReadFrom(tr)
	return b.Bytes(), err
}

func rewriteManifestInTar(t *testing.T, in []byte, m *Manifest) []byte {
	t.Helper()
	mj, _ := m.JSON()
	return rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
		if h.Name == proto.BackupManifestFile {
			return h, mj, true
		}
		return h, body, true
	}, nil)
}

func addTarEntry(name string, typeflag byte, link string, body []byte) func(tw *tar.Writer) {
	return func(tw *tar.Writer) {
		h := &tar.Header{Name: name, Typeflag: typeflag, Linkname: link, Mode: 0o600, Size: int64(len(body)), ModTime: time.Now()}
		_ = tw.WriteHeader(h)
		_, _ = tw.Write(body)
	}
}

// fakeMountAgent answers storage.mount and storage.enumerate for one disk.
type fakeMountAgent struct {
	mount      string
	candidates []proto.StorageCandidate
}

func (f *fakeMountAgent) start(t *testing.T, nc *nats.Conn) {
	t.Helper()
	respond := func(m *nats.Msg, v any) {
		b, _ := json.Marshal(v)
		_ = m.Respond(b)
	}
	s1, err := nc.Subscribe(proto.StorageMountSubject(restoreNodeID), func(m *nats.Msg) {
		var cmd proto.StorageMountCmd
		_ = json.Unmarshal(m.Data, &cmd)
		if cmd.PartUUID != restorePartUUID {
			respond(m, proto.StorageMountAck{OK: false, Refusal: proto.StorageRefusalNotFound, Detail: "no such target"})
			return
		}
		respond(m, proto.StorageMountAck{OK: true, PartUUID: cmd.PartUUID, MountPath: f.mount})
	})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := nc.Subscribe(proto.StorageEnumerateSubject(restoreNodeID), func(m *nats.Msg) {
		respond(m, proto.StorageEnumerateAck{OK: true, Backend: "mock", Candidates: f.candidates, Ts: time.Now().UTC()})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s1.Unsubscribe(); _ = s2.Unsubscribe() })
}

func readMarker(t *testing.T, mount string) *proto.StorageBackupSet {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(mount, proto.StorageMarkerFile))
	if err != nil {
		t.Fatal(err)
	}
	var set proto.StorageBackupSet
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatal(err)
	}
	return &set
}

// restoreHarness is one built generation, one fake agent, one fresh data dir.
type restoreHarness struct {
	nc       *nats.Conn
	key      testKeypair
	fx       identityFixture
	mount    string
	dataDir  string
	manifest *Manifest
	cfg      RestoreConfig
}

func newRestoreHarness(t *testing.T, opts generationOpts) *restoreHarness {
	t.Helper()
	root := t.TempDir()
	mount := filepath.Join(root, "mnt", "rasputin-backup")
	dataDir := filepath.Join(root, "fresh-var-lib-rasputin")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := newTestKeypair(t)
	fx := newIdentityFixture()
	m := buildGeneration(t, mount, key, fx, opts)
	nc := startNATS(t)
	agent := &fakeMountAgent{mount: mount, candidates: []proto.StorageCandidate{{
		DevicePath: "/dev/sdb", Model: "Archive Disk", Serial: "S1", SizeBytes: 2 << 40,
		Transport: proto.StorageTransportUSB, Removable: true, HasBackupSet: true,
		BackupSet: readMarker(t, mount), Fingerprint: "fp-1",
	}, {
		// The boot disk, enumerated but never a source.
		DevicePath: "/dev/nvme0n1", Protected: true, ProtectedReason: "holds /var/lib/rasputin",
	}}}
	agent.start(t, nc)
	return &restoreHarness{
		nc: nc, key: key, fx: fx, mount: mount, dataDir: dataDir, manifest: m,
		cfg: RestoreConfig{NC: nc, SelfNodeID: restoreNodeID, DataDir: dataDir, ClusterID: "home1"},
	}
}

func (h *restoreHarness) request(key []byte) RestoreRequest {
	return RestoreRequest{PartUUID: restorePartUUID, GenerationID: h.manifest.GenerationID, KeyID: restoreKeyID, PrivateKey: key}
}

// dataDirEntries lists the data dir, for "left as it found it" assertions.
func dataDirEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func mustSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ----- the cases ----------------------------------------------------------

func TestPrepareRestoreStagesTheIdentitySetAndReportsTheGap(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{
		complete: false,
		volumes: []VolumeRecord{
			capturedVolume("vaultwarden", "data", "critical"),
			skippedVolume("jellyfin", "library", "bulk", "bulk volumes stream direct; that lane is not built"),
		},
	})
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	priv := h.key.priv.Bytes()
	report, err := PrepareRestore(context.Background(), h.cfg, h.request(priv))
	if err != nil {
		t.Fatalf("PrepareRestore: %v", err)
	}

	// Nothing but the pending directory was created under the data dir.
	if got := dataDirEntries(t, h.dataDir); len(got) != 1 || got[0] != restorePendingDirName {
		t.Fatalf("data dir holds %v, want only %s", got, restorePendingDirName)
	}
	pending := filepath.Join(h.dataDir, restorePendingDirName)
	want := map[string][]byte{
		"rasputin.db":                        h.fx.db,
		"trust/mesh-ca.key":                  h.fx.caKey,
		"trust/mesh-ca.pem":                  h.fx.caPem,
		"mesh/headscale/config.yaml":         h.fx.hsConfig,
		"mesh/headscale/db/headscale.sqlite": h.fx.hsDB,
	}
	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(pending, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("staged %s: %v", rel, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("staged %s differs from what was captured", rel)
		}
	}
	// The report: every identity file with the digest that was verified.
	if len(report.Restored) != len(want) {
		t.Fatalf("restored %d entries, want %d: %+v", len(report.Restored), len(want), report.Restored)
	}
	for _, e := range report.Restored {
		if e.SHA256 != mustSHA(want[e.Path]) {
			t.Fatalf("%s: report digest %s, file digest %s", e.Path, e.SHA256, mustSHA(want[e.Path]))
		}
	}
	if report.Phase != RestorePhase || report.GenerationID != h.manifest.GenerationID || report.KeyID != restoreKeyID || report.Complete {
		t.Fatalf("report header wrong: %+v", report)
	}
	// The gap, by name: the captured volume is present and not restored; the
	// skipped one is absent with its reason.
	if len(report.AppVolumesPresent) != 1 || report.AppVolumesPresent[0].Name != "vaultwarden/data" || report.AppVolumesPresent[0].Member == "" {
		t.Fatalf("appVolumesPresent = %+v", report.AppVolumesPresent)
	}
	if len(report.AppVolumesAbsent) != 1 || report.AppVolumesAbsent[0].Name != "jellyfin/library" || !strings.Contains(report.AppVolumesAbsent[0].Reason, "bulk") {
		t.Fatalf("appVolumesAbsent = %+v", report.AppVolumesAbsent)
	}
	if !strings.Contains(report.Warning, "APP DATA WAS NOT RESTORED") {
		t.Fatalf("warning does not say so: %q", report.Warning)
	}
	// restore.json beside the files, and it is the same report.
	var onDisk RestoreReport
	b, err := os.ReadFile(filepath.Join(pending, restoreReportFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &onDisk); err != nil || onDisk.ID != report.ID {
		t.Fatalf("restore.json: %v / %+v", err, onDisk)
	}
	// The key is in none of the surfaces this produced.
	for name, text := range map[string]string{"log": logs.String(), "restore.json": string(b)} {
		if strings.Contains(text, h.key.privateB64()) || strings.Contains(text, h.key.privateHex()) {
			t.Fatalf("the private key reached the %s", name)
		}
	}
	if rj, _ := json.Marshal(report); strings.Contains(string(rj), h.key.privateB64()) || strings.Contains(string(rj), h.key.privateHex()) {
		t.Fatal("the private key is in the report")
	}
}

func TestPrepareRestoreRefusesAKeyThatIsNotTheDisks(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	other := newTestKeypair(t)
	_, err := PrepareRestore(context.Background(), h.cfg, h.request(other.priv.Bytes()))
	if !errors.Is(err, ErrRestoreKeyMismatch) {
		t.Fatalf("err = %v, want ErrRestoreKeyMismatch", err)
	}
	if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
		t.Fatalf("data dir was written: %v", got)
	}
}

func TestPrepareRestoreRefusesShapeAndIdentityMismatches(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	priv := h.key.priv.Bytes()
	cases := map[string]RestoreRequest{
		"wrong key id":       {PartUUID: restorePartUUID, GenerationID: h.manifest.GenerationID, KeyID: "ak-other", PrivateKey: priv},
		"unknown generation": {PartUUID: restorePartUUID, GenerationID: "20260101T000000Z-nojob-full", KeyID: restoreKeyID, PrivateKey: priv},
		"generation path":    {PartUUID: restorePartUUID, GenerationID: "../" + h.manifest.GenerationID, KeyID: restoreKeyID, PrivateKey: priv},
		"unknown disk":       {PartUUID: "no-such-part", GenerationID: h.manifest.GenerationID, KeyID: restoreKeyID, PrivateKey: priv},
		"part uuid shape":    {PartUUID: "../etc", GenerationID: h.manifest.GenerationID, KeyID: restoreKeyID, PrivateKey: priv},
		"short key":          {PartUUID: restorePartUUID, GenerationID: h.manifest.GenerationID, KeyID: restoreKeyID, PrivateKey: priv[:16]},
		"zero key":           {PartUUID: restorePartUUID, GenerationID: h.manifest.GenerationID, KeyID: restoreKeyID, PrivateKey: make([]byte, 32)},
	}
	for name, req := range cases {
		if _, err := PrepareRestore(context.Background(), h.cfg, req); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
			t.Fatalf("%s: data dir was written: %v", name, got)
		}
	}
	empty := h.cfg
	empty.SelfNodeID = ""
	if _, err := PrepareRestore(context.Background(), empty, h.request(priv)); err == nil {
		t.Fatal("an api with no self node id restored")
	}
}

// Each tamper builds an archive the writer could not have produced and
// expects the restore to refuse it with ErrRestoreArchive and the data dir
// untouched. The archive is SEALED after tampering, so the AEAD passes — this
// is the extraction's own discipline being tested, not the cipher's.
func TestPrepareRestoreRefusesHostileMembers(t *testing.T) {
	cases := map[string]func(t *testing.T, in []byte, m *Manifest) []byte{
		"dot-dot member": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, keepAll, addTarEntry("../outside.txt", tar.TypeReg, "", []byte("escape")))
		},
		"absolute member": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, keepAll, addTarEntry("/etc/passwd", tar.TypeReg, "", []byte("root:x")))
		},
		"symlink member": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, keepAll, addTarEntry("trust/link", tar.TypeSymlink, "/etc/shadow", nil))
		},
		"symlink in place of an identity file": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
				if h.Name == "trust/mesh-ca.key" {
					h.Typeflag = tar.TypeSymlink
					h.Linkname = "/etc/shadow"
					return h, nil, true
				}
				return h, body, true
			}, nil)
		},
		"digest mismatch": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
				if h.Name == "rasputin.db" {
					body = append([]byte{}, body...)
					body[0] ^= 0xff // same size, different bytes
				}
				return h, body, true
			}, nil)
		},
		"size mismatch": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
				if h.Name == "trust/mesh-ca.pem" {
					body = append(body, []byte("extra")...)
				}
				return h, body, true
			}, nil)
		},
		"identity member the manifest does not name": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, keepAll, addTarEntry("mesh/headscale/planted.key", tar.TypeReg, "", []byte("planted")))
		},
		"identity member the manifest names is missing": func(t *testing.T, in []byte, m *Manifest) []byte {
			return rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
				return h, body, h.Name != "trust/mesh-ca.key"
			}, nil)
		},
		"manifest not first": func(t *testing.T, in []byte, m *Manifest) []byte {
			var manifestBody []byte
			out := rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
				if h.Name == proto.BackupManifestFile {
					manifestBody = body
					return h, body, false
				}
				return h, body, true
			}, addTarEntry(proto.BackupManifestFile, tar.TypeReg, "", nil))
			_ = manifestBody
			return out
		},
		"manifest for another generation": func(t *testing.T, in []byte, m *Manifest) []byte {
			mm := *m
			mm.GenerationID = "20200101T000000Z-other-full"
			return rewriteManifestInTar(t, in, &mm)
		},
		"unreadable manifest version": func(t *testing.T, in []byte, m *Manifest) []byte {
			mm := *m
			mm.ManifestVersion = 99
			return rewriteManifestInTar(t, in, &mm)
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRestoreHarness(t, generationOpts{complete: true, tamper: tamper})
			_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
			if !errors.Is(err, ErrRestoreArchive) {
				t.Fatalf("err = %v, want ErrRestoreArchive", err)
			}
			if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
				t.Fatalf("data dir was left with %v after a refused restore", got)
			}
		})
	}
}

func keepAll(h *tar.Header, body []byte) (*tar.Header, []byte, bool) { return h, body, true }

func TestPrepareRestoreRefusesATruncatedArchive(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	p := filepath.Join(h.mount, proto.BackupGenerationsDir, h.manifest.GenerationID, proto.BackupArchiveFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b[:len(b)-40], 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if !errors.Is(err, ErrRestoreArchive) {
		t.Fatalf("err = %v", err)
	}
	if got := dataDirEntries(t, h.dataDir); len(got) != 0 {
		t.Fatalf("data dir was left with %v", got)
	}
}

func TestPrepareRestoreRefusesASecondWhileOneIsPending(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	if _, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes())); err != nil {
		t.Fatal(err)
	}
	_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if !errors.Is(err, ErrRestorePending) {
		t.Fatalf("err = %v, want ErrRestorePending", err)
	}
}

func TestPrepareRestoreReportsAVersionOneArchivesInArchiveVolumesAsNotRestored(t *testing.T) {
	// A manifest-v1 generation carried app volumes INSIDE the identity
	// archive under app-volumes/. Phase 1 puts the identity set back and
	// names the rest as present and not restored.
	h := newRestoreHarness(t, generationOpts{complete: true, manifestVersion: 1, tamper: func(t *testing.T, in []byte, m *Manifest) []byte {
		return rewriteTar(t, in, keepAll, addTarEntry("app-volumes/vaultwarden/data.tar", tar.TypeReg, "", []byte("old-style volume")))
	}})
	report, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if err != nil {
		t.Fatalf("PrepareRestore: %v", err)
	}
	if len(report.NotRestored) != 1 || report.NotRestored[0].Path != "app-volumes/vaultwarden/data.tar" {
		t.Fatalf("notRestored = %+v", report.NotRestored)
	}
	if _, err := os.Stat(filepath.Join(h.dataDir, restorePendingDirName, "app-volumes")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a non-identity member was extracted")
	}
}

func TestListRestoreCandidatesDescribesTheDisk(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{
		complete: false,
		volumes:  []VolumeRecord{capturedVolume("vaultwarden", "data", "critical"), skippedVolume("photos", "library", "bulk", "bulk lane not built")},
	})
	resp, err := ListRestoreCandidates(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.NodeID != restoreNodeID || resp.ClusterID != "home1" || len(resp.Candidates) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	c := resp.Candidates[0]
	if !c.Restorable || c.Problem != "" || c.Marker == nil || c.Marker.KeyID != restoreKeyID || c.Marker.PublicKey != h.key.publicB64 {
		t.Fatalf("candidate = %+v", c)
	}
	if c.Marker.WrappedByPassphrase != testWrappedPass || c.Marker.WrappedByRecoveryCode != testWrappedRecovery {
		t.Fatal("the wrapped blobs the browser needs are not on the candidate")
	}
	if len(c.Generations) != 1 {
		t.Fatalf("generations = %+v", c.Generations)
	}
	g := c.Generations[0]
	if g.ID != h.manifest.GenerationID || !g.Restorable || g.Complete || g.Scope != proto.BackupScopeFull || g.KeyID != restoreKeyID || g.IdentityEntries != 5 || g.ArchiveBytes == 0 {
		t.Fatalf("generation = %+v", g)
	}
	if len(g.AppVolumesPresent) != 1 || g.AppVolumesPresent[0].Name != "vaultwarden/data" || len(g.AppVolumesAbsent) != 1 || g.AppVolumesAbsent[0].Name != "photos/library" {
		t.Fatalf("volumes: present %+v absent %+v", g.AppVolumesPresent, g.AppVolumesAbsent)
	}
	// The response carries no key material beyond the public key and the
	// two wrappings the disk already publishes.
	rj, _ := json.Marshal(resp)
	if strings.Contains(string(rj), h.key.privateB64()) || strings.Contains(string(rj), h.key.privateHex()) {
		t.Fatal("private key in the candidates response")
	}
}

func TestListRestoreCandidatesNamesWhyADiskCannotBeUsed(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	nc := startNATS(t)
	cfg := h.cfg
	cfg.NC = nc
	symmetric := readMarker(t, h.mount)
	symmetric.PublicKey = ""
	noPart := readMarker(t, h.mount)
	noPart.PartUUID = ""
	agent := &fakeMountAgent{mount: h.mount, candidates: []proto.StorageCandidate{
		{DevicePath: "/dev/sdc", HasBackupSet: true, BackupSet: symmetric},
		{DevicePath: "/dev/sdd", HasBackupSet: true, BackupSet: noPart},
		{DevicePath: "/dev/sde", HasBackupSet: true, BackupSet: nil},
		{DevicePath: "/dev/nvme0n1", Protected: true, HasBackupSet: true, BackupSet: readMarker(t, h.mount)},
		{DevicePath: "/dev/sdf", HasBackupSet: false},
	}}
	agent.start(t, nc)
	resp, err := ListRestoreCandidates(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Candidates) != 4 {
		t.Fatalf("candidates = %+v", resp.Candidates)
	}
	wantProblem := map[string]string{
		"/dev/sdc":     "predates the keypair design",
		"/dev/sdd":     "no partition UUID",
		"/dev/sde":     "could not be read",
		"/dev/nvme0n1": "running from",
	}
	for _, c := range resp.Candidates {
		if c.Restorable || !strings.Contains(c.Problem, wantProblem[c.DevicePath]) {
			t.Fatalf("%s: restorable=%v problem=%q, want %q", c.DevicePath, c.Restorable, c.Problem, wantProblem[c.DevicePath])
		}
	}
	if _, err := ListRestoreCandidates(context.Background(), RestoreConfig{NC: nc}); err == nil {
		t.Fatal("an api with no self node id listed candidates")
	}
}

func TestValidateRestorePath(t *testing.T) {
	good := []string{"rasputin.db", "trust/mesh-ca.key", "mesh/headscale/db/headscale.sqlite", "a/.hidden"}
	bad := []string{"", "/abs", "../x", "a/../b", "a/./b", "./a", "a//b", "a/", `a\b`, "a/..", "..", ".", "a b", "trust/mesh-ca.key\x00"}
	for _, p := range good {
		if err := validateRestorePath(p); err != nil {
			t.Fatalf("%q refused: %v", p, err)
		}
	}
	for _, p := range bad {
		if err := validateRestorePath(p); err == nil {
			t.Fatalf("%q accepted", p)
		}
	}
}

// ----- apply --------------------------------------------------------------

// seedFreshInstall gives the data dir what a first boot leaves there: a
// database with a WAL, a freshly generated CA, empty Headscale state.
func seedFreshInstall(t *testing.T, dataDir string) {
	t.Helper()
	writeTestFile(t, filepath.Join(dataDir, "rasputin.db"), "FRESH-DB")
	writeTestFile(t, filepath.Join(dataDir, "rasputin.db-wal"), "FRESH-WAL")
	if err := os.MkdirAll(filepath.Join(dataDir, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dataDir, "trust", "mesh-ca.key"), "FRESH-CA-KEY")
	writeTestFile(t, filepath.Join(dataDir, "trust", "mesh-ca.pem"), "FRESH-CA-PEM")
	writeTestFile(t, filepath.Join(dataDir, "trust", "root-ca.pem"), "BUNDLE-ROOT")
	if err := os.MkdirAll(filepath.Join(dataDir, "mesh", "headscale"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dataDir, "mesh", "headscale", "fresh.yaml"), "FRESH-HS")
}

func TestApplyPendingRestoreSwapsTheIdentityIntoPlaceAndRecordsIt(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	seedFreshInstall(t, h.dataDir)
	if _, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes())); err != nil {
		t.Fatal(err)
	}
	layout := RestoreLayout{DataDir: h.dataDir, TrustDir: filepath.Join(h.dataDir, "trust"), MeshStateDir: filepath.Join(h.dataDir, "mesh")}
	report, applied, err := ApplyPendingRestore(layout)
	if err != nil || !applied || report == nil || report.AppliedAt == nil {
		t.Fatalf("apply: %v applied=%v report=%+v", err, applied, report)
	}
	want := map[string][]byte{
		"rasputin.db":                        h.fx.db,
		"trust/mesh-ca.key":                  h.fx.caKey,
		"trust/mesh-ca.pem":                  h.fx.caPem,
		"mesh/headscale/config.yaml":         h.fx.hsConfig,
		"mesh/headscale/db/headscale.sqlite": h.fx.hsDB,
		// Untouched: not part of the identity set.
		"trust/root-ca.pem": []byte("BUNDLE-ROOT"),
	}
	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(h.dataDir, filepath.FromSlash(rel)))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("live %s: %v / %q", rel, err, got)
		}
	}
	// The stale WAL went aside with the fresh database, and the fresh
	// Headscale tree is gone from the live path.
	for _, gone := range []string{"rasputin.db-wal", "mesh/headscale/fresh.yaml", restorePendingDirName} {
		if _, err := os.Lstat(filepath.Join(h.dataDir, filepath.FromSlash(gone))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still in place", gone)
		}
	}
	// The fresh install's files were moved aside, not deleted.
	ents := dataDirEntries(t, h.dataDir)
	var replaced string
	for _, e := range ents {
		if strings.HasPrefix(e, restoreReplacedPrefix) {
			replaced = filepath.Join(h.dataDir, e)
		}
	}
	if replaced == "" {
		t.Fatalf("no replaced dir among %v", ents)
	}
	for rel, body := range map[string]string{"rasputin.db": "FRESH-DB", "rasputin.db-wal": "FRESH-WAL", "trust/mesh-ca.key": "FRESH-CA-KEY", "mesh/headscale/fresh.yaml": "FRESH-HS"} {
		got, err := os.ReadFile(filepath.Join(replaced, filepath.FromSlash(rel)))
		if err != nil || string(got) != body {
			t.Fatalf("replaced %s: %v / %q", rel, err, got)
		}
	}
	// A second apply is a no-op.
	if _, again, err := ApplyPendingRestore(layout); err != nil || again {
		t.Fatalf("second apply: %v %v", err, again)
	}
	// The record lands in the store, once, and the applied dir goes.
	st := newStore(t)
	rec, err := RecordAppliedRestore(context.Background(), st, h.dataDir)
	if err != nil || rec == nil || rec.ID != report.ID {
		t.Fatalf("record: %v %+v", err, rec)
	}
	if _, err := os.Lstat(filepath.Join(h.dataDir, restoreAppliedDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("applied dir not removed after recording")
	}
	if rec, err := RecordAppliedRestore(context.Background(), st, h.dataDir); err != nil || rec != nil {
		t.Fatalf("second record: %v %+v", err, rec)
	}
	list, err := st.ListRestores(context.Background())
	if err != nil || len(list) != 1 || list[0].ID != report.ID || list[0].RecordedAt == nil {
		t.Fatalf("list: %v %+v", err, list)
	}
	latest, err := st.LatestRestore(context.Background())
	if err != nil || latest == nil || latest.GenerationID != report.GenerationID {
		t.Fatalf("latest: %v %+v", err, latest)
	}
}

func TestApplyPendingRestoreRollsBackWhenAMoveFails(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	seedFreshInstall(t, h.dataDir)
	if _, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes())); err != nil {
		t.Fatal(err)
	}
	// A trust dir that is a FILE: the database swap succeeds, the CA move
	// cannot, and everything must go back.
	badTrust := filepath.Join(h.dataDir, "trust-is-a-file")
	writeTestFile(t, badTrust, "not a directory")
	layout := RestoreLayout{DataDir: h.dataDir, TrustDir: badTrust, MeshStateDir: filepath.Join(h.dataDir, "mesh")}
	_, applied, err := ApplyPendingRestore(layout)
	if err == nil || applied || !errors.Is(err, ErrRestoreApplyFailed) {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}
	got, err := os.ReadFile(filepath.Join(h.dataDir, "rasputin.db"))
	if err != nil || string(got) != "FRESH-DB" {
		t.Fatalf("fresh database not restored after rollback: %v %q", err, got)
	}
	if _, err := os.Stat(filepath.Join(h.dataDir, "rasputin.db-wal")); err != nil {
		t.Fatal("fresh WAL not put back")
	}
	if _, err := os.Stat(filepath.Join(h.dataDir, restorePendingDirName, "rasputin.db")); err != nil {
		t.Fatal("staged database not put back into pending")
	}
}

func TestApplyPendingRestoreDoesNothingWithoutAPendingDir(t *testing.T) {
	dir := t.TempDir()
	rep, applied, err := ApplyPendingRestore(RestoreLayout{DataDir: dir})
	if err != nil || applied || rep != nil {
		t.Fatalf("%v %v %+v", err, applied, rep)
	}
	if rep, err := RecordAppliedRestore(context.Background(), newStore(t), dir); err != nil || rep != nil {
		t.Fatalf("%v %+v", err, rep)
	}
	if err := os.WriteFile(filepath.Join(dir, restorePendingDirName), []byte("a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplyPendingRestore(RestoreLayout{DataDir: dir}); err == nil {
		t.Fatal("a file named restore-pending was accepted")
	}
}

func TestSweepRestoreStaging(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, restoreStagingPrefix+"dead"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if n := SweepRestoreStaging(dir); n != 1 {
		t.Fatalf("swept %d", n)
	}
	if got := dataDirEntries(t, dir); len(got) != 1 || got[0] != "keep" {
		t.Fatalf("left %v", got)
	}
}
