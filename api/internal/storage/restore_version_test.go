package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// geekdojo/geekdojo-brain#872: a backup records the control-plane version
// that took it, and a restore accepts it only on that same version.

const (
	noVersionSentence = "This backup records no control plane version, so this control plane cannot tell which release took it. Restore it on the release it was taken on."
	unstampedSentence = "This control plane build carries no version stamp, so it cannot tell whether a backup belongs to it. Restore from a released image."
)

// readOnly makes dir unwritable for the rest of the test, so an attempt to
// create the staging directory fails with a permission error instead of the
// refusal under test: proof the refusal came first, not that staging was
// cleaned up after.
func readOnly(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// versionErr asserts err is a RestoreVersionError and not a permission or
// archive error, and returns it.
func versionErr(t *testing.T, err error) *RestoreVersionError {
	t.Helper()
	if !errors.Is(err, ErrRestoreVersion) {
		t.Fatalf("err = %v, want ErrRestoreVersion", err)
	}
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, ErrRestoreArchive) {
		t.Fatalf("err = %v also matches a permission or archive error", err)
	}
	var ve *RestoreVersionError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want *RestoreVersionError", err)
	}
	return ve
}

// innerManifestEdit rewrites the inner manifest's JSON as a map, so a key
// can be removed outright rather than written empty.
func innerManifestEdit(edit func(map[string]any)) func(t *testing.T, in []byte, m *Manifest) []byte {
	return func(t *testing.T, in []byte, _ *Manifest) []byte {
		return rewriteTar(t, in, func(h *tar.Header, body []byte) (*tar.Header, []byte, bool) {
			if h.Name != proto.BackupManifestFile {
				return h, body, true
			}
			var raw map[string]any
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatal(err)
			}
			edit(raw)
			nb, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			return h, nb, true
		}, nil)
	}
}

// editSidecar rewrites the clear sidecar manifest of the harness generation.
func (h *restoreHarness) editSidecar(t *testing.T, edit func(*Manifest)) {
	t.Helper()
	p := filepath.Join(h.mount, proto.BackupGenerationsDir, h.manifest.GenerationID, proto.BackupManifestFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	edit(&m)
	mj, _ := m.JSON()
	if err := os.WriteFile(p, mj, 0o600); err != nil {
		t.Fatal(err)
	}
}

// firstTarMember decodes the tar's first member as a manifest.
func firstTarMember(t *testing.T, tarBytes []byte) Manifest {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != proto.BackupManifestFile {
		t.Fatalf("first member: %v %+v", err, hdr)
	}
	raw, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TC-872-01: Assemble records the version in the inner manifest (the first
// tar member) and in the returned manifest the sidecar is written from.
func TestAssembleRecordsTheControlPlaneVersion(t *testing.T) {
	dataDir := t.TempDir()
	for _, d := range []string{"trust", "mesh/headscale", "bus"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(dataDir, "trust", "mesh-ca.key"), "MESH-CA-KEY")
	writeTestFile(t, filepath.Join(dataDir, "trust", "mesh-ca.pem"), "MESH-CA-PEM")
	snap := filepath.Join(dataDir, "snapshot.db")
	writeTestFile(t, snap, "SQLITE-SNAPSHOT-BYTES")

	var buf bytes.Buffer
	m, err := Assemble(&buf, AssembleOptions{
		Sources:      IdentitySources{TrustDir: filepath.Join(dataDir, "trust"), MeshStateDir: filepath.Join(dataDir, "mesh"), BusDir: filepath.Join(dataDir, "bus")},
		SnapshotPath: snap, GenerationID: "20261011T000000Z-test-full", ClusterID: "home1", KeyID: "key-1",
		Scope: proto.BackupScopeFull, ControlPlaneVersion: "2026.10.2",
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if inner := firstTarMember(t, buf.Bytes()); inner.ControlPlaneVersion != "2026.10.2" {
		t.Errorf("inner manifest controlPlaneVersion = %q, want 2026.10.2", inner.ControlPlaneVersion)
	}
	side, err := m.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(side, []byte(`"controlPlaneVersion": "2026.10.2"`)) {
		t.Errorf("sidecar JSON lacks the version key:\n%s", side)
	}
}

// TC-872-02: a full backup.run writes the composition-root version into the
// sidecar handed to the target and into the sealed archive's inner manifest.
func TestBackupRunRecordsTheControlPlaneVersion(t *testing.T) {
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{})
	j := h.waitTerminal(t, h.submit(t, RunSpec{Reason: ReasonManual}))
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (%s)", j.Status, j.Error)
	}
	cmd, ok := h.agent.lastWrite()
	if !ok {
		t.Fatal("the agent was never asked to write")
	}
	var side Manifest
	if err := json.Unmarshal([]byte(cmd.ManifestJSON), &side); err != nil {
		t.Fatal(err)
	}
	if side.ControlPlaneVersion != runCPVersion {
		t.Errorf("sidecar controlPlaneVersion = %q, want %q", side.ControlPlaneVersion, runCPVersion)
	}
	var plain bytes.Buffer
	if _, err := Unseal(&plain, bytes.NewReader(h.agent.lastSealed()), h.key.priv.Bytes()); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if inner := firstTarMember(t, plain.Bytes()); inner.ControlPlaneVersion != runCPVersion {
		t.Errorf("inner controlPlaneVersion = %q, want %q", inner.ControlPlaneVersion, runCPVersion)
	}
}

// TC-872-03: an unstamped build fails the run at step 1 with a sentence, and
// no later step runs: no preflight, no snapshot, no fan-out stop, no write.
func TestBackupRunRefusesAnUnstampedBuild(t *testing.T) {
	none := ""
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{cpVersion: &none})
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	if j.Error != errNoVersionStampBackup.Error() {
		t.Errorf("job error = %q, want %q", j.Error, errNoVersionStampBackup)
	}
	if !strings.HasPrefix(j.Error, "This ") || !strings.HasSuffix(j.Error, ".") || !strings.Contains(j.Error, "version stamp") {
		t.Errorf("job error %q is not a sentence naming the missing stamp", j.Error)
	}
	steps, err := h.jobStore.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		switch {
		case st.Name == "validate" && st.Status != jobs.StepFailed:
			t.Errorf("validate is %s, want failed", st.Status)
		case st.Name != "validate" && st.Status != jobs.StepPending:
			t.Errorf("step %s ran (%s) after a step-1 refusal", st.Name, st.Status)
		}
	}
	h.agent.mu.Lock()
	preflights, staged := len(h.agent.preflightCmds), len(h.agent.staged)
	h.agent.mu.Unlock()
	if preflights != 0 || staged != 0 || h.agent.writeCount() != 0 {
		t.Errorf("agent saw %d preflight(s), %d stage(s), %d write(s)", preflights, staged, h.agent.writeCount())
	}
	if stops, _ := h.agent.quiesceCounts(); stops != 0 {
		t.Errorf("the fan-out stopped %d app(s)", stops)
	}
	if left := h.stagingEntries(t); len(left) != 0 {
		t.Errorf("a step-1 refusal staged %v", left)
	}
}

// TC-872-04: a generation taken on the running version stages normally.
func TestPrepareRestoreAcceptsTheSameVersion(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	if h.manifest.ControlPlaneVersion != restoreCPVersion || h.cfg.ControlPlaneVersion != restoreCPVersion {
		t.Fatalf("setup: taken %q, running %q", h.manifest.ControlPlaneVersion, h.cfg.ControlPlaneVersion)
	}
	report, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if err != nil || report == nil {
		t.Fatalf("PrepareRestore = %v, %v", report, err)
	}
	if got := dataDirEntries(t, h.dataDir); !slices.Equal(got, []string{restorePendingDirName}) {
		t.Fatalf("data dir = %v", got)
	}
	if _, err := os.Stat(filepath.Join(h.dataDir, restorePendingDirName, "rasputin.db")); err != nil {
		t.Fatalf("restore-pending holds no rasputin.db: %v", err)
	}
}

// TC-872-05: a generation taken on another version — newer, older, or a dev
// build of the same base — is refused before staging, naming the version to
// flash and the version this board runs.
func TestPrepareRestoreRefusesAnotherVersionBeforeStaging(t *testing.T) {
	for _, running := range []string{"2026.10.3", "2026.10.1", "2026.10.2-dev.197"} {
		t.Run(running, func(t *testing.T) {
			h := newRestoreHarness(t, generationOpts{complete: true})
			h.cfg.ControlPlaneVersion = running
			before := dataDirEntries(t, h.dataDir)
			readOnly(t, h.dataDir)
			_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
			ve := versionErr(t, err)
			if ve.Taken != restoreCPVersion || ve.Running != running {
				t.Errorf("error = %+v", ve)
			}
			want := "This backup was taken on control plane version 2026.10.2, and this control plane runs version " + running +
				". Flash release 2026.10.2 onto this board and restore again."
			if got := ve.Sentence(); got != want {
				t.Errorf("sentence = %q\nwant       %q", got, want)
			}
			if after := dataDirEntries(t, h.dataDir); !slices.Equal(before, after) {
				t.Errorf("data dir %v became %v", before, after)
			}
		})
	}
}

// TC-872-06: the archive the previous release writes — version 2, no
// controlPlaneVersion key — is refused and nothing is staged (Bryce,
// 2026-10-24: no backwards compatibility in alpha).
func TestPrepareRestoreRefusesThePreviousReleasesArchive(t *testing.T) {
	v2, err := os.ReadFile(filepath.Join("testdata", "identity-archive-v2026.10.2.tar"))
	if err != nil {
		t.Fatal(err)
	}
	h := newRestoreHarness(t, generationOpts{complete: true})
	h.manifest = sealGeneration(t, h.mount, h.key, v2)
	if h.manifest.ManifestVersion != 2 || bytes.Contains(v2[:4096], []byte("controlPlaneVersion")) {
		t.Fatalf("fixture is version %d or carries the key", h.manifest.ManifestVersion)
	}
	before := dataDirEntries(t, h.dataDir)
	readOnly(t, h.dataDir)
	_, err = PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if got := versionErr(t, err).Sentence(); got != noVersionSentence {
		t.Errorf("sentence = %q", got)
	}
	if after := dataDirEntries(t, h.dataDir); !slices.Equal(before, after) {
		t.Errorf("data dir %v became %v", before, after)
	}
}

// TC-872-07: a version-3 archive whose inner manifest has the key removed, or
// present and empty, is refused with the no-version sentence.
func TestPrepareRestoreRefusesAVersionThreeArchiveWithNoVersion(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"key removed": func(m map[string]any) { delete(m, "controlPlaneVersion") },
		"key empty":   func(m map[string]any) { m["controlPlaneVersion"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			h := newRestoreHarness(t, generationOpts{complete: true, store: true, tamper: innerManifestEdit(edit)})
			if h.manifest.ManifestVersion != ManifestVersion {
				t.Fatalf("setup: version %d", h.manifest.ManifestVersion)
			}
			before := dataDirEntries(t, h.dataDir)
			readOnly(t, h.dataDir)
			_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
			if got := versionErr(t, err).Sentence(); got != noVersionSentence {
				t.Errorf("sentence = %q", got)
			}
			if after := dataDirEntries(t, h.dataDir); !slices.Equal(before, after) {
				t.Errorf("data dir %v became %v", before, after)
			}
		})
	}
}

// TC-872-08: an unstamped running build refuses before the disk is touched:
// no storage mount RPC is sent.
func TestPrepareRestoreRefusesAnUnstampedBuildBeforeTheDisk(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true})
	h.cfg.ControlPlaneVersion = ""
	mounts := 0
	sub, err := h.nc.Subscribe(proto.StorageMountSubject(restoreNodeID), func(*nats.Msg) { mounts++ })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	before := dataDirEntries(t, h.dataDir)
	_, err = PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if got := versionErr(t, err).Sentence(); got != unstampedSentence {
		t.Errorf("sentence = %q", got)
	}
	// A flush round-trips the server, so any mount request published before
	// it has been delivered to the counter by now.
	if err := h.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := sub.Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	if mounts != 0 {
		t.Errorf("%d mount RPC(s) sent", mounts)
	}
	if after := dataDirEntries(t, h.dataDir); !slices.Equal(before, after) {
		t.Errorf("data dir %v became %v", before, after)
	}
}

// TC-872-09: the inner manifest decides; the clear sidecar is never read for
// the version.
func TestPrepareRestoreTrustsTheInnerVersionNotTheSidecar(t *testing.T) {
	t.Run("inner differs, sidecar matches", func(t *testing.T) {
		h := newRestoreHarness(t, generationOpts{complete: true, cpVersion: "2026.10.2"})
		h.editSidecar(t, func(m *Manifest) { m.ControlPlaneVersion = "2026.10.3" })
		h.cfg.ControlPlaneVersion = "2026.10.3"
		_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
		if ve := versionErr(t, err); ve.Taken != "2026.10.2" {
			t.Errorf("taken = %q, want the inner 2026.10.2", ve.Taken)
		}
	})
	t.Run("inner matches, sidecar differs", func(t *testing.T) {
		h := newRestoreHarness(t, generationOpts{complete: true, cpVersion: "2026.10.3"})
		h.editSidecar(t, func(m *Manifest) { m.ControlPlaneVersion = "2026.10.2" })
		h.cfg.ControlPlaneVersion = "2026.10.3"
		if report, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes())); err != nil || report == nil {
			t.Fatalf("PrepareRestore = %v, %v", report, err)
		}
		if got := dataDirEntries(t, h.dataDir); !slices.Equal(got, []string{restorePendingDirName}) {
			t.Fatalf("data dir = %v", got)
		}
	})
}

// TC-872-10: a backup from a newer build that also bumped the format is
// refused for its version, naming the release, not for its format.
func TestPrepareRestoreChecksTheVersionBeforeTheFormat(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true, manifestVersion: ManifestVersion + 1, cpVersion: "2027.01.0"})
	h.cfg.ControlPlaneVersion = "2026.10.3"
	_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	ve := versionErr(t, err)
	if ve.Taken != "2027.01.0" || !strings.Contains(ve.Sentence(), "Flash release 2027.01.0") {
		t.Errorf("error = %+v, sentence %q", ve, ve.Sentence())
	}
}

// TC-872-11: the picker marks a newer-format generation unrestorable and
// names the release its sidecar says took it.
func TestListRestoreCandidatesNamesTheReleaseForANewerFormat(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true, manifestVersion: ManifestVersion + 1, cpVersion: "2027.01.0"})
	resp, err := ListRestoreCandidates(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Candidates) != 1 || len(resp.Candidates[0].Generations) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	g := resp.Candidates[0].Generations[0]
	if g.Restorable {
		t.Fatal("a newer-format generation is restorable")
	}
	if !strings.Contains(g.Problem, "taken on control plane version 2027.01.0: flash release 2027.01.0") || !strings.HasSuffix(g.Problem, ".") {
		t.Errorf("problem = %q", g.Problem)
	}
}

// TC-872-12: an existing inner-manifest refusal (no rasputin.db) now comes
// before the staging directory, so a read-only data dir still yields it.
func TestPrepareRestoreRefusesABadInnerManifestBeforeStaging(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{complete: true, tamper: func(t *testing.T, in []byte, m *Manifest) []byte {
		edited := *m
		edited.Entries = slices.DeleteFunc(slices.Clone(m.Entries), func(e ManifestEntry) bool { return e.Path == "rasputin.db" })
		return rewriteManifestInTar(t, in, &edited)
	}})
	before := dataDirEntries(t, h.dataDir)
	readOnly(t, h.dataDir)
	_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if !errors.Is(err, ErrRestoreArchive) || errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "the manifest names no rasputin.db") {
		t.Fatalf("err = %v, want the no-rasputin.db refusal", err)
	}
	if after := dataDirEntries(t, h.dataDir); !slices.Equal(before, after) {
		t.Errorf("data dir %v became %v", before, after)
	}
}

// TC-872-13: the unseal goroutine has finished by the time PrepareRestore
// returns, on a version refusal and on a staging failure after the manifest
// was read. A goroutine left blocked on the pipe would hold decrypted bytes.
func TestPrepareRestoreEndsTheUnsealOnEveryRefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		running string
		want    func(error) bool
	}{
		{"version refused", "2026.10.3", func(err error) bool { return errors.Is(err, ErrRestoreVersion) }},
		{"staging fails", restoreCPVersion, func(err error) bool { return errors.Is(err, fs.ErrPermission) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestoreHarness(t, generationOpts{complete: true})
			h.cfg.ControlPlaneVersion = tc.running
			var finished <-chan struct{}
			h.cfg.unsealStarted = func(ch <-chan struct{}) { finished = ch }
			readOnly(t, h.dataDir)
			_, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
			if !tc.want(err) {
				t.Fatalf("err = %v", err)
			}
			if finished == nil {
				t.Fatal("the unseal never started, so this proves nothing")
			}
			// No wait: Close waits for the goroutine, so it must already be
			// done. Still open here means it was left blocked on the pipe.
			select {
			case <-finished:
			default:
				t.Fatal("the unseal goroutine is still running after PrepareRestore returned")
			}
		})
	}
}

// RestoreVersionError's Go value stays lowercase for wrapping and logs; the
// sentence is the operator's (F-872-01).
func TestRestoreVersionErrorValueIsNotTheSentence(t *testing.T) {
	for _, e := range []*RestoreVersionError{{}, {Running: "2026.10.2"}, {Taken: "2026.10.1", Running: "2026.10.2"}} {
		v, s := e.Error(), e.Sentence()
		if !strings.HasPrefix(v, "restore version: ") {
			t.Errorf("value %q", v)
		}
		if s[0] < 'A' || s[0] > 'Z' || !strings.HasSuffix(s, ".") || strings.Contains(s, "control-plane") || strings.Contains(s, "controlplane") {
			t.Errorf("sentence %q is not a capitalised sentence with one spelling of control plane", s)
		}
	}
}
