//go:build unix

package backupxfer

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
)

// The extraction discipline for app volumes, exercised the way the restore
// exercises it: a tar built here, unpacked beneath a directory opened
// through fsat, and every hostile member the package doc promises to refuse
// refused with the staging tree named and nothing outside it touched.

type tarEntry struct {
	name string
	typ  byte
	body string
	link string
	mode int64
}

func buildTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link,
			ModTime: time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC), Format: tar.FormatPAX}
		if hdr.Mode == 0 {
			hdr.Mode = 0o644
		}
		if e.typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func stagingRoot(t *testing.T) (string, *os.File) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".rasputin-restore-x")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := fsat.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return dir, root
}

func TestUnpackPutsAVolumeBackWithItsShape(t *testing.T) {
	tarBytes := buildTar(t,
		tarEntry{name: "db/", typ: tar.TypeDir, mode: 0o750},
		tarEntry{name: "db/db.sqlite3", typ: tar.TypeReg, body: "SQLite format 3\x00rows", mode: 0o600},
		tarEntry{name: "config.json", typ: tar.TypeReg, body: `{"a":1}`, mode: 0o644},
		tarEntry{name: "attachments/2026/", typ: tar.TypeDir, mode: 0o755},
		tarEntry{name: "attachments/2026/a file with spaces.bin", typ: tar.TypeReg, body: strings.Repeat("x", 70000), mode: 0o640},
		tarEntry{name: "empty.txt", typ: tar.TypeReg, body: "", mode: 0o644},
	)
	dir, root := stagingRoot(t)
	res, err := Unpack(root, bytes.NewReader(tarBytes), UnpackBounds{MaxBytes: uint64(len(tarBytes))})
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if res.Files != 4 || res.Dirs != 2 || res.Bytes != uint64(20+7+70000) {
		t.Fatalf("result %+v", res)
	}
	sum := sha256.Sum256(tarBytes)
	if res.Digest != hex.EncodeToString(sum[:]) || res.StreamBytes != uint64(len(tarBytes)) {
		t.Fatalf("digest/length over the stream: %s/%d, want %x/%d", res.Digest, res.StreamBytes, sum, len(tarBytes))
	}
	if res.OwnershipApplied {
		t.Fatal("ownership was not asked for and is reported applied")
	}
	got, err := os.ReadFile(filepath.Join(dir, "db", "db.sqlite3"))
	if err != nil || string(got) != "SQLite format 3\x00rows" {
		t.Fatalf("db.sqlite3: %q %v", got, err)
	}
	st, err := os.Stat(filepath.Join(dir, "db", "db.sqlite3"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("db.sqlite3 mode %v %v", st, err)
	}
	if !st.ModTime().Equal(time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("db.sqlite3 mtime %v, want the header's", st.ModTime())
	}
	if st, err := os.Stat(filepath.Join(dir, "db")); err != nil || !st.IsDir() || st.Mode().Perm() != 0o750 {
		t.Fatalf("db/ %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Join(dir, "attachments", "2026", "a file with spaces.bin")); err != nil || st.Size() != 70000 || st.Mode().Perm() != 0o640 {
		t.Fatalf("spaces file %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Join(dir, "empty.txt")); err != nil || st.Size() != 0 {
		t.Fatalf("empty.txt %v %v", st, err)
	}
}

// A file whose parent directory has no entry of its own — the stager always
// writes one, but a tar is a tar — is created beneath directories made on
// the way down.
func TestUnpackCreatesMissingParents(t *testing.T) {
	tarBytes := buildTar(t, tarEntry{name: "a/b/c/deep.txt", typ: tar.TypeReg, body: "deep"})
	dir, root := stagingRoot(t)
	if _, err := Unpack(root, bytes.NewReader(tarBytes), UnpackBounds{MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "a", "b", "c", "deep.txt")); err != nil || string(got) != "deep" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestUnpackRefusesHostileMembers(t *testing.T) {
	cases := []struct {
		name  string
		tar   []byte
		bound uint64
		want  string
	}{
		{"dot-dot", buildTar(t, tarEntry{name: "../outside", typ: tar.TypeReg, body: "x"}), 1 << 20, "not beneath"},
		{"dot-dot inside", buildTar(t, tarEntry{name: "a/../../outside", typ: tar.TypeReg, body: "x"}), 1 << 20, "not beneath"},
		{"absolute", buildTar(t, tarEntry{name: "/etc/passwd", typ: tar.TypeReg, body: "x"}), 1 << 20, "not beneath"},
		{"empty component", buildTar(t, tarEntry{name: "a//b", typ: tar.TypeReg, body: "x"}), 1 << 20, "plain descent"},
		{"dot component", buildTar(t, tarEntry{name: "./a", typ: tar.TypeReg, body: "x"}), 1 << 20, "plain descent"},
		{"symlink", buildTar(t, tarEntry{name: "link", typ: tar.TypeSymlink, link: "/etc/shadow"}), 1 << 20, "symlink"},
		{"hard link", buildTar(t, tarEntry{name: "a", typ: tar.TypeReg, body: "x"}, tarEntry{name: "b", typ: tar.TypeLink, link: "a"}), 1 << 20, "not a regular file or a directory"},
		{"fifo", buildTar(t, tarEntry{name: "p", typ: tar.TypeFifo}), 1 << 20, "not a regular file or a directory"},
		{"duplicate", buildTar(t, tarEntry{name: "a", typ: tar.TypeReg, body: "1"}, tarEntry{name: "a", typ: tar.TypeReg, body: "2"}), 1 << 20, "twice"},
		{"over the byte bound", buildTar(t, tarEntry{name: "big", typ: tar.TypeReg, body: strings.Repeat("y", 4096)}), 4095, "past the 4095 bytes"},
		{"not a tar", []byte("this is not a tar archive at all, not even close to one block"), 1 << 20, "reading the tar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, root := stagingRoot(t)
			_, err := Unpack(root, bytes.NewReader(c.tar), UnpackBounds{MaxBytes: c.bound})
			if err == nil {
				t.Fatal("unpacked")
			}
			if !errors.Is(err, ErrUnpackRefused) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want ErrUnpackRefused mentioning %q", err, c.want)
			}
			// Nothing escaped the staging directory: its parent holds only it.
			ents, _ := os.ReadDir(filepath.Dir(dir))
			if len(ents) != 1 || ents[0].Name() != filepath.Base(dir) {
				t.Fatalf("the staging directory's parent holds %v", ents)
			}
			for _, name := range []string{"link", "outside", "passwd"} {
				if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
					t.Fatalf("%s was created", name)
				}
			}
		})
	}
}

func TestUnpackRefusesTooManyEntries(t *testing.T) {
	var entries []tarEntry
	for i := 0; i < 12; i++ {
		entries = append(entries, tarEntry{name: "f" + strings.Repeat("x", i), typ: tar.TypeReg, body: "x"})
	}
	_, root := stagingRoot(t)
	_, err := Unpack(root, bytes.NewReader(buildTar(t, entries...)), UnpackBounds{MaxBytes: 1 << 20, MaxEntries: 10})
	if err == nil || !strings.Contains(err.Error(), "more than 10 members") {
		t.Fatalf("err = %v", err)
	}
}

// A member that ends early — the stream cut mid-body, which is what a source
// going away looks like from here — is a refusal, not a short file.
func TestUnpackRefusesATruncatedStream(t *testing.T) {
	tarBytes := buildTar(t, tarEntry{name: "a", typ: tar.TypeReg, body: strings.Repeat("z", 3000)})
	_, root := stagingRoot(t)
	_, err := Unpack(root, bytes.NewReader(tarBytes[:1024+1000]), UnpackBounds{MaxBytes: 1 << 20})
	if err == nil || !errors.Is(err, ErrUnpackRefused) {
		t.Fatalf("err = %v", err)
	}
}

// A planted symlink in the staging tree — something that got there between
// two members — is not followed: the create is O_EXCL|O_NOFOLLOW and refuses
// the name.
func TestUnpackNeverWritesThroughAPlantedSymlink(t *testing.T) {
	dir, root := stagingRoot(t)
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(dir, "d")); err != nil {
		t.Fatal(err)
	}
	for _, tb := range [][]byte{
		buildTar(t, tarEntry{name: "config.json", typ: tar.TypeReg, body: "replaced"}),
		buildTar(t, tarEntry{name: "d/victim", typ: tar.TypeReg, body: "replaced"}),
	} {
		if _, err := Unpack(root, bytes.NewReader(tb), UnpackBounds{MaxBytes: 1 << 20}); err == nil {
			t.Fatal("wrote through a symlink")
		}
	}
	if got, _ := os.ReadFile(outside); string(got) != "original" {
		t.Fatalf("the file outside the staging tree was written: %q", got)
	}
}
