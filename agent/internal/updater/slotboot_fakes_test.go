package updater

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeESPDevice is the device the fake media names in its errors, the way
// OpenWrtBootMedia names the real one.
const fakeESPDevice = "/dev/fake-esp"

// fakeMedia is a BootMedia over plain directories: the ESP is espRoot, and each
// slot device maps to a directory standing in for its mounted squashfs.
type fakeMedia struct {
	mu        sync.Mutex
	espRoot   string
	slotRoots map[string]string
	calls     *callLog

	// mountErr, when set, fails ESP mounts before fn runs: every mount from the
	// mountErrFrom-th (1-based; 0 means from the first).
	mountErr     error
	mountErrFrom int
	// openSlotErr fails OpenSlot; releaseErr fails the slot's release.
	openSlotErr error
	releaseErr  error
	// umountErrOn fails the umount of the n-th ESP mount (1-based), after fn ran.
	umountErrOn int
	// beforeFn runs before fn on the n-th ESP mount (1-based), e.g. to corrupt a
	// staged file "on the disk" between the write and the read-back.
	beforeFn map[int]func(root string)

	espMounts int
}

func (m *fakeMedia) WithESP(fn func(root string) error) error {
	m.mu.Lock()
	m.espMounts++
	n := m.espMounts
	m.mu.Unlock()
	m.calls.add("WithESP")
	if m.mountErr != nil && n >= m.mountErrFrom {
		return m.mountErr
	}
	if h := m.beforeFn[n]; h != nil {
		h(m.espRoot)
	}
	var fnErr error
	if err := fn(m.espRoot); err != nil {
		fnErr = errors.Join(errors.New("ESP "+fakeESPDevice), err)
	}
	if m.umountErrOn == n {
		return errors.Join(fnErr, errors.New("umount "+fakeESPDevice+": device busy"))
	}
	return fnErr
}

func (m *fakeMedia) OpenSlot(dev string) (string, func() error, error) {
	m.calls.add("OpenSlot")
	if m.openSlotErr != nil {
		return "", nil, m.openSlotErr
	}
	root, ok := m.slotRoots[dev]
	if !ok {
		return "", nil, errors.New("fake media: no slot root for " + dev)
	}
	return root, func() error {
		m.calls.add("release")
		return m.releaseErr
	}, nil
}

// callLog records collaborator calls, with an optional snapshot taken at each.
type callLog struct {
	mu    sync.Mutex
	names []string
	snap  func() string
	snaps []string
}

func (c *callLog) add(name string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.names = append(c.names, name)
	if c.snap != nil {
		c.snaps = append(c.snaps, c.snap())
	}
}

type fakeMods struct {
	loaded []string
	failOn string
}

func (f *fakeMods) Load(path string) error {
	if f.failOn != "" && filepath.Base(path) == f.failOn {
		return errors.New("finit_module: exec format error")
	}
	f.loaded = append(f.loaded, path)
	return nil
}

type fakeFS struct {
	list string
	err  error
}

func (f fakeFS) Filesystems() (string, error) { return f.list, f.err }

const procFilesystemsWithVFAT = "nodev\tsysfs\nnodev\ttmpfs\n\tsquashfs\n\tvfat\n\text4\n"
const procFilesystemsNoVFAT = "nodev\tsysfs\nnodev\ttmpfs\n\tsquashfs\n\text4\n"

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// logCapture is a JSON slog handler into a buffer, read back as records.
type logCapture struct{ buf bytes.Buffer }

func (l *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&l.buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (l *logCapture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

// newTestAB is NewOpenWrtABBackend with inert collaborators, for tests of code
// that never reaches the ESP or the module loader.
func newTestAB(stateDir string, trust TrustSource) (*OpenWrtABBackend, error) {
	return NewOpenWrtABBackend(stateDir, trust, &fakeMedia{}, &fakeMods{}, fakeFS{list: procFilesystemsWithVFAT}, discardLogger())
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeGrubenvFile(t *testing.T, path string, kv map[string]string) {
	t.Helper()
	block, err := encodeGrubenv(kv, grubenvSize)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, block)
}

// treeHash hashes every file under root except those whose root-relative path
// is in skip.
func treeHash(t *testing.T, root string, skip ...string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		for _, s := range skip {
			if rel == s {
				return nil
			}
		}
		if d.IsDir() {
			lines = append(lines, rel+"/")
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines = append(lines, rel+" "+shaOf(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
