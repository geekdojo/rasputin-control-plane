package sealrotate

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	// KeyBytes is a seal key's length: 32 bytes, as #803 mints.
	KeyBytes = 32
	// SealKeyName and FragmentName are the two files #803 writes in the seal
	// directory; RotationDirName is the directory the new key is staged in,
	// which openbao.service loads as the seal-rotation credential directory.
	SealKeyName     = "seal-key"
	FragmentName    = "seal.hcl"
	RotationDirName = "rotation"

	// ProductionSealDir is the seal directory on a control plane, and
	// ProductionCredDir where systemd copies its credentials for the store.
	ProductionSealDir = "/var/lib/rasputin/openbao-seal"
	ProductionCredDir = "/run/credentials/openbao.service"
	// rotationCredPrefix is how systemd names a file of the seal-rotation
	// directory credential: seal-rotation_<file name>.
	rotationCredPrefix = "seal-rotation_"
)

// Paths says where the seal files are on disk and where the store reads
// them. The fragment names keys by the store's path (CredDir), never by the
// seal directory.
type Paths struct {
	// SealDir holds seal-key, seal.hcl and rotation/.
	SealDir string
	// CredDir is where the store reads seal-key: the fragment's current_key
	// in the Clean shape is CredDir/seal-key.
	CredDir string
	// RotationCred is where the store reads rotation/<id>.
	RotationCred func(KeyID) string
}

// ProductionPaths is the control plane's layout: openbao.service's
// LoadCredential= lines copy seal-key and every file of rotation/ under
// ProductionCredDir.
func ProductionPaths() Paths {
	return Paths{
		SealDir: ProductionSealDir,
		CredDir: ProductionCredDir,
		RotationCred: func(id KeyID) string {
			return filepath.Join(ProductionCredDir, rotationCredPrefix+string(id))
		},
	}
}

func (p Paths) sealKeyCred() string { return filepath.Join(p.CredDir, SealKeyName) }
func (p Paths) sealKey() string     { return filepath.Join(p.SealDir, SealKeyName) }
func (p Paths) fragment() string    { return filepath.Join(p.SealDir, FragmentName) }
func (p Paths) rotationDir() string { return filepath.Join(p.SealDir, RotationDirName) }
func (p Paths) rotationKey(id KeyID) string {
	return filepath.Join(p.rotationDir(), string(id))
}

// Resume is what a run does with the tree it finds.
type Resume int

// The resume actions, one per recognised tree.
const (
	// Fresh: Clean and rotation/ empty; a new key is minted.
	Fresh Resume = iota + 1
	// CleanUp: Clean with leftovers in rotation/, which are removed.
	CleanUp
	// RewrapFirst: Staged; the running store, if it answers 200, is
	// re-wrapped, then restarted on Staged and re-wrapped again, then verify
	// and settle.
	RewrapFirst
	// VerifyThenSettle: Verify; the new key alone is proven, then settled.
	VerifyThenSettle
)

// String names the action in logs and step results.
func (r Resume) String() string {
	switch r {
	case Fresh:
		return "fresh"
	case CleanUp:
		return "clean-up"
	case RewrapFirst:
		return "re-wrap-first"
	case VerifyThenSettle:
		return "verify-then-settle"
	}
	return "unknown"
}

// Tree is the seal directory as State read it.
type Tree struct {
	Fragment Fragment
	// Leftovers are the names in rotation/ the fragment does not name. Only a
	// Clean tree may have any.
	Leftovers []string
	Resume    Resume
}

// Files is the seal directory's model service: every read and write of the
// seal files, and nothing else (ARCH-BL). It makes no decision about a
// rotation; State only says which tree is on disk.
type Files struct {
	p Paths
	// newBuf allocates the read-back buffer; a test keeps a reference to
	// check it is zeroed (F-830-06). NewFiles sets make.
	newBuf func(n int) []byte
}

// NewFiles checks p and returns Files. It does no I/O.
func NewFiles(p Paths) (*Files, error) {
	switch {
	case p.SealDir == "":
		return nil, errors.New("sealrotate: Paths.SealDir is empty")
	case p.CredDir == "":
		return nil, errors.New("sealrotate: Paths.CredDir is empty")
	case p.RotationCred == nil:
		return nil, errors.New("sealrotate: Paths.RotationCred is nil")
	}
	return &Files{p: p, newBuf: func(n int) []byte { return make([]byte, n) }}, nil
}

// State reads the seal directory and returns its tree, or an error naming
// what is not recognised. It changes nothing. Key files are checked by Lstat
// alone, for type and size, and never opened (F-830-06).
func (f *Files) State() (Tree, error) {
	b, err := os.ReadFile(f.p.fragment())
	if err != nil {
		return Tree{}, fmt.Errorf("sealrotate: read the seal fragment: %w", err)
	}
	frag, err := parseFragment(f.p, b)
	if err != nil {
		return Tree{}, err
	}
	if err := checkKey(f.p.sealKey()); err != nil {
		return Tree{}, err
	}
	names, err := f.rotationNames()
	if err != nil {
		return Tree{}, err
	}
	t := Tree{Fragment: frag}
	switch frag.Shape {
	case Clean:
		t.Leftovers = names
		t.Resume = Fresh
		if len(names) > 0 {
			t.Resume = CleanUp
		}
		return t, nil
	case Staged:
		t.Resume = RewrapFirst
	case Verify:
		t.Resume = VerifyThenSettle
	}
	if len(names) != 1 || names[0] != string(frag.Current) {
		return Tree{}, fmt.Errorf("sealrotate: the %s fragment names rotation/%s, and rotation/ holds %d entries %v",
			frag.Shape, frag.Current, len(names), names)
	}
	if err := checkKey(f.p.rotationKey(frag.Current)); err != nil {
		return Tree{}, err
	}
	return t, nil
}

// checkKey refuses anything at path but a regular 32-byte file. It stats and
// never reads.
func checkKey(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("sealrotate: seal key %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("sealrotate: seal key %s is not a regular file", path)
	}
	if fi.Size() != KeyBytes {
		return fmt.Errorf("sealrotate: seal key %s is %d bytes, not %d", path, fi.Size(), KeyBytes)
	}
	return nil
}

// rotationNames lists rotation/, sorted. A missing directory is an error:
// tmpfiles makes it on every boot, and the store unit fails without it.
func (f *Files) rotationNames() ([]string, error) {
	es, err := os.ReadDir(f.p.rotationDir())
	if err != nil {
		return nil, fmt.Errorf("sealrotate: list %s: %w", f.p.rotationDir(), err)
	}
	names := make([]string, 0, len(es))
	for _, e := range es {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// writeKey is the one place a seal key's bytes leave a secret.Value: into a
// 0600 file through atrest. The caller destroys key.
func (f *Files) writeKey(path string, key secret.Value) error {
	if key.Len() != KeyBytes {
		return fmt.Errorf("sealrotate: a seal key is %d bytes, not %d", key.Len(), KeyBytes)
	}
	return atrest.WriteSecretFile(path, key.Reveal())
}

// WriteRotationKey writes key as rotation/<id>.
func (f *Files) WriteRotationKey(id KeyID, key secret.Value) error {
	return f.writeKey(f.p.rotationKey(id), key)
}

// WriteSealKey replaces seal-key with key.
func (f *Files) WriteSealKey(key secret.Value) error {
	return f.writeKey(f.p.sealKey(), key)
}

// ReadRotationKey reads rotation/<id> into a secret.Value. The read buffer is
// zeroed before it returns (F-830-06); the caller destroys the Value.
func (f *Files) ReadRotationKey(id KeyID) (secret.Value, error) {
	return f.readKey(f.p.rotationKey(id))
}

// readKey reads exactly KeyBytes from path into a Value, zeroing its buffer.
func (f *Files) readKey(path string) (secret.Value, error) {
	fh, err := os.Open(path)
	if err != nil {
		return secret.Value{}, fmt.Errorf("sealrotate: open %s: %w", path, err)
	}
	defer func() { _ = fh.Close() }() // read-only: a close error loses nothing
	buf := f.newBuf(KeyBytes + 1)
	defer clear(buf)
	// One byte more than a key is asked for, so a longer file is told apart
	// from an exact one: exactly KeyBytes ends in ErrUnexpectedEOF.
	n, err := io.ReadFull(fh, buf)
	switch {
	case n == KeyBytes && errors.Is(err, io.ErrUnexpectedEOF):
	case err == nil:
		return secret.Value{}, fmt.Errorf("sealrotate: %s holds more than %d bytes", path, KeyBytes)
	default:
		return secret.Value{}, fmt.Errorf("sealrotate: read %s: %d of %d bytes: %w", path, n, KeyBytes, err)
	}
	return secret.New(buf[:KeyBytes]), nil
}

// WriteFragment atomically replaces seal.hcl with frag. The fragment holds no
// secret; it is written 0600 root as #803 writes it.
func (f *Files) WriteFragment(frag Fragment) error {
	b, err := frag.render(f.p)
	if err != nil {
		return err
	}
	return atrest.WriteSecretFile(f.p.fragment(), b)
}

// RemoveRotation removes every entry of rotation/, leaving the directory.
func (f *Files) RemoveRotation() error {
	names, err := f.rotationNames()
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		if err := os.Remove(filepath.Join(f.p.rotationDir(), n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("sealrotate: empty %s: %w", f.p.rotationDir(), err)
	}
	return nil
}
