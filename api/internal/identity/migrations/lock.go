package migrations

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// migrationFile is a shipped migration's file name.
var migrationFile = regexp.MustCompile(`^m[0-9]{4}_[a-z0-9_]+\.go$`)

// restore is the fix every lock failure names: a shipped migration is never
// edited.
const restore = "restore it and add a new migration"

// lockLine is one migrations.lock line.
type lockLine struct {
	id   int
	file string
	sum  string
}

// CheckLock checks the package directory fsys and the lock bytes against
// all. Each shipped mNNNN_*.go file (not a test file) has exactly one
// "<id> <file> sha256=<hex>" line. It fails, naming the migration, on an
// edited file, a file with no line, a line with no file, lock IDs that differ
// from all's, and an all entry whose Apply is defined outside its locked
// file. Blank lines and # comments are ignored.
func CheckLock(fsys fs.FS, lock []byte, all []Migration) error {
	lines, err := parseLock(lock)
	if err != nil {
		return err
	}
	byFile := map[string]lockLine{}
	for _, l := range lines {
		if _, dup := byFile[l.file]; dup {
			return fmt.Errorf("migrations.lock names %s twice: %s", l.file, restore)
		}
		byFile[l.file] = l
	}
	ents, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("migrations: read the package directory: %w", err)
	}
	files := map[string]bool{}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, "_test.go") || !migrationFile.MatchString(name) {
			continue
		}
		files[name] = true
		l, ok := byFile[name]
		if !ok {
			return fmt.Errorf("migration file %s has no line in migrations.lock: %s", name, restore)
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("migration %d (%s) could not be read: %w", l.id, name, err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != l.sum {
			return fmt.Errorf("migration %d (%s) was edited after it shipped: %s", l.id, name, restore)
		}
	}
	for _, l := range lines {
		if !files[l.file] {
			return fmt.Errorf("migration %d's file %s, named in migrations.lock, is missing: %s", l.id, l.file, restore)
		}
	}
	lockIDs := make([]int, len(lines))
	for i, l := range lines {
		lockIDs[i] = l.id
	}
	allIDs := make([]int, len(all))
	for i, m := range all {
		allIDs[i] = m.ID
	}
	if !slices.Equal(lockIDs, allIDs) {
		return fmt.Errorf("migrations.lock's migration IDs %v differ from All's %v: %s", lockIDs, allIDs, restore)
	}
	for i, m := range all {
		want := lines[i].file
		if got := applyFile(m.Apply); got != want {
			return fmt.Errorf("migration %d (%s): its Apply is defined in %q, not in its locked file %s: %s", m.ID, m.Name, got, want, restore)
		}
	}
	return nil
}

// applyFile is the base name of the file that defines fn, "" for none.
func applyFile(fn any) string {
	v := reflect.ValueOf(fn)
	if !v.IsValid() || v.Kind() != reflect.Func || v.IsNil() {
		return ""
	}
	f := runtime.FuncForPC(v.Pointer())
	if f == nil {
		return ""
	}
	file, _ := f.FileLine(f.Entry())
	return path.Base(strings.ReplaceAll(file, "\\", "/"))
}

// parseLock reads the lock's lines in order. A line that is not blank, a #
// comment or "<id> <file> sha256=<64 hex>" is an error.
func parseLock(lock []byte) ([]lockLine, error) {
	var out []lockLine
	sc := bufio.NewScanner(bytes.NewReader(lock))
	n := 0
	for sc.Scan() {
		n++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 || !strings.HasPrefix(fields[2], "sha256=") {
			return nil, fmt.Errorf("migrations.lock line %d is not \"<id> <file> sha256=<hex>\"", n)
		}
		id, err := strconv.Atoi(fields[0])
		sum := strings.TrimPrefix(fields[2], "sha256=")
		if _, herr := hex.DecodeString(sum); err != nil || herr != nil || len(sum) != 64 || !migrationFile.MatchString(fields[1]) {
			return nil, fmt.Errorf("migrations.lock line %d is not \"<id> <file> sha256=<hex>\"", n)
		}
		out = append(out, lockLine{id: id, file: fields[1], sum: sum})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("migrations: read migrations.lock: %w", err)
	}
	return out, nil
}
