package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// TC-981-16: the real package tree, its migrations.lock and All pass, in the
// ordinary go test the backend CI job runs.
func TestLock(t *testing.T) {
	lock, err := os.ReadFile("migrations.lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckLock(os.DirFS("."), lock, All); err != nil {
		t.Fatal(err)
	}
}

// fixtureApply is defined in this file, so it is never inside a locked
// migration file.
func fixtureApply(context.Context, Admin, string) error { return nil }

func sum(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

// TC-981-16: each way a shipped migration can escape the lock fails, naming
// the migration and saying "restore it and add a new migration".
func TestCheckLock_Fails(t *testing.T) {
	const body = "package migrations\n"
	one := []Migration{{ID: 1, Name: "first", Apply: fixtureApply}}
	for _, c := range []struct {
		name  string
		tree  fstest.MapFS
		lock  string
		all   []Migration
		names string
	}{
		{"an edited file",
			fstest.MapFS{"m0001_first.go": {Data: []byte(body + "// edited\n")}},
			"1 m0001_first.go sha256=" + sum(body), one, "m0001_first.go"},
		{"a file with no lock line",
			fstest.MapFS{"m0001_first.go": {Data: []byte(body)}},
			"", nil, "m0001_first.go"},
		{"a lock line with no file",
			fstest.MapFS{},
			"1 m0001_first.go sha256=" + sum(body), one, "m0001_first.go"},
		{"an All entry with no lock line",
			fstest.MapFS{},
			"", one, "[1]"},
		{"an All entry whose Apply is outside its locked file",
			fstest.MapFS{"m0001_first.go": {Data: []byte(body)}},
			"1 m0001_first.go sha256=" + sum(body), one, "migration 1 (first)"},
		{"a malformed lock line",
			fstest.MapFS{},
			"1 m0001_first.go", nil, "line 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := CheckLock(c.tree, []byte(c.lock), c.all)
			if err == nil {
				t.Fatal("CheckLock passed")
			}
			if c.name != "a malformed lock line" && !strings.Contains(err.Error(), "restore it and add a new migration") {
				t.Errorf("error %q does not say to restore it and add a new migration", err)
			}
			if !strings.Contains(err.Error(), c.names) {
				t.Errorf("error %q does not name %s", err, c.names)
			}
		})
	}
	// Test files and other files are not migrations.
	tree := fstest.MapFS{"m0001_first_test.go": {Data: []byte(body)}, "runner.go": {Data: []byte(body)}}
	if err := CheckLock(tree, nil, nil); err != nil {
		t.Errorf("non-migration files: %v", err)
	}
}
