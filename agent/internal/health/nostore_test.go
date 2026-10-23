package health

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TC-767-13: the agent has no path to the secret store. A control plane's
// update of itself is gated on the store by the api, which asks its own store
// (geekdojo/geekdojo-brain#767); the agent must never become a second store
// client. This reads every non-test Go file in the agent module, comments
// included, and fails on the store's address, its API paths, its vendor name
// or the api's store settings.
//
// If this fails on code you just wrote, the store check belongs in the api.
func TestTheAgentHasNoPathToTheSecretStore(t *testing.T) {
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`:8200`),
		regexp.MustCompile(`"/v1/sys/`),
		regexp.MustCompile(`"/v1/auth/`),
		regexp.MustCompile(`(?i)openbao`),
		regexp.MustCompile(`RASPUTIN_SECRETSTORE_`),
	}

	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot find the agent module root from %s: %v", root, err)
	}
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(src), "\n") {
			for _, re := range forbidden {
				if re.MatchString(line) {
					t.Errorf("%s:%d reaches for the secret store (%s):\n\t%s",
						filepath.ToSlash(rel), i+1, re, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// A walk that sees nothing passes nothing. The module holds well over a
	// hundred non-test files; 20 is the floor onereboot_test.go uses.
	if checked < 20 {
		t.Fatalf("only %d files were checked; the walk is not seeing the agent module", checked)
	}
}
