package catalog_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog/floor"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Validator parity (geekdojo/geekdojo-brain#495, gate 8).
//
// The premise the gate exists for: an image reference that reaches `docker
// pull` should be held to ONE rule, whoever produced it. Today it is not —
// a tile from a signed bundle is digest-pinned and checked, while the
// platform sidecars carry tag defaults with environment overrides that pass
// through no validator at all. Two catalogs, two rules, and nothing that says
// so out loud.
//
// This does not close that gap; pinning the platform images by digest per
// architecture is its own work (geekdojo/geekdojo-brain#534). What it does is
// make the gap countable and stop it growing: every place a reference is
// produced is listed in .github/image-sources.tsv with the rule it is held to,
// and a NEW one fails this test until someone has written down which rule
// applies to it.

const sourcesPath = ".github/image-sources.tsv"

var sourcesCols = []string{"id", "path", "symbol", "kind", "status", "cite", "note"}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("%s does not look like the repo root: %v", root, err)
	}
	return root
}

func readSources(t *testing.T, root string) []map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, sourcesPath))
	if err != nil {
		t.Fatalf("read %s: %v", sourcesPath, err)
	}
	var out []map[string]string
	header := false
	for n, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if !header {
			if len(parts) != len(sourcesCols) {
				t.Fatalf("%s:%d: header has %d columns, want %d", sourcesPath, n+1,
					len(parts), len(sourcesCols))
			}
			for i, c := range sourcesCols {
				if parts[i] != c {
					t.Fatalf("%s:%d: column %d is %q, want %q", sourcesPath, n+1, i+1, parts[i], c)
				}
			}
			header = true
			continue
		}
		if len(parts) != len(sourcesCols) {
			t.Fatalf("%s:%d: %d fields, want %d", sourcesPath, n+1, len(parts), len(sourcesCols))
		}
		row := map[string]string{}
		for i, c := range sourcesCols {
			row[c] = parts[i]
		}
		out = append(out, row)
	}
	if !header {
		t.Fatalf("%s: no header row", sourcesPath)
	}
	return out
}

// imageEnvKey matches the environment variables that substitute an image.
var imageEnvKey = regexp.MustCompile(`^RASPUTIN_.*IMAGE$`)

// imageDefault matches an identifier that holds a default image reference.
var imageDefault = regexp.MustCompile(`^default.*Image$`)

// discoverImageSources finds every place in the tree that produces an image
// reference: a default constant and an environment override. Returns
// "path#symbol" -> the variable or constant name.
func discoverImageSources(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor", "ui":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ValueSpec:
				for _, name := range node.Names {
					if imageDefault.MatchString(name.Name) {
						out[rel+"#"+name.Name] = name.Name
					}
				}
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "os" {
					return true
				}
				if sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv" {
					return true
				}
				if len(node.Args) == 0 {
					return true
				}
				lit, ok := node.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				key, uerr := strconv.Unquote(lit.Value)
				if uerr != nil || !imageEnvKey.MatchString(key) {
					return true
				}
				out[rel+"#"+key] = key
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("found no image sources at all — the scan is broken, and a broken scan " +
			"makes this gate pass over every one of them")
	}
	return out
}

func TestImageSourceRegisterCoversEverySource(t *testing.T) {
	root := repoRoot(t)
	found := discoverImageSources(t, root)
	rows := readSources(t, root)

	listed := map[string]bool{}
	ids := map[string]bool{}
	for _, r := range rows {
		key := r["path"] + "#" + r["symbol"]
		if listed[key] {
			t.Errorf("%s: %s is listed twice", sourcesPath, key)
		}
		listed[key] = true
		if ids[r["id"]] {
			t.Errorf("%s: duplicate id %s", sourcesPath, r["id"])
		}
		ids[r["id"]] = true
	}

	var missing []string
	for key := range found {
		if !listed[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d image source(s) are not in %s:\n  %s\n"+
			"Every place an image reference is produced records the rule it is held "+
			"to: `validated` when it passes tileschema.ValidateImagePin, or `pending` "+
			"citing the issue that will make it. A new source that is neither is a "+
			"third rule nobody decided on.",
			len(missing), sourcesPath, strings.Join(missing, "\n  "))
	}

	var stale []string
	for key := range listed {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%s lists %d source(s) that no longer exist: %s. A row that outlives "+
			"its code makes the validated count read higher than it is.",
			sourcesPath, len(stale), strings.Join(stale, ", "))
	}

	validated, pending := 0, 0
	for _, r := range rows {
		switch r["status"] {
		case "validated":
			validated++
		case "pending":
			pending++
			if r["cite"] == "" {
				t.Errorf("%s: %s is pending with no issue cited", sourcesPath, r["id"])
			}
		default:
			t.Errorf("%s: %s has status %q; want validated or pending",
				sourcesPath, r["id"], r["status"])
		}
		if strings.TrimSpace(r["note"]) == "" {
			t.Errorf("%s: %s has no note saying what produces the reference", sourcesPath, r["id"])
		}
	}
	t.Logf("image sources: %d · %d pass the pin validator · %d owed",
		len(rows), validated, pending)
}

// The embedded floor is the one image set that already passes the validator
// every signed bundle's tiles pass. It ships in every image, so a hand-edited
// or stale floor reaches every cluster built from this commit.
func TestFloorPassesTheSameValidatorASignedBundleDoes(t *testing.T) {
	b, err := floor.Load()
	if err != nil {
		t.Fatalf("floor.Load: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("the embedded floor does not pass Bundle.Validate: %v", err)
	}

	// Validate() reaches the pin check only for installable tiles, so the
	// floor's images are checked directly here too: a tile that stopped being
	// installable would otherwise drop out of the check silently.
	var checked int
	for _, bt := range b.Tiles {
		for _, img := range bt.Safety.Images {
			checked++
			if err := tileschema.ValidateImagePin(img); err != nil {
				t.Errorf("floor tile %q image %q: %v", bt.Tile.ID, img, err)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no floor tile named an image, so this test checked nothing")
	}
	t.Logf("floor: %d image reference(s) digest-pinned", checked)
}

func TestValidateImagePin(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for _, tc := range []struct {
		name string
		img  string
		ok   bool
	}{
		{"a digest-pinned reference", "ghcr.io/x/y@" + digest, true},
		{"a tag beside the digest is cosmetic", "ghcr.io/x/y:v1@" + digest, true},
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"a tag alone", "ghcr.io/x/y:v1.2.3", false},
		{"latest", "ghcr.io/x/y:latest", false},
		{"no tag at all", "ghcr.io/x/y", false},
		{"a digest that is not sha256", "ghcr.io/x/y@sha512:" + strings.Repeat("a", 128), false},
		{"a short digest", "ghcr.io/x/y@sha256:" + strings.Repeat("a", 63), false},
		{"a long digest", "ghcr.io/x/y@sha256:" + strings.Repeat("a", 65), false},
		{"upper-case hex", "ghcr.io/x/y@sha256:" + strings.Repeat("A", 64), false},
		{"non-hex", "ghcr.io/x/y@sha256:" + strings.Repeat("z", 64), false},
		{"no name before the digest", "@" + digest, false},
		{"only whitespace before the digest", "  @" + digest, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tileschema.ValidateImagePin(tc.img)
			if tc.ok && err != nil {
				t.Fatalf("ValidateImagePin(%q) = %v, want nil", tc.img, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("ValidateImagePin(%q) = nil; a reference that is not pinned to "+
					"an exact digest does not describe a fixed stack", tc.img)
			}
		})
	}
}
