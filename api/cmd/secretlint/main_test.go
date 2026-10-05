package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const header = "path\tsymbol\treason\n"

const secretModule = "github.com/geekdojo/rasputin-control-plane/secret"

// secretModuleDir asks the go command where this module resolves the secret
// module from, so the answer follows the module's own go.mod (or go.work)
// instead of assuming a sibling directory on disk: a module copied alone, as
// mutation testing does, has no ../../../secret. It fails the test, never
// skips it, when the module cannot be resolved.
func secretModuleDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", secretModule).Output()
	if err != nil {
		var stderr []byte
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = ee.Stderr
		}
		t.Fatalf("resolve %s: %v: %s", secretModule, err, stderr)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatalf("resolve %s: go list returned no directory", secretModule)
	}
	return dir
}

// fixture writes a module at a temp dir that requires the real secret module
// by a local replace, with the given files, and returns its root. GOWORK is
// off so the fixture is its own module, not a member of this workspace.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	secretDir := secretModuleDir(t)
	t.Setenv("GOWORK", "off")
	root := t.TempDir()
	files["go.mod"] = "module example.com/fx\n\ngo 1.26\n\nrequire github.com/geekdojo/rasputin-control-plane/secret v0.0.0\n\n" +
		"replace github.com/geekdojo/rasputin-control-plane/secret => " + secretDir + "\n"
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const revealer = `package a

import "github.com/geekdojo/rasputin-control-plane/secret"

type T struct{ k secret.Value }

func (t *T) Method() []byte { return t.k.Reveal() }
`

const reflector = `package a

import (
	"reflect"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

type T struct{ k secret.Value }

func (t *T) Method() reflect.Value { return reflect.ValueOf(t) }
`

const clean = `package b

func F() int { return 1 }
`

func runFixture(t *testing.T, root string, patterns []string, allow string) (int, string) {
	t.Helper()
	allowPath := filepath.Join(root, "allow.tsv")
	if allow != "" {
		if err := os.WriteFile(allowPath, []byte(allow), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	code := run(root, patterns, allowPath, &out)
	return code, out.String()
}

// TC-732-14 (a): one allowlisted Reveal passes.
func TestRun_AllowlistedRevealPasses(t *testing.T) {
	root := fixture(t, map[string]string{"a/a.go": revealer})
	code, out := runFixture(t, root, []string{"./..."}, header+"a/a.go\tT.Method\tthe one way out\n")
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "1 Reveal site(s), all allowlisted") {
		t.Fatalf("no pass summary:\n%s", out)
	}
}

// TC-732-14 (b): an unlisted Reveal fails with path:line, rule and symbol.
func TestRun_UnlistedRevealFails(t *testing.T) {
	root := fixture(t, map[string]string{"a/a.go": revealer})
	code, out := runFixture(t, root, []string{"./..."}, header)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "a/a.go:7: SL01 T.Method: ") {
		t.Fatalf("no path:line: SL01 T.Method finding:\n%s", out)
	}
}

// TC-732-14 (c): an SL02 site fails even when a row names its path and
// symbol: SL02 has no allowlist.
func TestRun_SL02FailsDespiteARow(t *testing.T) {
	root := fixture(t, map[string]string{"a/a.go": reflector})
	code, out := runFixture(t, root, []string{"./..."}, header+"a/a.go\tT.Method\tattempted allowance\n")
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "SL02 T.Method") {
		t.Fatalf("no SL02 finding:\n%s", out)
	}
}

// TC-732-14 (d): a row that matches no site fails and is named.
func TestRun_StaleRowFails(t *testing.T) {
	root := fixture(t, map[string]string{"b/b.go": clean})
	code, out := runFixture(t, root, []string{"./..."}, header+"b/b.go\tGone.Method\tit used to\n")
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "b/b.go\tGone.Method matches no Reveal site") {
		t.Fatalf("the stale row is not named:\n%s", out)
	}
}

// TC-732-14 (e), (f), (g): a malformed or missing allowlist fails.
func TestRun_BadAllowlistFails(t *testing.T) {
	cases := map[string]string{
		"wrong column name": "path\tsym\treason\n",
		"wrong field count": header + "b/b.go\tF\n",
		"missing file":      "",
	}
	for name, allow := range cases {
		root := fixture(t, map[string]string{"b/b.go": clean})
		code, out := runFixture(t, root, []string{"./..."}, allow)
		if code != 1 {
			t.Errorf("%s: exit %d, want 1:\n%s", name, code, out)
		}
		if !strings.Contains(out, "allowlist") {
			t.Errorf("%s: output does not name the allowlist:\n%s", name, out)
		}
	}
}

// TC-732-14 (h): a package that does not type-check fails, with no pass.
func TestRun_TypeErrorFails(t *testing.T) {
	root := fixture(t, map[string]string{"b/b.go": "package b\n\nfunc F() int { return \"not an int\" }\n"})
	code, out := runFixture(t, root, []string{"./..."}, header)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	if strings.Contains(out, "all allowlisted") {
		t.Fatalf("a tree that did not type-check printed a pass:\n%s", out)
	}
}

// TC-732-14 (i): no patterns fails rather than linting nothing.
func TestRun_EmptyPatternsFail(t *testing.T) {
	root := fixture(t, map[string]string{"b/b.go": clean})
	code, out := runFixture(t, root, nil, header)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
}

// TC-732-14 (j): every pattern is linted: an unlisted Reveal in the second
// of two packages is reported.
func TestRun_EveryPatternIsLinted(t *testing.T) {
	root := fixture(t, map[string]string{"b/b.go": clean, "a/a.go": revealer})
	code, out := runFixture(t, root, []string{"./b", "./a"}, header)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "a/a.go:7: SL01 T.Method") {
		t.Fatalf("the second pattern's Reveal is not reported:\n%s", out)
	}
}

// A pattern that matches no package fails.
func TestRun_PatternMatchingNothingFails(t *testing.T) {
	root := fixture(t, map[string]string{"b/b.go": clean})
	code, out := runFixture(t, root, []string{"./nope/..."}, header)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
}
