package identitytest

// TC-988-26: the base theme snapshot the login theme's coverage test holds
// (ui/identity-theme/upstream/<v>/) equals the pinned identity service's own
// files (geekdojo/geekdojo-brain#988). The templates and the English bundle
// are compared byte for byte with the dist's themes jar, every base login
// module and rfc4648 by sha256, and each module's import list with the one
// build.mjs judges bare specifiers by. It needs the installed dist only, not a
// running Keycloak: it skips without RASPUTIN_IDENTITY_HOME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
)

// snapshotDir is the snapshot for the pinned release.
func snapshotDir(version string) string {
	return filepath.Join("..", "..", "..", "ui", "identity-theme", "upstream", version)
}

// jarFiles reads every file of a jar under prefix, keyed by its path below
// prefix.
func jarFiles(t *testing.T, jar, prefix string) map[string][]byte {
	t.Helper()
	r, err := zip.OpenReader(jar)
	if err != nil {
		t.Fatalf("open %s: %v", jar, err)
	}
	defer func() { _ = r.Close() }()
	out := map[string][]byte{}
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasPrefix(f.Name, prefix) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		out[strings.TrimPrefix(f.Name, prefix)] = b
	}
	return out
}

// importRE matches an ES module's static and dynamic import specifiers, as
// ui/identity-theme/build.mjs's importSpecifiers does.
var importRE = regexp.MustCompile(`(?m)(?:^|[\s;])import\s*(?:[^'"]*?\sfrom\s*)?['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)`)

func moduleImports(src []byte) []string {
	set := map[string]bool{}
	for _, m := range importRE.FindAllSubmatch(src, -1) {
		s := string(m[1])
		if s == "" {
			s = string(m[2])
		}
		set[s] = true
	}
	out := []string{}
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// compareSnapshot is every way the snapshot at dir differs from the dist's
// base login theme (login: paths below theme/base/login/) and common files
// (common: below theme/keycloak/common/resources/), each naming the file.
func compareSnapshot(dir string, login, common map[string][]byte) []string {
	var problems []string
	ftl := 0
	for name, want := range login {
		if path.Dir(name) != "." || !strings.HasSuffix(name, ".ftl") {
			continue
		}
		ftl++
		got, err := os.ReadFile(filepath.Join(dir, "login", name))
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("the snapshot has no login/%s, which the dist has", name))
		case !bytes.Equal(got, want):
			problems = append(problems, fmt.Sprintf("the snapshot's login/%s differs from the dist's", name))
		}
	}
	snapFTL, _ := filepath.Glob(filepath.Join(dir, "login", "*.ftl"))
	for _, f := range snapFTL {
		if _, ok := login[filepath.Base(f)]; !ok {
			problems = append(problems, fmt.Sprintf("the snapshot's login/%s is not in the dist", filepath.Base(f)))
		}
	}
	if ftl == 0 {
		problems = append(problems, "the dist's themes jar holds no base login template")
	}
	msgs := "messages/messages_en.properties"
	if got, err := os.ReadFile(filepath.Join(dir, "login", msgs)); err != nil {
		problems = append(problems, "the snapshot has no login/"+msgs)
	} else if !bytes.Equal(got, login[msgs]) {
		problems = append(problems, "the snapshot's login/"+msgs+" differs from the dist's")
	}

	var list struct {
		Files []struct {
			SHA256 string `json:"sha256"`
			Path   string `json:"path"`
		} `json:"files"`
	}
	if b, err := os.ReadFile(filepath.Join(dir, "resources-sha256.json")); err != nil || json.Unmarshal(b, &list) != nil {
		return append(problems, "the snapshot's resources-sha256.json is missing or does not parse")
	}
	sums := map[string]string{}
	for _, f := range list.Files {
		sums[f.Path] = f.SHA256
	}
	var imports struct {
		Imports map[string][]string `json:"imports"`
	}
	if b, err := os.ReadFile(filepath.Join(dir, "module-imports.json")); err != nil || json.Unmarshal(b, &imports) != nil {
		return append(problems, "the snapshot's module-imports.json is missing or does not parse")
	}
	want := map[string]string{}
	for name, b := range login {
		if strings.HasPrefix(name, "resources/js/") {
			want["login/"+name] = sum(b)
			mod := path.Base(name)
			if got := imports.Imports[mod]; !slices.Equal(got, moduleImports(b)) {
				problems = append(problems, fmt.Sprintf("module-imports.json lists %v for %s, but the dist's imports %v", got, mod, moduleImports(b)))
			}
		}
	}
	if b, ok := common["vendor/rfc4648/rfc4648.js"]; ok {
		want["common/keycloak/vendor/rfc4648/rfc4648.js"] = sum(b)
	} else {
		problems = append(problems, "the dist has no common vendor/rfc4648/rfc4648.js")
	}
	for k, w := range want {
		if sums[k] != w {
			problems = append(problems, fmt.Sprintf("resources-sha256.json records %q for %s, but the dist's is %s", sums[k], k, w))
		}
	}
	for k := range sums {
		if _, ok := want[k]; !ok {
			problems = append(problems, fmt.Sprintf("resources-sha256.json lists %s, which the dist does not have", k))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestIdentity_BaseThemeSnapshotEqualsThePin(t *testing.T) {
	home := os.Getenv(HomeEnv)
	if home == "" {
		functest.SkipOrFail(t, SwitchEnv, "%s is not set, so there is no installed identity service to read the base theme from", HomeEnv)
		return
	}
	version := KeycloakRelease[strings.LastIndex(KeycloakRelease, ":")+1:]
	lib := filepath.Join(home, "keycloak", "lib", "lib", "main")
	login := jarFiles(t, filepath.Join(lib, "org.keycloak.keycloak-themes-"+version+".jar"), "theme/base/login/")
	common := jarFiles(t, filepath.Join(lib, "org.keycloak.keycloak-themes-vendor-"+version+".jar"), "theme/keycloak/common/resources/")
	dir := snapshotDir(version)

	if problems := compareSnapshot(dir, login, common); len(problems) != 0 {
		t.Fatalf("the snapshot %s is not the pinned base theme:\n%s", dir, strings.Join(problems, "\n"))
	}

	// A copy changed by one byte fails, naming the file.
	cp := t.TempDir()
	if err := os.CopyFS(cp, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cp, "login", "login.ftl")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got := compareSnapshot(cp, login, common)
	if !slices.Equal(got, []string{"the snapshot's login/login.ftl differs from the dist's"}) {
		t.Errorf("a one-byte change gave %q, want it to name login/login.ftl", got)
	}
}
