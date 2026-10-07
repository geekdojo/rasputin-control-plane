package gatereg_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	modPrefix     = "github.com/geekdojo/rasputin-control-plane/"
	meshPkg       = modPrefix + "api/internal/mesh"
	tailscalePkg  = modPrefix + "agent/internal/tailscale"
	apiTrustPkg   = modPrefix + "api/internal/nodetrust"
	agentTrustPkg = modPrefix + "agent/internal/nodetrust"
)

// deps is `go list -deps` of pkg, run from the workspace root.
func deps(t *testing.T, root, pkg string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}

// fileImports is the import set of one source file.
func fileImports(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		out = append(out, p)
	}
	return out
}

// TC-741-25: no HTTPS trust path reaches the CA through api/internal/mesh or
// agent/internal/tailscale, and api/internal/nodetrust does not import mesh.
//
// Whole packages are checked by `go list -deps` where the package is a trust
// consumer and nothing else. Two places are composition roots or mixed
// packages that legitimately import mesh for other reasons — the api's main
// and internal/api's mesh handlers — so there the trust code is checked at
// the level it lives: the files that serve the CA import no mesh, and the
// api's HTTPS leaf functions name no mesh identifier.
func TestTrustPathsDoNotDependOnTheMesh(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		pkg       string
		forbidden string
		needs     string // a package the trust path must reach, or ""
	}{
		{modPrefix + "api/internal/obs", meshPkg, ""},
		{modPrefix + "api/internal/apps", meshPkg, ""},
		{apiTrustPkg, meshPkg, modPrefix + "proto"},
		{modPrefix + "api/internal/tlsca", meshPkg, ""},
		{modPrefix + "agent/internal/updater", tailscalePkg, ""},
		{modPrefix + "agent/internal/quiesce", tailscalePkg, ""},
		{modPrefix + "backupxfer", tailscalePkg, ""},
		{agentTrustPkg, tailscalePkg, modPrefix + "proto"},
	} {
		got := deps(t, root, c.pkg)
		if slices.Contains(got, c.forbidden) {
			t.Errorf("%s imports %s", c.pkg, c.forbidden)
		}
		if c.needs != "" && !slices.Contains(got, c.needs) {
			t.Errorf("%s does not reach %s", c.pkg, c.needs)
		}
		t.Logf("checked: %s does not depend on %s", c.pkg, c.forbidden)
	}

	for _, f := range []string{"api/internal/api/ca_handlers.go", "api/internal/api/ios_profile.go"} {
		imps := fileImports(t, filepath.Join(root, f))
		if slices.Contains(imps, meshPkg) {
			t.Errorf("%s imports %s", f, meshPkg)
		}
		t.Logf("checked: %s imports no %s", f, meshPkg)
	}
	if !slices.Contains(fileImports(t, filepath.Join(root, "api/internal/api/ca_handlers.go")), modPrefix+"api/internal/tlsca") {
		t.Error("the CA handlers do not name the CA through tlsca")
	}

	// The api's HTTPS leaf: ensureAPILeaf and apiLeafSpec name tlsca, never mesh.
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, filepath.Join(root, "api/cmd/rasputin-api/main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "ensureAPILeaf" && fn.Name.Name != "apiLeafSpec") {
			continue
		}
		seen[fn.Name.Name] = true
		usesTLSCA := false
		ast.Inspect(fn, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					switch id.Name {
					case "mesh":
						t.Errorf("%s names mesh.%s", fn.Name.Name, sel.Sel.Name)
					case "tlsca":
						usesTLSCA = true
					}
				}
			}
			return true
		})
		if !usesTLSCA {
			t.Errorf("%s does not reach the CA through tlsca", fn.Name.Name)
		}
		t.Logf("checked: main.%s names tlsca, not mesh", fn.Name.Name)
	}
	if !seen["ensureAPILeaf"] || !seen["apiLeafSpec"] {
		t.Errorf("leaf functions not found: %v", seen)
	}
}
