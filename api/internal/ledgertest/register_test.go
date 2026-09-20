package ledgertest_test

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
)

// The register gate for "no secret in the job ledger"
// (geekdojo/geekdojo-brain#493, gate 6).
//
// The assertion itself belongs to each workflow's own package, where the
// harness that can run that workflow lives. What belongs here is the thing no
// single package can see: whether EVERY workflow has one.
//
// So this walks the tree for workflow declarations, and holds
// .github/ledger-secrets.tsv to them. A workflow added tomorrow fails this
// test until someone has written down whether its ledger can carry a
// credential — which is the review the gate exists to force, and the one that
// cannot happen inside the pull request that adds the workflow unless
// something asks for it.

const registerPath = ".github/ledger-secrets.tsv"

var registerCols = []string{"kind", "source", "status", "test", "cite", "note"}

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

// discoverWorkflows finds every jobs.Workflow literal in the tree and returns
// kind -> the file that declares it.
//
// Kinds are written both as string literals and as package constants, so the
// constants in each package are collected first and the literal is resolved
// through them. A Kind this cannot resolve is reported rather than skipped: a
// workflow the scan cannot name is a workflow the register cannot cover, and
// silently dropping it would leave this whole test passing over the gap.
func discoverWorkflows(t *testing.T, root string) map[string]string {
	t.Helper()

	type lit struct {
		expr ast.Expr
		file string
		pkg  string
	}
	var found []lit
	consts := map[string]string{} // "pkgdir.Name" -> value

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
			return nil // not our business; the build catches it
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		pkgdir := filepath.ToSlash(filepath.Dir(rel))

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ValueSpec:
				for i, name := range node.Names {
					if i < len(node.Values) {
						if b, ok := node.Values[i].(*ast.BasicLit); ok && b.Kind == token.STRING {
							if v, e := strconv.Unquote(b.Value); e == nil {
								consts[pkgdir+"."+name.Name] = v
							}
						}
					}
				}
			case *ast.CompositeLit:
				if !isWorkflowLit(node) {
					return true
				}
				for _, el := range node.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Kind" {
						found = append(found, lit{expr: kv.Value, file: rel, pkg: pkgdir})
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	out := map[string]string{}
	for _, l := range found {
		switch v := l.expr.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				if s, e := strconv.Unquote(v.Value); e == nil {
					out[s] = l.file
					continue
				}
			}
			t.Errorf("%s: a workflow Kind is a literal this scan cannot read", l.file)
		case *ast.Ident:
			if s, ok := consts[l.pkg+"."+v.Name]; ok {
				out[s] = l.file
				continue
			}
			t.Errorf("%s: a workflow Kind is the constant %s, whose value this scan "+
				"could not resolve. Every workflow has to be nameable here or the "+
				"register cannot cover it.", l.file, v.Name)
		default:
			t.Errorf("%s: a workflow Kind is neither a string nor a constant, so this "+
				"scan cannot name it", l.file)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no workflows at all — the scan is broken, and a broken scan " +
			"makes this whole gate pass over every workflow in the tree")
	}
	return out
}

// isWorkflowLit matches `jobs.Workflow{...}` and, inside package jobs itself,
// `Workflow{...}`.
func isWorkflowLit(c *ast.CompositeLit) bool {
	switch t := c.Type.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "jobs" && t.Sel.Name == "Workflow"
	case *ast.Ident:
		return t.Name == "Workflow"
	}
	return false
}

func readRegister(t *testing.T, root string) []map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, registerPath))
	if err != nil {
		t.Fatalf("read %s: %v", registerPath, err)
	}
	var out []map[string]string
	header := false
	for n, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if !header {
			if len(parts) != len(registerCols) {
				t.Fatalf("%s:%d: header has %d columns, want %d", registerPath, n+1,
					len(parts), len(registerCols))
			}
			for i, c := range registerCols {
				if parts[i] != c {
					t.Fatalf("%s:%d: column %d is %q, want %q", registerPath, n+1, i+1, parts[i], c)
				}
			}
			header = true
			continue
		}
		if len(parts) != len(registerCols) {
			t.Fatalf("%s:%d: %d fields, want %d", registerPath, n+1, len(parts), len(registerCols))
		}
		row := map[string]string{}
		for i, c := range registerCols {
			row[c] = parts[i]
		}
		out = append(out, row)
	}
	if !header {
		t.Fatalf("%s: no header row", registerPath)
	}
	return out
}

var testDecl = regexp.MustCompile(`(?m)^func (Test\w+)\(`)

func testNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "ui":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, m := range testDecl.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
		return nil
	})
	return out
}

func TestLedgerRegisterCoversEveryWorkflow(t *testing.T) {
	root := repoRoot(t)
	workflows := discoverWorkflows(t, root)
	rows := readRegister(t, root)

	listed := map[string]bool{}
	for _, r := range rows {
		if listed[r["kind"]] {
			t.Errorf("%s: %s is listed twice", registerPath, r["kind"])
		}
		listed[r["kind"]] = true
	}

	var missing []string
	for kind, file := range workflows {
		if !listed[kind] {
			missing = append(missing, kind+" ("+file+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d workflow(s) are not in %s:\n  %s\n"+
			"Every workflow records whether its ledger can carry a credential, and "+
			"the test that proves it does not. Add a row: `covered` naming that test, "+
			"`pending` citing the issue that will add it, or `no-secret` with a note "+
			"saying why this workflow handles none.",
			len(missing), registerPath, strings.Join(missing, "\n  "))
	}

	var stale []string
	for _, r := range rows {
		if _, ok := workflows[r["kind"]]; !ok {
			stale = append(stale, r["kind"])
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%s lists %d workflow(s) that no longer exist: %s. A row that outlives "+
			"its workflow makes the coverage count read higher than it is.",
			registerPath, len(stale), strings.Join(stale, ", "))
	}
}

func TestLedgerRegisterRowsHoldTheirOwnContract(t *testing.T) {
	root := repoRoot(t)
	rows := readRegister(t, root)
	tests := testNames(t, root)
	workflows := discoverWorkflows(t, root)

	covered, pending, none := 0, 0, 0
	for _, r := range rows {
		kind := r["kind"]
		if src, ok := workflows[kind]; ok && r["source"] != src {
			t.Errorf("%s: %s says it is declared in %q; it is declared in %q",
				registerPath, kind, r["source"], src)
		}
		switch r["status"] {
		case "covered":
			covered++
			if r["test"] == "" {
				t.Errorf("%s: %s is covered but names no test", registerPath, kind)
			}
			for _, name := range strings.Fields(r["test"]) {
				if !tests[name] {
					t.Errorf("%s: %s names the test %s, which does not exist. A register "+
						"that names a test nobody wrote reads as coverage and is not.",
						registerPath, kind, name)
				}
			}
		case "pending":
			pending++
			if r["cite"] == "" {
				t.Errorf("%s: %s is pending with no issue cited, so nobody will pick it up",
					registerPath, kind)
			}
			if r["test"] != "" {
				t.Errorf("%s: %s is pending but names a test; mark it covered", registerPath, kind)
			}
		case "no-secret":
			none++
			if strings.TrimSpace(r["note"]) == "" {
				t.Errorf("%s: %s claims to handle no credential and says nothing about why. "+
					"That claim is the whole assertion for this workflow, so it is written "+
					"down or it is not made.", registerPath, kind)
			}
		default:
			t.Errorf("%s: %s has status %q; want covered, pending or no-secret",
				registerPath, kind, r["status"])
		}
	}

	// The posture, always — a green run that printed nothing would read as
	// "every workflow is covered", and today most are not.
	t.Logf("job ledger: %d workflows · %d asserted · %d handle no credential · %d owed",
		len(rows), covered, none, pending)
	if covered == 0 {
		t.Error("no workflow has a ledger assertion at all; the register is describing nothing")
	}
}
