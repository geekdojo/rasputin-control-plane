package secretlint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/packages"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretlint"
)

// TC-732-12: SL01 fires on a call, a method value, a method expression
// (value and pointer receiver), a promoted method, and Reveal through an
// interface or a type parameter Value satisfies — including one spelled
// []uint8, which only the exact types.Implements path accepts — with the
// enclosing symbol named, a package-level var initializer included. It is silent for an unrelated Reveal, for an interface Value does
// not satisfy, and inside the stub at the real import path; it fires inside a
// second package named secret at another path.
func TestSL01(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), secretlint.Analyzer,
		"sl01", "other/secret", "github.com/geekdojo/rasputin-control-plane/secret")
}

// TC-732-12: a package that cannot see secret.Value still reports Reveal
// through an interface Value satisfies, matched by method set.
func TestSL01_InterfaceWithoutImport(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), secretlint.Analyzer, "noimport")
}

// TC-732-13: SL02 on unsafe.Pointer, reflect.ValueOf and reflect.Indirect of
// a type that holds a Value; silent on a struct of plain fields.
func TestSL02(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), secretlint.Analyzer, "sl02")
}

// The analyzer's Result carries every site, with the enclosing symbol.
func TestResult(t *testing.T) {
	res := analysistest.Run(t, analysistest.TestData(), secretlint.Analyzer, "sl01")
	if len(res) != 1 {
		t.Fatalf("%d results, want 1", len(res))
	}
	sites, ok := res[0].Action.Result.([]secretlint.Site)
	if !ok {
		t.Fatalf("result is %T, want []secretlint.Site", res[0].Action.Result)
	}
	if len(sites) != 10 {
		t.Fatalf("%d sites, want 10: %v", len(sites), sites)
	}
	first := sites[0]
	if first.Rule != secretlint.RuleReveal || first.Symbol != "Session.Open" || first.Pos.Line == 0 {
		t.Fatalf("first site = %+v, want SL01 in Session.Open with a line", first)
	}
}

// F-732-06: valueMethods, the fallback for a package that cannot see
// secret.Value, is pinned to the real type's method set, name and signature.
// A method added to Value without a row here fails this test.
func TestValueMethodsMatchSecretValue(t *testing.T) {
	pkgs, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes}, secretlint.PkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || len(pkgs[0].Errors) != 0 || pkgs[0].Types == nil {
		t.Fatalf("load %s: %v", secretlint.PkgPath, pkgs)
	}
	obj, ok := pkgs[0].Types.Scope().Lookup("Value").(*types.TypeName)
	if !ok {
		t.Fatalf("%s has no type Value", secretlint.PkgPath)
	}
	got := map[string]string{}
	ms := types.NewMethodSet(obj.Type())
	for sel := range ms.Methods() {
		fn := sel.Obj().(*types.Func)
		got[fn.Name()] = secretlint.SigKey(fn.Signature())
	}
	if !maps.Equal(got, secretlint.ValueMethods) {
		t.Fatalf("valueMethods = %v\nsecret.Value's method set = %v", secretlint.ValueMethods, got)
	}
}

// enclosing treats a declaration as the half-open range [Pos, End): its
// first token belongs to it, the position just past its end does not.
func TestEnclosingIsHalfOpen(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "e.go", "package e\n\nfunc F() {}\nvar V = 1\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	fn, v := f.Decls[0].(*ast.FuncDecl), f.Decls[1]
	cases := []struct {
		name string
		pos  token.Pos
		want string
	}{
		{"first token of a func", fn.Pos(), "F"},
		{"last byte of a func", fn.End() - 1, "F"},
		{"just past a func", fn.End(), "<file>"},
		{"first token of a var", v.Pos(), "V"},
		{"just past a var", v.End(), "<file>"},
		{"before every declaration", f.Name.Pos(), "<file>"},
	}
	for _, c := range cases {
		if got := secretlint.Enclosing(f, c.pos); got != c.want {
			t.Errorf("%s: enclosing = %q, want %q", c.name, got, c.want)
		}
	}
}
