package jobs_test

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// The callers of the job runner are held here, by type, rather than by a text
// grep, which cannot see a spec's static type (F-825-03). The checker loads
// packages with full type information and fails on:
//
//  1. a call to (*jobs.Runner).Submit, SubmitPrepared or SubmitChild, or to a
//     value of type bmc.SubmitFn or console.Submitter, whose spec argument's
//     static type is json.RawMessage, *json.RawMessage or []byte;
//  2. any selection of (*jobs.Runner).SubmitRawSpec, a call or a method value,
//     outside Server.handleCreateJob and Scheduler.fire;
//  3. a scan that found no runner call at all, which would pass vacuously.
//
// Test files are not loaded: they exercise the refusal and the raw entry point
// on purpose.

const (
	modulePath = "github.com/geekdojo/rasputin-control-plane/api"
	jobsPath   = modulePath + "/internal/jobs"
	bmcPath    = modulePath + "/internal/bmc"
	consolePkg = modulePath + "/internal/console"
)

// rawSpecCallers are the only declarations allowed to reach SubmitRawSpec,
// keyed by package path.
var rawSpecCallers = map[string]string{
	modulePath + "/internal/api":       "Server.handleCreateJob",
	modulePath + "/internal/scheduler": "Scheduler.fire",
}

type specScan struct {
	runnerCalls int      // calls to Submit/SubmitPrepared/SubmitChild and the two func types
	rawCallers  []string // "<pkg path>.<decl>" for every SubmitRawSpec selection
	violations  []violation
}

type violation struct {
	pos token.Position
	msg string
}

func (v violation) String() string { return v.pos.String() + ": " + v.msg }

func loadForSpecScan(t *testing.T, dir string, patterns ...string) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
		Dir: dir,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatalf("load %v: %v", patterns, err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("load %v: %d package errors", patterns, n)
	}
	if len(pkgs) == 0 {
		t.Fatalf("load %v: no packages", patterns)
	}
	return pkgs
}

func scanSpecArgs(pkgs []*packages.Package) specScan {
	var sc specScan
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			for _, decl := range f.Decls {
				name := declName(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.CallExpr:
						sc.checkCall(p, n)
					case *ast.SelectorExpr:
						if isRunnerMethod(p.TypesInfo.Uses[n.Sel], "SubmitRawSpec") {
							where := p.PkgPath + "." + name
							sc.rawCallers = append(sc.rawCallers, where)
							if rawSpecCallers[p.PkgPath] != name {
								sc.violations = append(sc.violations, violation{p.Fset.Position(n.Pos()), fmt.Sprintf(
									"SubmitRawSpec selected in %s; only Server.handleCreateJob and Scheduler.fire may reach the raw entry point",
									where)})
							}
						}
					}
					return true
				})
			}
		}
	}
	return sc
}

// checkCall records a runner call and flags a raw spec argument.
func (sc *specScan) checkCall(p *packages.Package, call *ast.CallExpr) {
	var what string
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		obj := p.TypesInfo.Uses[fun.Sel]
		for _, m := range []string{"Submit", "SubmitPrepared", "SubmitChild"} {
			if isRunnerMethod(obj, m) {
				what = "(*jobs.Runner)." + m
			}
		}
	}
	if what == "" {
		if tv, ok := p.TypesInfo.Types[call.Fun]; ok && tv.IsValue() {
			switch {
			case isNamed(tv.Type, bmcPath, "SubmitFn"):
				what = "bmc.SubmitFn"
			case isNamed(tv.Type, consolePkg, "Submitter"):
				what = "console.Submitter"
			}
		}
	}
	if what == "" {
		return
	}
	sc.runnerCalls++
	if len(call.Args) < 3 {
		return
	}
	spec := call.Args[2]
	if t := p.TypesInfo.TypeOf(spec); isRawSpecType(t) {
		sc.violations = append(sc.violations, violation{p.Fset.Position(spec.Pos()), fmt.Sprintf(
			"%s called with a spec of static type %s; pass the typed spec struct",
			what, types.TypeString(t, nil))})
	}
}

// isRunnerMethod reports whether obj is the method (*jobs.Runner).<name>.
func isRunnerMethod(obj types.Object, name string) bool {
	fn, ok := obj.(*types.Func)
	if !ok || fn.Name() != name || fn.Pkg() == nil || fn.Pkg().Path() != jobsPath {
		return false
	}
	recv := fn.Signature().Recv()
	if recv == nil {
		return false
	}
	t := recv.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	return isNamed(t, jobsPath, "Runner")
}

func isNamed(t types.Type, pkgPath, name string) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	o := n.Obj()
	return o.Pkg() != nil && o.Pkg().Path() == pkgPath && o.Name() == name
}

// isRawSpecType reports json.RawMessage, *json.RawMessage and []byte: the
// static types encodeSpec refuses with ErrRawSpec.
func isRawSpecType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		return isRawMessage(ptr.Elem())
	}
	if isRawMessage(t) {
		return true
	}
	return types.Identical(types.Unalias(t), types.NewSlice(types.Typ[types.Byte]))
}

// isRawMessage reports json.RawMessage under either encoding/json build. Up
// to Go 1.26 it is the named type encoding/json.RawMessage; from Go 1.27 the
// default build is backed by json/v2, where RawMessage is an alias of
// encoding/json/jsontext.Value, and Unalias yields that.
func isRawMessage(t types.Type) bool {
	return isNamed(t, "encoding/json", "RawMessage") || isNamed(t, "encoding/json/jsontext", "Value")
}

// declName names a top-level declaration as secretlint does: Recv.Method for
// a method, the name for a function, "<var>" or "<file>" otherwise.
func declName(d ast.Decl) string {
	fd, ok := d.(*ast.FuncDecl)
	if !ok {
		return "<file>"
	}
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// TC-825-22, TC-825-23: at head, every runner call in the api module passes a
// typed spec, and the raw entry point is reached from exactly its two callers.
func TestSpecArgs_Module(t *testing.T) {
	pkgs := loadForSpecScan(t, ".", modulePath+"/...")
	sc := scanSpecArgs(pkgs)
	if sc.runnerCalls == 0 {
		t.Fatal("empty scan: no runner call found in the api module")
	}
	for _, v := range sc.violations {
		t.Error(v.String())
	}
	got := slices.Clone(sc.rawCallers)
	slices.Sort(got)
	got = slices.Compact(got)
	var want []string
	for pkg, decl := range rawSpecCallers {
		want = append(want, pkg+"."+decl)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("SubmitRawSpec is reached from %v, want exactly %v", got, want)
	}
}

// TC-825-23: a fixture that passes json.Marshal's bytes, a json.RawMessage and
// a *json.RawMessage to the runner, and []byte to the two func types, fails
// with each position named. A typed struct and nil pass.
func TestSpecArgs_FixtureRawSpec(t *testing.T) {
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/rawspec"))
	want := []string{
		"rawspec.go:22", // r.Submit(ctx, k, spec, c) with spec from json.Marshal
		"rawspec.go:25", // SubmitPrepared with json.RawMessage
		"rawspec.go:28", // SubmitChild with *json.RawMessage
		"rawspec.go:31", // bmc.SubmitFn with []byte
		"rawspec.go:34", // console.Submitter with json.RawMessage
	}
	assertViolations(t, sc, want)
	if sc.runnerCalls != 7 {
		t.Errorf("runner calls = %d, want 7 (five raw, one typed, one nil)", sc.runnerCalls)
	}
}

// TC-825-22: a third caller of SubmitRawSpec fails and is named, both a call
// and a method value taken in another declaration.
func TestSpecArgs_FixtureThirdRawCaller(t *testing.T) {
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/thirdcaller"))
	assertViolations(t, sc, []string{
		"thirdcaller.go:12", // r.SubmitRawSpec(...) in Call
		"thirdcaller.go:17", // f := r.SubmitRawSpec in MethodValue
	})
	for i, decl := range []string{"thirdcaller.Call", "thirdcaller.MethodValue"} {
		if !strings.Contains(sc.violations[i].msg, decl) {
			t.Errorf("violation %d does not name %s: %s", i, decl, sc.violations[i])
		}
	}
}

// TC-825-22, TC-825-23: a scan with no runner call is empty, which the module
// test refuses rather than passing.
func TestSpecArgs_FixtureEmptyScan(t *testing.T) {
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/empty"))
	if sc.runnerCalls != 0 || len(sc.violations) != 0 || len(sc.rawCallers) != 0 {
		t.Fatalf("empty fixture scanned as %+v, want nothing", sc)
	}
}

// assertViolations wants one violation per "<file>:<line>", in order.
func assertViolations(t *testing.T, sc specScan, want []string) {
	t.Helper()
	if len(sc.violations) != len(want) {
		t.Fatalf("%d violations, want %d: %v", len(sc.violations), len(want), sc.violations)
	}
	for i, w := range want {
		v := sc.violations[i]
		if got := fmt.Sprintf("%s:%d", filepath.Base(v.pos.Filename), v.pos.Line); got != w {
			t.Errorf("violation %d at %s, want %s: %s", i, got, w, v)
		}
	}
}
