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
//  2. any selection of a raw entry point, a call or a method value, outside
//     its pinned callers: (*jobs.Runner).SubmitOperatorSpec only in
//     Server.handleCreateJob, and (*jobs.Runner).SubmitRawSpec only in
//     Scheduler.fire;
//  3. a scan that found no runner call at all, which would pass vacuously;
//  4. the Submitter pins (geekdojo/geekdojo-brain#1001, F-1001-02): any use
//     of authz.SystemSubmitter outside package jobs, of authz.Person outside
//     package auth, of authz.RepairSession outside package breakglass
//     (geekdojo/geekdojo-brain#321), and of authz.BridgeGrant anywhere;
//  5. the person path: in package api, a Submitter argument to
//     (*jobs.Runner).SubmitFor or SubmitOperatorSpec or to
//     storage.SubmitClaim that is not the expression submitter(r), and any
//     selection of the system path (Submit, SubmitPrepared, SubmitChild,
//     SubmitRawSpec) outside the two system consequences
//     Server.submitDNSForward and Server.handleSetupMode
//     (geekdojo/geekdojo-brain#1002 classes those routes).
//
// Test files are not loaded: they exercise the refusal and the raw entry point
// on purpose.

const (
	modulePath = "github.com/geekdojo/rasputin-control-plane/api"
	jobsPath   = modulePath + "/internal/jobs"
	bmcPath    = modulePath + "/internal/bmc"
	consolePkg = modulePath + "/internal/console"
	authzPath  = modulePath + "/internal/authz"
	authPath   = modulePath + "/internal/auth"
	apiPath    = modulePath + "/internal/api"
	storPath   = modulePath + "/internal/storage"
)

// constructorOwners is the one package allowed to use each Submitter
// constructor in non-test code; "" is none. Identity 5.2 adds the owner of
// BridgeGrant. TC-321-26: RepairSession's owner is package breakglass
// (breakglass.Session.Submitter).
var constructorOwners = map[string]string{
	"SystemSubmitter": jobsPath,
	"Person":          authPath,
	"RepairSession":   modulePath + "/internal/breakglass",
	"BridgeGrant":     "",
}

// personPath is a package whose jobs are a person's: the declarations in it
// allowed to reach the runner's system path.
type personPath map[string]map[string]bool

// modulePersonPaths is the api module's person path: package api, whose two
// system consequences stay on the system path until #1002.
var modulePersonPaths = personPath{
	apiPath: {"Server.submitDNSForward": true, "Server.handleSetupMode": true},
}

// systemPath is the runner's system path, which a person's request never
// reaches.
var systemPath = []string{"Submit", "SubmitPrepared", "SubmitChild", "SubmitRawSpec"}

// rawSpecCallers are the only declarations allowed to reach each raw entry
// point, keyed by the method and then by package path. The operator's
// POST /api/jobs reaches SubmitRawSpec through SubmitOperatorSpec, which
// refuses a System kind first (geekdojo/geekdojo-brain#978) and records the
// job itself, after the runner's policy decides it (#1001).
var rawSpecCallers = map[string]map[string]string{
	"SubmitOperatorSpec": {
		modulePath + "/internal/api": "Server.handleCreateJob",
	},
	"SubmitRawSpec": {
		modulePath + "/internal/scheduler": "Scheduler.fire",
	},
}

type specScan struct {
	runnerCalls int      // calls to Submit/SubmitPrepared/SubmitChild/SubmitFor and the two func types
	rawCallers  []string // "<pkg path>.<decl>" for every SubmitRawSpec selection
	personCalls int      // person-path calls whose Submitter argument was checked
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

func scanSpecArgs(pkgs []*packages.Package, persons personPath) specScan {
	var sc specScan
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			for _, decl := range f.Decls {
				name := declName(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.Ident:
						sc.checkConstructor(p, n)
					case *ast.CallExpr:
						sc.checkCall(p, n)
						if allowed, ok := persons[p.PkgPath]; ok {
							sc.checkPersonCall(p, n, name, allowed)
						}
					case *ast.SelectorExpr:
						for method, callers := range rawSpecCallers {
							if !isRunnerMethod(p.TypesInfo.Uses[n.Sel], method) {
								continue
							}
							where := p.PkgPath + "." + name
							sc.rawCallers = append(sc.rawCallers, method+" from "+where)
							if callers[p.PkgPath] != name {
								sc.violations = append(sc.violations, violation{p.Fset.Position(n.Pos()), fmt.Sprintf(
									"%s selected in %s; only its pinned callers may reach the raw entry point",
									method, where)})
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
		for _, m := range []string{"Submit", "SubmitPrepared", "SubmitChild", "SubmitFor"} {
			if isRunnerMethod(obj, m) {
				what = "(*jobs.Runner)." + m
			}
		}
	}
	specArg := 2
	if what == "(*jobs.Runner).SubmitFor" {
		specArg = 3
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
	if len(call.Args) <= specArg {
		return
	}
	spec := call.Args[specArg]
	if t := p.TypesInfo.TypeOf(spec); isRawSpecType(t) {
		sc.violations = append(sc.violations, violation{p.Fset.Position(spec.Pos()), fmt.Sprintf(
			"%s called with a spec of static type %s; pass the typed spec struct",
			what, types.TypeString(t, nil))})
	}
}

// checkConstructor flags a use of a Submitter constructor outside its owner.
func (sc *specScan) checkConstructor(p *packages.Package, id *ast.Ident) {
	fn, ok := p.TypesInfo.Uses[id].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != authzPath || fn.Signature().Recv() != nil {
		return
	}
	owner, pinned := constructorOwners[fn.Name()]
	if !pinned || p.PkgPath == owner {
		return
	}
	who := "only " + owner + " may build that Submitter"
	if owner == "" {
		who = "no package may build that Submitter yet"
	}
	sc.violations = append(sc.violations, violation{p.Fset.Position(id.Pos()), fmt.Sprintf(
		"authz.%s used in %s; %s", fn.Name(), p.PkgPath, who)})
}

// checkPersonCall holds a person-path package's runner calls: a Submitter
// argument is submitter(r), and the system path is reached only from the
// allowed declarations.
func (sc *specScan) checkPersonCall(p *packages.Package, call *ast.CallExpr, decl string, allowed map[string]bool) {
	fun, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return
	}
	obj := p.TypesInfo.Uses[fun.Sel]
	arg := -1
	switch {
	case isRunnerMethod(obj, "SubmitFor"):
		arg = 1
	case isRunnerMethod(obj, "SubmitOperatorSpec"):
		arg = 3
	case isFunc(obj, storPath, "SubmitClaim"):
		arg = 5
	}
	if arg >= 0 {
		sc.personCalls++
		if len(call.Args) <= arg || !isSubmitterOfRequest(p, call.Args[arg]) {
			sc.violations = append(sc.violations, violation{p.Fset.Position(call.Pos()), fmt.Sprintf(
				"%s in %s.%s is not given submitter(r); a handler never picks its own submitter",
				fun.Sel.Name, p.PkgPath, decl)})
		}
		return
	}
	for _, m := range systemPath {
		if isRunnerMethod(obj, m) && !allowed[decl] {
			sc.violations = append(sc.violations, violation{p.Fset.Position(call.Pos()), fmt.Sprintf(
				"(*jobs.Runner).%s, the system path, called in %s.%s; a person's job goes through SubmitFor",
				m, p.PkgPath, decl)})
		}
	}
}

// isSubmitterOfRequest reports whether e is a call of the package's own
// submitter function.
func isSubmitterOfRequest(p *packages.Package, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[id].(*types.Func)
	return ok && fn.Name() == "submitter" && fn.Pkg() != nil && fn.Pkg().Path() == p.PkgPath && fn.Signature().Recv() == nil
}

// isFunc reports whether obj is the package-level function pkgPath.name.
func isFunc(obj types.Object, pkgPath, name string) bool {
	fn, ok := obj.(*types.Func)
	return ok && fn.Name() == name && fn.Pkg() != nil && fn.Pkg().Path() == pkgPath && fn.Signature().Recv() == nil
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

// TC-825-22, TC-825-23, TC-1001-17: at head, every runner call in the api
// module passes a typed spec, the raw entry points are reached from exactly
// their pinned callers, every Submitter constructor is used only by its
// owner, and every person-path call in package api is given submitter(r).
func TestSpecArgs_Module(t *testing.T) {
	pkgs := loadForSpecScan(t, ".", modulePath+"/...")
	sc := scanSpecArgs(pkgs, modulePersonPaths)
	if sc.runnerCalls == 0 {
		t.Fatal("empty scan: no runner call found in the api module")
	}
	if sc.personCalls == 0 {
		t.Fatal("empty scan: no person-path call found in package api")
	}
	for _, v := range sc.violations {
		t.Error(v.String())
	}
	got := slices.Clone(sc.rawCallers)
	slices.Sort(got)
	got = slices.Compact(got)
	var want []string
	for method, callers := range rawSpecCallers {
		for pkg, decl := range callers {
			want = append(want, method+" from "+pkg+"."+decl)
		}
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
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/rawspec"), modulePersonPaths)
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
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/thirdcaller"), modulePersonPaths)
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
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/empty"), modulePersonPaths)
	if sc.runnerCalls != 0 || len(sc.violations) != 0 || len(sc.rawCallers) != 0 {
		t.Fatalf("empty fixture scanned as %+v, want nothing", sc)
	}
}

// TC-1001-17: a person-path handler that calls the system path, one that
// hands SubmitFor a Submitter it built, and a use of each constructor outside
// its owner are each reported at their position.
func TestSpecArgs_FixturePersonPath(t *testing.T) {
	const personpath = jobsPath + "/testdata/specargs/personpath"
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/personpath"),
		personPath{personpath: {"Server.systemConsequence": true}})
	assertViolations(t, sc, []string{
		"personpath.go:30", // s.runner.Submit in a person's handler
		"personpath.go:35", // s.runner.SubmitPrepared in a person's handler
	})
	for _, v := range sc.violations {
		if !strings.Contains(v.msg, "the system path") {
			t.Errorf("violation does not name the system path: %s", v)
		}
	}
	if sc.personCalls != 1 {
		t.Errorf("person calls = %d, want 1 (the clean SubmitFor)", sc.personCalls)
	}
}

// TC-1001-17, F-1001-02: a handler passing authz.SystemSubmitter (or any
// constructor) to SubmitFor is reported twice: the constructor outside its
// owner, and the argument that is not submitter(r).
func TestSpecArgs_FixtureSystemSubmitter(t *testing.T) {
	const pkg = jobsPath + "/testdata/specargs/systemsubmitter"
	sc := scanSpecArgs(loadForSpecScan(t, ".", "./testdata/specargs/systemsubmitter"), personPath{pkg: {}})
	assertViolations(t, sc, []string{
		"systemsubmitter.go:24", // SubmitFor(ctx, authz.SystemSubmitter(...), ...): not submitter(r)
		"systemsubmitter.go:24", // ... and SystemSubmitter outside package jobs
		"systemsubmitter.go:29", // SubmitFor given authz.Person: not submitter(r)
		"systemsubmitter.go:29", // ... and Person outside package auth
		"systemsubmitter.go:34", // RepairSession outside package breakglass (TC-321-26)
		"systemsubmitter.go:35", // BridgeGrant, likewise
	})
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
