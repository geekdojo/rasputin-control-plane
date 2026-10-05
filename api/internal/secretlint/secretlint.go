// Package secretlint is the go/analysis analyzer that holds secret.Value to
// its one way out (ADR-0009).
//
// secret.Value renders "[redacted]" through every ordinary path, so the only
// places its bytes can leave are the ones this analyzer reports:
//
//	SL01  a selection of secret.Value.Reveal: a call, a method value or a
//	      method expression, or Reveal called through an interface that
//	      secret.Value implements. Every one is a site a reviewer has to
//	      have read, so api/cmd/secretlint fails on one that
//	      .github/secret-reveal-allow.tsv does not name.
//	SL02  unsafe.Pointer(x), reflect.ValueOf(x) or reflect.Indirect(x) where
//	      the static type of x can hold a secret.Value. Those read the bytes
//	      without Reveal, so there is no allowlist for them.
//
// Package secret itself is exempt, keyed on its import path and not its
// name: it is where Reveal is defined.
//
// The analyzer reports each site as a diagnostic and also returns them all
// as its Result ([]Site), which is what api/cmd/secretlint gates on.
package secretlint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// PkgPath is the import path of package secret, which defines Value.
const PkgPath = "github.com/geekdojo/rasputin-control-plane/secret"

// Rule IDs.
const (
	RuleReveal = "SL01"
	RuleUnsafe = "SL02"
)

// Site is one rule firing at one place.
type Site struct {
	Rule   string
	Pos    token.Position
	Symbol string // the enclosing declaration, e.g. "RestoreSessions.Open"
	Detail string
}

// Analyzer is the immutable go/analysis descriptor.
var Analyzer = &analysis.Analyzer{
	Name:       "secretlint",
	Doc:        "reports every way a secret.Value's bytes can leave: Reveal (SL01) and unsafe/reflect access (SL02)",
	Run:        run,
	ResultType: reflect.TypeFor[[]Site](),
}

func run(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() == PkgPath {
		return []Site(nil), nil
	}
	c := &checker{pass: pass, value: findValue(pass.Pkg)}
	for _, f := range pass.Files {
		c.file = f
		ast.Inspect(f, c.visit)
	}
	return c.sites, nil
}

type checker struct {
	pass  *analysis.Pass
	value *types.Named // secret.Value, when this package can see it
	file  *ast.File
	sites []Site
}

func (c *checker) visit(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.SelectorExpr:
		if c.isReveal(n) {
			c.report(RuleReveal, n.Sel.Pos(), "secret.Value.Reveal: the bytes leave here")
		}
	case *ast.CallExpr:
		if what, ok := c.unsafeAccess(n); ok {
			c.report(RuleUnsafe, n.Pos(), what+" of a type that holds a secret.Value reads its bytes without Reveal")
		}
	}
	return true
}

func (c *checker) report(rule string, pos token.Pos, detail string) {
	sym := enclosing(c.file, pos)
	c.sites = append(c.sites, Site{Rule: rule, Pos: c.pass.Fset.Position(pos), Symbol: sym, Detail: detail})
	c.pass.Reportf(pos, "%s %s: %s", rule, sym, detail)
}

// isReveal reports whether sel selects secret.Value.Reveal, directly or
// through an interface Value implements.
func (c *checker) isReveal(sel *ast.SelectorExpr) bool {
	s, ok := c.pass.TypesInfo.Selections[sel]
	if !ok || s.Kind() == types.FieldVal {
		return false
	}
	fn, ok := s.Obj().(*types.Func)
	if !ok || fn.Name() != "Reveal" {
		return false
	}
	recv := fn.Signature().Recv()
	if recv == nil {
		return false
	}
	rt := types.Unalias(recv.Type())
	if p, ok := rt.(*types.Pointer); ok {
		rt = types.Unalias(p.Elem())
	}
	if isValueType(rt) {
		return true
	}
	iface, ok := rt.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return c.implementedByValue(iface)
}

// implementedByValue reports whether secret.Value satisfies iface. When this
// package cannot see secret.Value (nothing it imports reaches it), a Value can
// still arrive through the interface from elsewhere, so the method set is
// matched by name and signature against Value's.
func (c *checker) implementedByValue(iface *types.Interface) bool {
	if c.value != nil {
		return types.Implements(c.value, iface)
	}
	for m := range iface.Methods() {
		want, ok := valueMethods[m.Name()]
		if !ok || sigKey(m.Signature()) != want {
			return false
		}
	}
	return true
}

// valueMethods is secret.Value's method set, by signature key. Used only
// for a package that cannot see the type itself.
var valueMethods = map[string]string{
	"Reveal":      "()([]byte)",
	"Len":         "()(int)",
	"Destroy":     "()()",
	"String":      "()(string)",
	"Format":      "(fmt.State,rune)()",
	"MarshalJSON": "()([]byte,error)",
	"LogValue":    "()(log/slog.Value)",
}

func sigKey(sig *types.Signature) string {
	list := func(t *types.Tuple) string {
		parts := make([]string, 0, t.Len())
		for v := range t.Variables() {
			parts = append(parts, types.TypeString(v.Type(), nil))
		}
		return "(" + strings.Join(parts, ",") + ")"
	}
	return list(sig.Params()) + list(sig.Results())
}

// unsafeAccess reports unsafe.Pointer(x), reflect.ValueOf(x) and
// reflect.Indirect(x) where x's static type holds a secret.Value. For
// reflect.Indirect the argument is a reflect.Value, so the type is read
// through a reflect.ValueOf(x) argument.
func (c *checker) unsafeAccess(call *ast.CallExpr) (string, bool) {
	if len(call.Args) != 1 {
		return "", false
	}
	arg := call.Args[0]
	if tv, ok := c.pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
		if b, ok := tv.Type.Underlying().(*types.Basic); ok && b.Kind() == types.UnsafePointer {
			return "unsafe.Pointer", c.holds(arg)
		}
		return "", false
	}
	switch reflectFunc(c.pass.TypesInfo, call) {
	case "ValueOf":
		return "reflect.ValueOf", c.holds(arg)
	case "Indirect":
		if inner, ok := ast.Unparen(arg).(*ast.CallExpr); ok && len(inner.Args) == 1 && reflectFunc(c.pass.TypesInfo, inner) == "ValueOf" {
			return "reflect.Indirect", c.holds(inner.Args[0])
		}
	}
	return "", false
}

// reflectFunc names the package-level reflect function call invokes, or "".
func reflectFunc(info *types.Info, call *ast.CallExpr) string {
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	default:
		return ""
	}
	fn, ok := info.Uses[id].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" || fn.Signature().Recv() != nil {
		return ""
	}
	return fn.Name()
}

func (c *checker) holds(e ast.Expr) bool {
	t := c.pass.TypesInfo.TypeOf(e)
	return t != nil && Holds(t)
}

// Holds reports whether a value of type t can carry a secret.Value: t
// itself, a struct field, a pointer, a slice or array element, or a map key
// or value — the shapes secret.Contains walks.
func Holds(t types.Type) bool { return holds(t, map[types.Type]bool{}) }

func holds(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if isValueType(t) {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return holds(u.Elem(), seen)
	case *types.Slice:
		return holds(u.Elem(), seen)
	case *types.Array:
		return holds(u.Elem(), seen)
	case *types.Map:
		return holds(u.Key(), seen) || holds(u.Elem(), seen)
	case *types.Struct:
		for f := range u.Fields() {
			if holds(f.Type(), seen) {
				return true
			}
		}
	}
	return false
}

func isValueType(t types.Type) bool {
	n, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := n.Obj()
	return obj.Name() == "Value" && obj.Pkg() != nil && obj.Pkg().Path() == PkgPath
}

// findValue returns secret.Value if pkg imports package secret, directly or
// transitively.
func findValue(pkg *types.Package) *types.Named {
	seen := map[*types.Package]bool{}
	var walk func(p *types.Package) *types.Named
	walk = func(p *types.Package) *types.Named {
		if seen[p] {
			return nil
		}
		seen[p] = true
		if p.Path() == PkgPath {
			if n, ok := p.Scope().Lookup("Value").(*types.TypeName); ok {
				if named, ok := n.Type().(*types.Named); ok {
					return named
				}
			}
			return nil
		}
		for _, imp := range p.Imports() {
			if v := walk(imp); v != nil {
				return v
			}
		}
		return nil
	}
	return walk(pkg)
}

// enclosing names the top-level declaration that contains pos: "T.Method"
// for a method, the name for a function, and the first declared name for a
// var, const or type declaration.
func enclosing(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if pos < d.Pos() || pos >= d.End() {
			continue
		}
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv != nil && len(d.Recv.List) == 1 {
				return recvName(d.Recv.List[0].Type) + "." + d.Name.Name
			}
			return d.Name.Name
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					// go/ast guarantees len(Names) > 0 for a ValueSpec.
					return s.Names[0].Name
				case *ast.TypeSpec:
					return s.Name.Name
				}
			}
		}
	}
	return "<file>"
}

func recvName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return recvName(e.X)
	case *ast.ParenExpr:
		return recvName(e.X)
	case *ast.IndexExpr:
		return recvName(e.X)
	case *ast.IndexListExpr:
		return recvName(e.X)
	case *ast.Ident:
		return e.Name
	}
	return fmt.Sprintf("%T", e)
}
