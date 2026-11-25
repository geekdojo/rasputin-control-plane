package jobs_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"golang.org/x/tools/go/packages"
)

// The kind table's completeness (geekdojo/geekdojo-brain#1001, TC-1001-16),
// held by type rather than by a grep: every jobs.Workflow literal in non-test
// code names a kind the table holds, and a System workflow's kind is
// system-only there. A Kind that is not a constant is followed one step: a
// field of a struct (unitrecover's r.d.Kind) resolves to every constant that
// field is given in a composite literal of that struct.

type kindScan struct {
	kinds    map[string]bool // kind -> any of its workflows is System
	problems []string
}

// indirectKind is a Workflow whose Kind is a struct field: the struct type,
// the field, and whether the workflow is System.
type indirectKind struct {
	typ    *types.Named
	field  string
	system bool
}

func scanWorkflowKinds(pkgs []*packages.Package) kindScan {
	sc := kindScan{kinds: map[string]bool{}}
	var indirect []indirectKind
	eachLit(pkgs, func(p *packages.Package, lit *ast.CompositeLit) {
		if !isNamed(p.TypesInfo.TypeOf(lit), jobsPath, "Workflow") {
			return
		}
		kindExpr, system := workflowFields(p, lit)
		if kindExpr == nil {
			return // the zero Workflow a refusing constructor returns
		}
		if k, ok := constString(p, kindExpr); ok {
			sc.kinds[k] = sc.kinds[k] || system
			return
		}
		if sel, ok := ast.Unparen(kindExpr).(*ast.SelectorExpr); ok {
			if s, ok := p.TypesInfo.Selections[sel]; ok && s.Kind() == types.FieldVal {
				recv := s.Recv()
				if ptr, ok := recv.(*types.Pointer); ok {
					recv = ptr.Elem()
				}
				if named, ok := types.Unalias(recv).(*types.Named); ok {
					indirect = append(indirect, indirectKind{typ: named, field: sel.Sel.Name, system: system})
					return
				}
			}
		}
		sc.problems = append(sc.problems, fmt.Sprintf("%s: a jobs.Workflow whose Kind the scan cannot resolve",
			p.Fset.Position(kindExpr.Pos())))
	})
	for _, in := range indirect {
		found := false
		eachLit(pkgs, func(p *packages.Package, lit *ast.CompositeLit) {
			t, ok := types.Unalias(p.TypesInfo.TypeOf(lit)).(*types.Named)
			if !ok || t.Obj() != in.typ.Obj() {
				return
			}
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == in.field {
					k, ok := constString(p, kv.Value)
					if !ok {
						sc.problems = append(sc.problems, fmt.Sprintf("%s: %s.%s is not a constant kind",
							p.Fset.Position(kv.Value.Pos()), in.typ.Obj().Name(), in.field))
						continue
					}
					found = true
					sc.kinds[k] = sc.kinds[k] || in.system
				}
			}
		})
		if !found {
			sc.problems = append(sc.problems, fmt.Sprintf("%s.%s names a workflow's kind, and no literal sets it",
				in.typ.Obj().Name(), in.field))
		}
	}
	return sc
}

// check is every way sc's kinds disagree with the table.
func (sc kindScan) check() []string {
	out := slices.Clone(sc.problems)
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range sc.kinds {
			if !yield(k) {
				return
			}
		}
	}) {
		switch {
		case !authz.Known(k):
			out = append(out, fmt.Sprintf("kind %q is registered and not in authz's kind table", k))
		case sc.kinds[k] && !authz.SystemOnly(k) && !authz.SystemOrRepair(k):
			// identity.move alone is the system's and a repair session's in
			// C9's state (geekdojo/geekdojo-brain#1004).
			out = append(out, fmt.Sprintf("kind %q is a System workflow and not system-only in authz's kind table", k))
		}
	}
	return out
}

func eachLit(pkgs []*packages.Package, fn func(*packages.Package, *ast.CompositeLit)) {
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok {
					fn(p, lit)
				}
				return true
			})
		}
	}
}

// workflowFields is a Workflow literal's Kind expression and whether it
// sets System to true.
func workflowFields(p *packages.Package, lit *ast.CompositeLit) (ast.Expr, bool) {
	var kind ast.Expr
	system := false
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		switch id, _ := kv.Key.(*ast.Ident); {
		case id == nil:
		case id.Name == "Kind":
			kind = kv.Value
		case id.Name == "System":
			v := p.TypesInfo.Types[kv.Value].Value
			system = v == nil || constant.BoolVal(v) // a non-constant System is treated as true
		}
	}
	return kind, system
}

func constString(p *packages.Package, e ast.Expr) (string, bool) {
	v := p.TypesInfo.Types[e].Value
	if v == nil || v.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(v), true
}

// TC-1001-16: every kind the api module registers is in the table, and every
// System workflow is system-only there. The scan is not vacuous: it finds
// app.deploy (a function-local const) and identity.recover (through
// unitrecover.Deps).
func TestKindTable_TC1001_16_Complete(t *testing.T) {
	sc := scanWorkflowKinds(loadForSpecScan(t, ".", modulePath+"/..."))
	for _, k := range []string{"app.deploy", "identity.recover", "secretstore.recover", "identity.recover_admin"} {
		if _, ok := sc.kinds[k]; !ok {
			t.Errorf("the scan did not find %s; it proves nothing", k)
		}
	}
	for _, p := range sc.check() {
		t.Error(p)
	}
	t.Logf("%d registered kinds, all in the table", len(sc.kinds))
}

// TC-1001-16: a workflow whose kind the table does not hold fails the scan,
// naming the kind.
func TestKindTable_TC1001_16_FixtureUnmapped(t *testing.T) {
	got := scanWorkflowKinds(loadForSpecScan(t, ".", "./testdata/kinds/unmapped")).check()
	if len(got) != 1 || !strings.Contains(got[0], `"test.not_in_the_table"`) || !strings.Contains(got[0], "not in authz's kind table") {
		t.Errorf("problems = %q, want one naming test.not_in_the_table", got)
	}
}

// TC-1001-16: a System workflow whose kind is control(...) fails the scan,
// naming the kind.
func TestKindTable_TC1001_16_FixtureSystemMismatch(t *testing.T) {
	got := scanWorkflowKinds(loadForSpecScan(t, ".", "./testdata/kinds/systemmismatch")).check()
	if len(got) != 1 || !strings.Contains(got[0], `"bmc.power"`) || !strings.Contains(got[0], "not system-only") {
		t.Errorf("problems = %q, want one naming bmc.power", got)
	}
}

// TC-994-31: the scan finds every account kind Identity 4.12 registers
// (geekdojo/geekdojo-brain#994), each a constant kind in the table and none
// System, with nothing it cannot resolve.
func TestKindTable_TC994_31_AccountKinds(t *testing.T) {
	sc := scanWorkflowKinds(loadForSpecScan(t, ".", modulePath+"/internal/accounts"))
	if len(sc.problems) != 0 {
		t.Errorf("problems: %v", sc.problems)
	}
	for _, k := range []string{"accounts.set_roles", "accounts.grant_access", "accounts.revoke_access", "accounts.set_network",
		"accounts.disable", "accounts.enable", "accounts.delete", "accounts.decline", "accounts.unlock", "accounts.sign_out",
		"accounts.set_email", "accounts.confirm_email", "accounts.set_display_name", "accounts.remove_second_steps",
		"accounts.remove_credential", "accounts.rename_credential"} {
		system, ok := sc.kinds[k]
		switch {
		case !ok:
			t.Errorf("the scan did not find %s", k)
		case system:
			t.Errorf("%s is a System workflow", k)
		case !authz.Known(k):
			t.Errorf("%s is not in the kind table", k)
		}
	}
	for _, p := range sc.check() {
		t.Error(p)
	}
}
