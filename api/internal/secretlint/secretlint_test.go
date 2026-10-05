package secretlint_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretlint"
)

// TC-732-12: SL01 fires on a call, a method value, a method expression
// (value and pointer receiver), a promoted method, and Reveal through an
// interface or a type parameter Value satisfies — with the enclosing symbol
// named. It is silent for an unrelated Reveal, for an interface Value does
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
	if len(sites) != 8 {
		t.Fatalf("%d sites, want 8: %v", len(sites), sites)
	}
	first := sites[0]
	if first.Rule != secretlint.RuleReveal || first.Symbol != "Session.Open" || first.Pos.Line == 0 {
		t.Fatalf("first site = %+v, want SL01 in Session.Open with a line", first)
	}
}
