// Command secretlint runs the secretlint analyzer (api/internal/secretlint)
// over the packages it is given and gates on the result (ADR-0009).
//
// It exits 1 when:
//
//   - an SL01 site (a secret.Value.Reveal) has no row in the allowlist;
//   - there is any SL02 site at all (unsafe or reflect access to a type that
//     holds a secret.Value has no allowlist);
//   - an allowlist row matches no site, so a row cannot outlive its code;
//   - the allowlist is missing or malformed;
//   - no patterns were given;
//   - a package fails to load or type-check, so a tree the analyzer could not
//     read never passes.
//
// The allowlist, .github/secret-reveal-allow.tsv, has the columns
// path, symbol and reason, and is keyed on path plus enclosing symbol, never
// on a line number — the convention of .github/failopen-allow.tsv.
//
// # Why this lives in api/cmd
//
// For the reason failopenlint does: here it inherits gosec, staticcheck,
// CodeQL, Dependabot and CI's build-and-test with no new go.work module.
//
// Usage, from the repo root:
//
//	go run ./api/cmd/secretlint ./api/... ./secret/...
//	go run ./api/cmd/secretlint -dir DIR -allow FILE PATTERN...  # tests
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretlint"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tsvreg"
)

func main() {
	dir := flag.String("dir", ".", "the directory patterns are resolved in and paths are reported relative to")
	allow := flag.String("allow", ".github/secret-reveal-allow.tsv", "the Reveal allowlist")
	flag.Parse()
	os.Exit(run(*dir, flag.Args(), *allow, os.Stdout))
}

// run lints patterns from dir against the allowlist at allowPath, writing
// findings to out. It returns the process exit code.
func run(dir string, patterns []string, allowPath string, out io.Writer) int {
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(out, "secretlint: "+format+"\n", a...)
		return 1
	}
	if len(patterns) == 0 {
		return fail("no package patterns given; a lint over nothing would pass having read nothing")
	}
	rows, err := tsvreg.Read(allowPath, []string{"path", "symbol", "reason"})
	if err != nil {
		return fail("allowlist: %v", err)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return fail("%v", err)
	}
	_, _ = fmt.Fprintf(out, "secretlint: linting %s\n", strings.Join(patterns, " "))

	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo |
			packages.NeedDeps | packages.NeedModule,
		Dir: root,
	}, patterns...)
	if err != nil {
		return fail("load: %v", err)
	}
	if len(pkgs) == 0 {
		return fail("the patterns matched no packages")
	}
	loadErrs := 0
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs++
			_, _ = fmt.Fprintf(out, "%s\n", e)
		}
	})
	if loadErrs > 0 {
		return fail("%d package load or type error(s); a tree the analyzer cannot read does not pass", loadErrs)
	}

	graph, err := checker.Analyze([]*analysis.Analyzer{secretlint.Analyzer}, pkgs, nil)
	if err != nil {
		return fail("analyze: %v", err)
	}
	var sites []secretlint.Site
	for act := range graph.All() {
		if !act.IsRoot {
			continue
		}
		if act.Err != nil {
			return fail("%s: %v", act.Package.PkgPath, act.Err)
		}
		s, _ := act.Result.([]secretlint.Site)
		sites = append(sites, s...)
	}
	return gate(root, sites, rows, out)
}

// gate applies the allowlist to the sites and reports what fails.
func gate(root string, sites []secretlint.Site, rows []map[string]string, out io.Writer) int {
	allowed := map[string]bool{}
	for _, r := range rows {
		allowed[r["path"]+"\x00"+r["symbol"]] = false
	}
	var bad []string
	reveals := 0
	for _, s := range sites {
		path := rel(root, s.Pos.Filename)
		line := fmt.Sprintf("%s:%d: %s %s: %s", path, s.Pos.Line, s.Rule, s.Symbol, s.Detail)
		if s.Rule != secretlint.RuleReveal {
			bad = append(bad, line+" (SL02 has no allowlist)")
			continue
		}
		reveals++
		k := path + "\x00" + s.Symbol
		if _, ok := allowed[k]; ok {
			allowed[k] = true
			continue
		}
		bad = append(bad, line+" (not in the allowlist)")
	}
	for _, r := range rows {
		if !allowed[r["path"]+"\x00"+r["symbol"]] {
			bad = append(bad, fmt.Sprintf("allowlist row %s\t%s matches no Reveal site; remove it", r["path"], r["symbol"]))
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		_, _ = fmt.Fprintln(out, b)
	}
	if len(bad) > 0 {
		_, _ = fmt.Fprintf(out, "secretlint: %d problem(s)\n", len(bad))
		return 1
	}
	_, _ = fmt.Fprintf(out, "secretlint: %d Reveal site(s), all allowlisted; no unsafe or reflect access\n", reveals)
	return 0
}

// rel reports path relative to root, slash-separated, as the allowlist
// keys it.
func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(r)
}
