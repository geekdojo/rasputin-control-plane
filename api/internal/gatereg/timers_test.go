package gatereg_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The timer audit (geekdojo/geekdojo-brain#497, gate 11).
//
// principles.md: a state change follows a checkable fact, never a clock. A
// timeout is allowed on a single I/O call. A periodic tick is allowed as a
// safety net that RE-CHECKS a fact. Every unavoidable bound needs a comment
// saying why.
//
// The rule is easy to agree with and easy to lose. Each tick and each lifetime
// in this tree was added for a reason that made sense where it was written;
// what nothing recorded was which of the three kinds it is, and therefore
// whether the fact behind it still exists. A credential lifetime that decides
// validity with no fact behind it is clock-driven state, and the only honest
// thing to do with one is say so out loud — which is what this register makes
// somebody do.
//
// So: every periodic construct and every credential lifetime in the tree is a
// row in .github/timer-audit.tsv naming its class and the fact behind it. A new
// one fails this test until it has one.

const timerRegisterPath = ".github/timer-audit.tsv"

var timerCols = []string{"id", "path", "symbol", "class", "fact", "cite", "note"}

var timerClasses = map[string]bool{
	// A periodic tick that re-checks a fact. `fact` names the fact.
	"tick": true,
	// A credential lifetime. `fact` names the fact it is a safety net over,
	// or the word `none` — and then the row must cite where that is recorded,
	// because a lifetime with no fact behind it is clock-driven state.
	"ttl": true,
	// A bound on ONE I/O call, which principles.md allows outright.
	"io-bound": true,
	// Neither: a data retention or cache bound that decides no credential's
	// validity and no state transition.
	"retention": true,
}

// periodic are the calls that make something happen again and again.
var periodic = map[string]bool{
	"NewTicker": true,
	"NewTimer":  true,
	"Tick":      true,
	"AfterFunc": true,
}

// lifetimeName matches an identifier that holds a credential lifetime.
//
// Deliberately narrow. `timeout` is excluded: the tree carries dozens of them
// and nearly all bound one I/O call, which principles.md allows without a row.
// Sweeping them in would bury the handful of bounds that actually decide
// whether a credential is still good — and a register nobody can read is one
// nobody keeps.
var lifetimeName = regexp.MustCompile(`(?i)(ttl|lifetime|expiry|expiration|grant)$`)

// lifetimeExtra are the ones whose names do not follow that shape but which
// decide the same thing.
var lifetimeExtra = map[string]bool{
	"renewWindow":      true,
	"staleAfter":       true,
	"offlineAfter":     true,
	"certNotAfter":     true,
	"certNotBefore":    true,
	"clockGateTimeout": true,
}

// modules scanned. proto and backupxfer carry derived grant lifetimes, so they
// are in; tileschema and artifactsig have no timers at all.
var timerModules = []string{"api", "agent", "proto", "backupxfer"}

type timerSite struct {
	Path   string
	Symbol string
	Kind   string // "periodic" or "lifetime", for the failure message only
}

func discoverTimers(t *testing.T, repo string) map[string]timerSite {
	t.Helper()
	out := map[string]timerSite{}

	for _, mod := range timerModules {
		dir := filepath.Join(repo, mod)
		if _, statErr := os.Stat(dir); statErr != nil {
			// A fixture tree carries only the modules its case needs. The real
			// repo carries all of them, and a scan that found nothing at all is
			// caught below — which is the failure that matters.
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "testdata", "vendor":
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
				return nil
			}
			rel, _ := filepath.Rel(repo, path)
			rel = filepath.ToSlash(rel)

			var fn string
			ast.Inspect(f, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.FuncDecl:
					fn = node.Name.Name
					if node.Recv != nil && len(node.Recv.List) > 0 {
						fn = recvType(node.Recv.List[0].Type) + "." + fn
					}
				case *ast.ValueSpec:
					for _, name := range node.Names {
						if lifetimeName.MatchString(name.Name) || lifetimeExtra[name.Name] {
							out[rel+"#"+name.Name] = timerSite{rel, name.Name, "lifetime"}
						}
					}
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok || pkg.Name != "time" || !periodic[sel.Sel.Name] {
						return true
					}
					sym := fn
					if sym == "" {
						sym = "(package level)"
					}
					out[rel+"#"+sym+":"+sel.Sel.Name] =
						timerSite{rel, sym + ":" + sel.Sel.Name, "periodic"}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", mod, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no timers or lifetimes at all — the scan is broken, and a broken " +
			"scan makes this whole audit pass over every one of them")
	}
	return out
}

func recvType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvType(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvType(t.X)
	case *ast.IndexListExpr:
		return recvType(t.X)
	}
	return "?"
}

func TestTimerAuditCoversEveryTickAndLifetime(t *testing.T) {
	repo := root(t)
	found := discoverTimers(t, repo)
	rows := readRegister(t, filepath.Join(repo, timerRegisterPath), timerCols)

	listed := map[string]bool{}
	ids := map[string]bool{}
	for _, r := range rows {
		key := r["path"] + "#" + r["symbol"]
		if listed[key] {
			t.Errorf("%s: %s is listed twice", timerRegisterPath, key)
		}
		listed[key] = true
		if ids[r["id"]] {
			t.Errorf("%s: duplicate id %s", timerRegisterPath, r["id"])
		}
		ids[r["id"]] = true
	}

	var missing []string
	for key, site := range found {
		if !listed[key] {
			missing = append(missing, key+"  ("+site.Kind+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d timer(s) or lifetime(s) are not in %s:\n  %s\n\n"+
			"principles.md: a state change follows a checkable fact, never a clock. A "+
			"timeout is allowed on one I/O call; a tick is allowed as a safety net that "+
			"RE-CHECKS a fact. Add a row saying which of those this is and naming the "+
			"fact — and if a credential's validity is decided by the clock alone, say "+
			"`none` and cite where that is recorded, because that is the one thing this "+
			"audit exists to make somebody write down.",
			len(missing), timerRegisterPath, strings.Join(missing, "\n  "))
	}

	var stale []string
	for key := range listed {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%s lists %d site(s) that no longer exist: %s. A row that outlives its "+
			"timer makes the audit read as more thorough than it is.",
			timerRegisterPath, len(stale), strings.Join(stale, "\n  "))
	}
}

func TestTimerAuditRowsHoldTheirOwnContract(t *testing.T) {
	repo := root(t)
	rows := readRegister(t, filepath.Join(repo, timerRegisterPath), timerCols)

	counts := map[string]int{}
	clockDriven := 0
	for _, r := range rows {
		id := r["id"]
		if !timerClasses[r["class"]] {
			classes := make([]string, 0, len(timerClasses))
			for c := range timerClasses {
				classes = append(classes, c)
			}
			sort.Strings(classes)
			t.Errorf("%s: %s has class %q; want one of %s",
				timerRegisterPath, id, r["class"], strings.Join(classes, ", "))
			continue
		}
		counts[r["class"]]++

		if strings.TrimSpace(r["fact"]) == "" {
			t.Errorf("%s: %s names no fact. A tick names what it re-checks, a lifetime "+
				"names what it is a safety net over, and an I/O bound names the call it "+
				"bounds — otherwise nobody can tell whether it is still needed.",
				timerRegisterPath, id)
			continue
		}

		if r["class"] == "ttl" && strings.EqualFold(strings.TrimSpace(r["fact"]), "none") {
			clockDriven++
			if strings.TrimSpace(r["cite"]) == "" {
				t.Errorf("%s: %s is a credential lifetime with NO fact behind it and "+
					"nothing cited. That is clock-driven state, which principles.md "+
					"forbids, so it is an exception-register row or a tracked issue — "+
					"not a blank column.", timerRegisterPath, id)
			}
		}
	}

	t.Logf("timer audit: %d row(s) · tick %d · ttl %d · io-bound %d · retention %d · "+
		"%d lifetime(s) with no fact behind them",
		len(rows), counts["tick"], counts["ttl"], counts["io-bound"],
		counts["retention"], clockDriven)
}
