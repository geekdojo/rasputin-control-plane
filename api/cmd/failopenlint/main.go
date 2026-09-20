// Command failopenlint refuses the shapes that turn a security control into a
// suggestion. Every rule is an error; none of them has a severity to lower.
//
// # Why these shapes and not others
//
// Each rule below was written from a pattern this tree actually grew, one
// reasonable-sounding local decision at a time. None of them looked wrong in
// the diff that introduced it; each of them means that when something is
// missing, malformed or unreadable, the code continues with less protection
// instead of stopping. That is the single failure mode this command exists to
// make unrepeatable:
//
//	FO01  InsecureSkipVerify outside a pinned-TLS helper. Skipping
//	      verification is safe exactly when something else does the
//	      verifying, in the same tls.Config, and never otherwise.
//	FO02  discarding the error from an authorization predicate. `ok, _ :=
//	      Allowed(...)` turns "I could not tell" into "no", or into "yes",
//	      depending on the zero value — and the reader cannot see which.
//	FO03  `if secret == "" { return nil }`. An absent credential is the one
//	      case where the check matters most, and this is the shape that
//	      skips it.
//	FO04  reading a security-relevant RASPUTIN_* variable outside a declared
//	      resolver. A setting parsed inline cannot be table-tested, so
//	      nobody ever learns what it does when it is empty or malformed.
//	      The declared resolvers are .github/security-resolvers.tsv, and
//	      each one owes a fail-closed table test.
//	FO05  x509.SystemCertPool in agent or backupxfer code. Those talk to
//	      our own control plane, which is not in the Web PKI; reaching for
//	      the system pool means the pin or the private root was not wired.
//	FO06  x509.ExtKeyUsageAny. It accepts a certificate issued for any
//	      purpose, which is the whole of what a purpose OID is for.
//	FO07  a dev-relaxation variable read without consulting the release
//	      marker in the same function. A development convenience that is
//	      live in production is not a development convenience.
//
// # Allowances
//
// .github/failopen-allow.tsv records every site the rules fire on that is not
// being changed right now. An allowance is NOT a lowered severity: the rule
// still fires, the finding still has a verdict and a reason, and a `blocked`
// row must cite the issue that will close it. The gate fails on an allowance
// that no longer matches anything, so a row cannot outlive the code it
// describes — the same discipline as .github/sast-register.tsv.
//
// # Why this lives in api/cmd
//
// It reads the whole tree but imports nothing from it. Put here rather than in
// a new go.work module, it inherits gosec, staticcheck, CodeQL, Dependabot and
// CI's build-and-test with no edit to go.work and no edit to the one module
// list Dependabot still needs written by hand.
//
// Usage:
//
//	go run ./api/cmd/failopenlint            # lint the repo from its root
//	go run ./api/cmd/failopenlint -root DIR  # lint another tree (tests)
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// finding is one rule firing at one place.
type finding struct {
	Rule   string
	Path   string // repo-relative, slash-separated
	Line   int
	Symbol string // the enclosing declaration, or the matched identifier
	Detail string
}

func (f finding) key() string { return f.Rule + "\x00" + f.Path + "\x00" + f.Symbol }

// ── rule inputs ─────────────────────────────────────────────────────────────

// securityEnvKey matches the RASPUTIN_* variables whose value can move a
// security decision. It is a PATTERN, not a list, so a variable added
// tomorrow is covered without anyone remembering to add it — which is the
// property a list has never had in this repo.
var securityEnvKey = regexp.MustCompile(
	`^RASPUTIN_.*(AUTH|TLS|TRUST|PIN|SECRET|TOKEN|KEY|CERT|ORIGIN|RP_ID|RP_ORIGINS|SECURE|INSECURE|FINGERPRINT|PERMISSIVE|DEBUG|BACKEND)`)

// devRelaxationEnvKey matches the variables that exist to make development
// easier. Each must be read in a function that also consults the release
// marker, so the relaxation cannot be live on an appliance.
var devRelaxationEnvKey = regexp.MustCompile(`^RASPUTIN_(DEBUG|DEV)_`)

// releaseMarkers are the calls that answer "is this a released image?". A
// function reading a dev-relaxation variable must call one of them.
var releaseMarkers = map[string]bool{
	"ImageVersion": true,
	"BootID":       true,
	"IsAppliance":  true,
	"Released":     true,
}

// authorizationPredicates are the calls whose error may not be dropped. The
// list is deliberately explicit rather than a name pattern: at error level a
// false positive costs more than a missed call, and a call added to this list
// is a one-line edit that arrives with the review of the code that needed it.
var authorizationPredicates = map[string]bool{
	"Admit":                 true,
	"Admitted":              true,
	"Allows":                true,
	"Authorize":             true,
	"CheckRestoreCustody":   true,
	"FirstRun":              true,
	"GetBool":               true,
	"Healthy":               true,
	"IsSet":                 true,
	"NodeHasLiveToken":      true,
	"RequireSession":        true,
	"StackReady":            true,
	"TrustConfigured":       true,
	"Validate":              true,
	"VerifyForPurpose":      true,
	"requestOriginAllowed":  true,
	"isSelfAgentToken":      true,
	"nodeHasSelfAgentToken": true,
}

// secretish names the identifiers whose emptiness must never be a reason to
// skip a check.
var secretish = regexp.MustCompile(`(?i)(secret|token|password|passphrase|credential|fingerprint|pin|apikey|api_key)$`)

// modulePrefixes for FO05: the code that talks to our own control plane and
// therefore has a private trust root or a pin, never the Web PKI.
var noSystemPool = []string{"agent/", "backupxfer/"}

func main() {
	root := flag.String("root", ".", "tree to lint")
	allowPath := flag.String("allow", ".github/failopen-allow.tsv", "allowance register, relative to -root")
	resolvers := flag.String("resolvers", ".github/security-resolvers.tsv", "declared resolvers, relative to -root")
	flag.Parse()

	code, err := run(*root, *allowPath, *resolvers, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "::error::failopenlint: %v\n", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func run(root, allowPath, resolverPath string, out io.Writer) (int, error) {
	allow, err := readAllow(filepath.Join(root, allowPath))
	if err != nil {
		return 0, err
	}
	resolverRows, err := readResolvers(filepath.Join(root, resolverPath))
	if err != nil {
		return 0, err
	}
	declared := map[string]bool{}
	for _, r := range resolverRows {
		declared[r["path"]+"#"+r["symbol"]] = true
	}

	findings, err := scan(root, declared)
	if err != nil {
		return 0, err
	}

	var unallowed []finding
	used := map[string]bool{}
	for _, f := range findings {
		if _, ok := allow[f.key()]; ok {
			used[f.key()] = true
			continue
		}
		unallowed = append(unallowed, f)
	}

	var stale []allowance
	for k, a := range allow {
		if !used[k] {
			stale = append(stale, a)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].line < stale[j].line })

	// The posture line, always. A gate that prints nothing when it passes
	// reads as "there is nothing here", and there is something here.
	fmt.Fprintf(out, "failopenlint: %d finding(s) · %d allowed · %d to fix\n",
		len(findings), len(findings)-len(unallowed), len(unallowed))
	blocked := map[string]bool{}
	for _, a := range allow {
		if a.verdict == "blocked" && a.issue != "" {
			blocked[a.issue] = true
		}
	}
	if len(blocked) > 0 {
		keys := make([]string, 0, len(blocked))
		for k := range blocked {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(out, "allowed pending a fix: %s\n", strings.Join(keys, ", "))
	}

	resolverProblems := checkResolvers(root, resolverRows, out)

	fail := false
	if len(resolverProblems) > 0 {
		fail = true
		fmt.Fprintf(out, "\n::error::%d problem(s) in the security-resolver register:\n", len(resolverProblems))
		for _, p := range resolverProblems {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}
	if len(unallowed) > 0 {
		fail = true
		fmt.Fprintf(out, "\n::error::%d fail-open finding(s) with no allowance:\n", len(unallowed))
		for _, f := range unallowed {
			fmt.Fprintf(out, "  %s  %s:%d  %s — %s\n", f.Rule, f.Path, f.Line, f.Symbol, f.Detail)
		}
		fmt.Fprintln(out, "Fix it. If it cannot be fixed now, add a row to")
		fmt.Fprintln(out, ".github/failopen-allow.tsv with a verdict and its reasoning; a")
		fmt.Fprintln(out, "'blocked' row must cite the issue that will close it. Do NOT weaken")
		fmt.Fprintln(out, "a rule to make this pass — every rule here is an error and stays one.")
	}
	if len(stale) > 0 {
		fail = true
		fmt.Fprintf(out, "\n::error::%d allowance(s) match nothing any more:\n", len(stale))
		for _, a := range stale {
			fmt.Fprintf(out, "  %s  %s  %s\n", a.rule, a.path, a.symbol)
		}
		fmt.Fprintln(out, "The code an allowance described is gone or has changed. Delete the")
		fmt.Fprintln(out, "row, or re-point it at the code as it is now — an allowance that")
		fmt.Fprintln(out, "outlives its site is a permission nobody granted.")
	}
	if fail {
		return 1, nil
	}
	return 0, nil
}

// ── the scan ────────────────────────────────────────────────────────────────

func scan(root string, declared map[string]bool) ([]finding, error) {
	var out []finding
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
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		found, ferr := parseFile(path, rel, declared)
		if ferr != nil {
			return ferr
		}
		out = append(out, found...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}

func parseFile(path, rel string, declared map[string]bool) ([]finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}

	var out []finding
	// enclosing tracks the innermost function declaration, so a finding names
	// a symbol a person can search for rather than only a line that moves.
	type fnInfo struct {
		name     string
		calls    map[string]bool
		envReads []finding
	}
	var fn *fnInfo
	// where names the enclosing declaration when there is one, so a finding
	// points at a symbol a person can search for rather than only a line
	// number that the next edit moves.
	where := func(fallback string) string {
		if fn != nil {
			return fn.name
		}
		return fallback
	}
	add := func(rule, symbol, detail string, pos token.Pos) {
		out = append(out, finding{
			Rule: rule, Path: rel, Line: fset.Position(pos).Line,
			Symbol: symbol, Detail: detail,
		})
	}

	// flushFn applies the rules that need the whole function body first.
	flushFn := func() {
		if fn == nil {
			return
		}
		for _, r := range fn.envReads {
			key := r.Detail
			switch {
			case devRelaxationEnvKey.MatchString(key):
				marked := false
				for c := range fn.calls {
					if releaseMarkers[c] {
						marked = true
						break
					}
				}
				if !marked {
					r.Rule = "FO07"
					r.Symbol += ":" + key
					r.Detail = key + " is read without consulting a release marker in the same function"
					out = append(out, r)
				}
			case securityEnvKey.MatchString(key):
				if !declared[rel+"#"+r.Symbol] {
					r.Rule = "FO04"
					// The variable's name is part of the symbol, so an
					// allowance covers ONE setting. Keyed on the enclosing
					// function alone, a single allowance for `main` would
					// quietly cover the next setting someone reads there.
					r.Symbol += ":" + key
					r.Detail = key + " is read outside a declared resolver"
					out = append(out, r)
				}
			}
		}
		fn = nil
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			flushFn()
			name := node.Name.Name
			if node.Recv != nil && len(node.Recv.List) > 0 {
				name = receiverType(node.Recv.List[0].Type) + "." + name
			}
			fn = &fnInfo{name: name, calls: map[string]bool{}}

		case *ast.KeyValueExpr:
			// FO01 as a struct field: InsecureSkipVerify: true.
			if id, ok := node.Key.(*ast.Ident); ok && id.Name == "InsecureSkipVerify" {
				if !isFalseLiteral(node.Value) {
					add("FO01", where("InsecureSkipVerify"),
						"InsecureSkipVerify is set outside the pinned-TLS helper", node.Pos())
				}
			}

		case *ast.AssignStmt:
			// FO01 as an assignment: cfg.InsecureSkipVerify = true.
			for i, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "InsecureSkipVerify" {
					if i < len(node.Rhs) && !isFalseLiteral(node.Rhs[i]) {
						add("FO01", where("InsecureSkipVerify"),
							"InsecureSkipVerify is set outside the pinned-TLS helper", node.Pos())
					}
				}
			}
			// FO02: the error of an authorization predicate dropped into _.
			if len(node.Rhs) == 1 {
				if call, ok := node.Rhs[0].(*ast.CallExpr); ok {
					if name := calleeName(call); authorizationPredicates[name] && dropsLast(node.Lhs) {
						add("FO02", where(name),
							"the error from "+name+" is discarded", node.Pos())
					}
				}
			}

		case *ast.IfStmt:
			// FO03: skipping when a secret is empty.
			if id, ok := emptyStringCompare(node.Cond); ok && secretish.MatchString(id) && skips(node.Body) {
				add("FO03", where(id),
					"an empty "+id+" skips the check instead of failing", node.Pos())
			}

		case *ast.SelectorExpr:
			switch node.Sel.Name {
			case "SystemCertPool":
				for _, p := range noSystemPool {
					if strings.HasPrefix(rel, p) {
						add("FO05", where("SystemCertPool"),
							"the system certificate pool is used in "+strings.TrimSuffix(p, "/")+" code", node.Pos())
						break
					}
				}
			case "ExtKeyUsageAny":
				add("FO06", where("ExtKeyUsageAny"),
					"ExtKeyUsageAny accepts a certificate issued for any purpose", node.Pos())
			}

		case *ast.CallExpr:
			if fn != nil {
				if name := calleeName(node); name != "" {
					fn.calls[name] = true
				}
			}
			if key, ok := envKey(node); ok && fn != nil {
				fn.envReads = append(fn.envReads, finding{
					Path: rel, Line: fset.Position(node.Pos()).Line,
					Symbol: fn.name, Detail: key,
				})
			}
		}
		return true
	})
	flushFn()
	return out, nil
}

// ── small AST helpers ───────────────────────────────────────────────────────

func receiverType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return receiverType(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return receiverType(t.X)
	case *ast.IndexListExpr:
		return receiverType(t.X)
	}
	return "?"
}

func calleeName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.IndexExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func isFalseLiteral(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}

// dropsLast reports whether the last assignment target is the blank
// identifier — the error position of a Go call that returns (T, error).
func dropsLast(lhs []ast.Expr) bool {
	if len(lhs) < 2 {
		return false
	}
	id, ok := lhs[len(lhs)-1].(*ast.Ident)
	return ok && id.Name == "_"
}

// emptyStringCompare returns the identifier compared to "" by ==.
func emptyStringCompare(e ast.Expr) (string, bool) {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return "", false
	}
	name := ""
	switch x := bin.X.(type) {
	case *ast.Ident:
		name = x.Name
	case *ast.SelectorExpr:
		name = x.Sel.Name
	default:
		return "", false
	}
	lit, ok := bin.Y.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	if s, err := strconv.Unquote(lit.Value); err != nil || s != "" {
		return "", false
	}
	return name, true
}

// skips reports whether a block's only effect is to leave the check —
// `return`, `return nil`, or `continue`. A block that returns an error, or
// does anything else, is not skipping.
func skips(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	switch last := b.List[len(b.List)-1].(type) {
	case *ast.BranchStmt:
		return last.Tok == token.CONTINUE
	case *ast.ReturnStmt:
		if len(last.Results) == 0 {
			return true
		}
		for _, r := range last.Results {
			switch v := r.(type) {
			case *ast.Ident:
				if v.Name != "nil" && v.Name != "true" {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	return false
}

// envReaders are the calls that turn a variable name into a value: the
// standard library's two, and the package-local wrappers this tree grew. The
// wrappers matter as much as os.Getenv — a setting read through envOr is
// exactly as unreachable from a table test as one read through os.Getenv.
var envReaders = map[string]bool{
	"Getenv":      true,
	"LookupEnv":   true,
	"envOr":       true,
	"envBool":     true,
	"envBoolPtr":  true,
	"envDuration": true,
}

// envKey returns the literal variable name an env-reading call names.
func envKey(c *ast.CallExpr) (string, bool) {
	name := ""
	switch f := c.Fun.(type) {
	case *ast.SelectorExpr:
		pkg, ok := f.X.(*ast.Ident)
		if !ok || pkg.Name != "os" {
			return "", false
		}
		name = f.Sel.Name
	case *ast.Ident:
		name = f.Name
	default:
		return "", false
	}
	if !envReaders[name] {
		return "", false
	}
	if len(c.Args) == 0 {
		return "", false
	}
	lit, ok := c.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// ── registers ───────────────────────────────────────────────────────────────

type allowance struct {
	rule, path, symbol, verdict, issue, reasoning string
	line                                          int
}

func readAllow(path string) (map[string]allowance, error) {
	rows, err := readTSV(path, []string{"rule", "path", "symbol", "verdict", "issue", "reasoning"})
	if err != nil {
		return nil, err
	}
	out := map[string]allowance{}
	for i, r := range rows {
		a := allowance{
			rule: r["rule"], path: r["path"], symbol: r["symbol"],
			verdict: r["verdict"], issue: r["issue"], reasoning: r["reasoning"],
			line: i + 1,
		}
		switch a.verdict {
		case "deliberate", "blocked", "false-positive":
		default:
			return nil, fmt.Errorf("%s: unknown verdict %q for %s %s (want deliberate, blocked or false-positive)",
				path, a.verdict, a.rule, a.path)
		}
		if strings.TrimSpace(a.reasoning) == "" {
			return nil, fmt.Errorf("%s: %s %s %s has no reasoning — an allowance with no stated reason is a suppression",
				path, a.rule, a.path, a.symbol)
		}
		if a.verdict == "blocked" && strings.TrimSpace(a.issue) == "" {
			return nil, fmt.Errorf("%s: %s %s %s is blocked with no issue cited — it can never be revisited",
				path, a.rule, a.path, a.symbol)
		}
		out[a.rule+"\x00"+a.path+"\x00"+a.symbol] = a
	}
	return out, nil
}

func readResolvers(path string) ([]map[string]string, error) {
	return readTSV(path, []string{"id", "path", "symbol", "reads", "test", "status", "cite"})
}

// checkResolvers holds .github/security-resolvers.tsv to its own contract: the
// resolver it names still exists, a `covered` row names a test that exists,
// and a `pending` row cites the issue that will cover it.
//
// The register is the other half of the FO04 rule. FO04 says a security
// setting is read inside a named resolver; this says every named resolver owes
// a fail-closed table test over {absent, empty, malformed, unreadable, probe
// error}. Without this half, "declared resolver" would mean nothing more than
// "written down", and declaring one would be a way past the rule rather than a
// commitment to test it.
func checkResolvers(root string, rows []map[string]string, out io.Writer) []string {
	var problems []string
	tests := map[string]bool{}
	seen := map[string]bool{}
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
			tests[m[1]] = true
		}
		return nil
	})

	covered, pending := 0, 0
	for _, r := range rows {
		id := r["id"]
		if id == "" {
			problems = append(problems, "a resolver row has no id")
			continue
		}
		if seen[id] {
			problems = append(problems, id+": duplicate id")
		}
		seen[id] = true
		if r["path"] == "" || r["symbol"] == "" {
			problems = append(problems, id+": path and symbol are both required")
			continue
		}
		if !declares(filepath.Join(root, r["path"]), r["symbol"]) {
			problems = append(problems, fmt.Sprintf(
				"%s: %s declares no %s — the resolver was renamed, moved or deleted",
				id, r["path"], r["symbol"]))
		}
		switch r["status"] {
		case "covered":
			covered++
			if r["test"] == "" {
				problems = append(problems, id+": covered with no test named")
				continue
			}
			for _, t := range strings.Split(r["test"], " ") {
				if t == "" {
					continue
				}
				if !tests[t] {
					problems = append(problems, fmt.Sprintf(
						"%s: no test named %s exists — a register that names a test nobody wrote is worse than none",
						id, t))
				}
			}
		case "pending":
			pending++
			if r["cite"] == "" {
				problems = append(problems, id+": pending with no issue cited — it can never be picked up")
			}
			if r["test"] != "" {
				problems = append(problems, id+": pending but names a test; mark it covered")
			}
		default:
			problems = append(problems, fmt.Sprintf("%s: unknown status %q (want covered or pending)", id, r["status"]))
		}
	}
	fmt.Fprintf(out, "security resolvers: %d declared · %d with a fail-closed test · %d owed\n",
		len(rows), covered, pending)
	return problems
}

var testDecl = regexp.MustCompile(`(?m)^func (Test\w+)\(`)

// declares reports whether a Go file declares the named symbol, accepting the
// same forms the resolver register uses: a function, a Type.Method, or a
// const/var name inside a grouped block.
func declares(path, symbol string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	recv, name, hasRecv := strings.Cut(symbol, ".")
	if !hasRecv {
		recv, name = "", recv
	}
	var pat *regexp.Regexp
	if recv != "" {
		pat = regexp.MustCompile(`(?m)^func \(\s*\w+ \*?` + regexp.QuoteMeta(recv) + `\)\s*` + regexp.QuoteMeta(name) + `\b`)
	} else {
		pat = regexp.MustCompile(`(?m)^(func|type|const|var)\s+` + regexp.QuoteMeta(name) + `\b|^\s+` + regexp.QuoteMeta(name) + `\s*(=|\w)`)
	}
	return pat.Match(b)
}

// readTSV reads a tab-separated register with a '#' comment convention and a
// header naming every column, and refuses a header that does not match.
func readTSV(path string, cols []string) ([]map[string]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Read-only: nothing is buffered, so a close error carries no
	// information this command could act on.
	defer func() { _ = fh.Close() }()

	var out []map[string]string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	header := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if !header {
			if len(parts) != len(cols) {
				return nil, fmt.Errorf("%s: header has %d columns, want %d (%s)",
					path, len(parts), len(cols), strings.Join(cols, ", "))
			}
			for i, c := range cols {
				if parts[i] != c {
					return nil, fmt.Errorf("%s: header column %d is %q, want %q", path, i+1, parts[i], c)
				}
			}
			header = true
			continue
		}
		if len(parts) != len(cols) {
			return nil, fmt.Errorf("%s: a row has %d fields, want %d", path, len(parts), len(cols))
		}
		row := map[string]string{}
		for i, c := range cols {
			row[c] = parts[i]
		}
		out = append(out, row)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !header {
		return nil, fmt.Errorf("%s: no header row", path)
	}
	return out, nil
}
