package gatereg_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both gates in this package are AST scans held against a register file, and
// both have the same worst failure: a scan that quietly stops finding things
// reports a complete register forever. So the scans are run against fixture
// trees here, where what they are supposed to find is known.
//
// The register CONTRACTS — a missing row, a stale row, a row with no fact —
// are exercised by the tests above against the real registers; what cannot be
// exercised there is the discovery, because the real tree has no way to grow a
// new ticker inside a test.

func fixtureTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	// The scans check for go.work at the root, so the fixture looks like a
	// repo rather than a directory that happens to hold Go files.
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.26.0\n"), 0o600); err != nil {
		t.Fatalf("write go.work: %v", err)
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

func TestTimerDiscoveryFindsWhatTheAuditIsFor(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"api/a.go": `package a

import "time"

const (
	sessionLifetime = 7 * 24 * time.Hour
	someTimeout     = 3 * time.Second
	renewWindow     = 60 * time.Hour
	unrelated       = 5
)

type S struct{}

func (s *S) loop() { _ = time.NewTicker(time.Second) }

func plain() { _ = time.NewTimer(time.Second) }

func fires() { _ = time.AfterFunc(time.Second, func() {}) }
`,
		// A test file, which the audit does not read: a bound in a test
		// decides nothing on a node.
		"api/a_test.go": `package a

import "time"

const decoyTTL = time.Hour

func decoy() { _ = time.NewTicker(time.Second) }
`,
		// A module the audit does not scan.
		"tileschema/b.go": `package b

import "time"

const otherTTL = time.Hour
`,
	})

	found := discoverTimers(t, root)

	for _, want := range []string{
		"api/a.go#sessionLifetime",
		"api/a.go#renewWindow",
		"api/a.go#S.loop:NewTicker",
		"api/a.go#plain:NewTimer",
		"api/a.go#fires:AfterFunc",
	} {
		if _, ok := found[want]; !ok {
			keys := make([]string, 0, len(found))
			for k := range found {
				keys = append(keys, k)
			}
			t.Errorf("the scan missed %s. A scan that stops finding things reports a "+
				"complete audit forever.\nfound: %s", want, strings.Join(keys, ", "))
		}
	}

	for _, unwanted := range []string{
		"api/a.go#someTimeout", // a plain I/O timeout: excluded on purpose
		"api/a.go#unrelated",
		"api/a_test.go#decoyTTL",
		"api/a_test.go#decoy:NewTicker",
		"tileschema/b.go#otherTTL",
	} {
		if _, ok := found[unwanted]; ok {
			t.Errorf("the scan picked up %s, which the audit deliberately does not "+
				"cover; sweeping those in buries the bounds that matter", unwanted)
		}
	}
}

func TestCapabilityPinReadsTheTreeAndNotTheRegister(t *testing.T) {
	root := fixtureTree(t, map[string]string{
		"api/internal/obs/supervisor.go": `package obs

const defaultAlloyImage = "grafana/alloy:v9.9.9"
`,
		"api/go.mod": "module x\n\ngo 1.26.0\n\nrequire github.com/nats-io/nats-server/v2 v2.99.0\n",
	})

	got, checkable, problem := resolvePin(t, root,
		"go-const:api/internal/obs/supervisor.go#defaultAlloyImage")
	if problem != "" || !checkable {
		t.Fatalf("resolvePin: checkable=%v problem=%q", checkable, problem)
	}
	if got != "v9.9.9" {
		t.Fatalf("resolvePin read %q; it must read the version the TREE pins, or a "+
			"bump could never disagree with the register", got)
	}

	got, checkable, problem = resolvePin(t, root, "go-mod:api/go.mod#github.com/nats-io/nats-server/v2")
	if problem != "" || !checkable || got != "v2.99.0" {
		t.Fatalf("resolvePin(go-mod) = %q, %v, %q; want v2.99.0", got, checkable, problem)
	}

	// A pin in another repository is reported as unchecked, never as matching.
	_, checkable, problem = resolvePin(t, root, "elsewhere:rasputin-os package/rauc")
	if checkable || problem != "" {
		t.Fatalf("an `elsewhere` pin must be reported as unchecked, got checkable=%v problem=%q",
			checkable, problem)
	}

	// Every way of getting the pin wrong has to say so rather than resolve to
	// an empty version, which would silently equal an empty register column.
	for _, tc := range []struct{ name, pin, want string }{
		{"a constant that is gone", "go-const:api/internal/obs/supervisor.go#defaultGoneImage", "no constant"},
		{"a file that is gone", "go-const:api/internal/obs/nope.go#defaultAlloyImage", "cannot read"},
		{"a module that is not required", "go-mod:api/go.mod#github.com/absent/thing", "no require line"},
		{"no target", "go-const:api/go.mod", "names no"},
		{"an unknown kind", "magic:api/go.mod#x", "unknown pin kind"},
		{"empty", "", "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, problem := resolvePin(t, root, tc.pin)
			if problem == "" {
				t.Fatalf("resolvePin(%q) reported no problem", tc.pin)
			}
			if !strings.Contains(problem, tc.want) {
				t.Fatalf("resolvePin(%q) said %q, want it to mention %q", tc.pin, problem, tc.want)
			}
		})
	}
}
