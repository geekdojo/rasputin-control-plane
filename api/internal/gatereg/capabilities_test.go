package gatereg_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The third-party capability register (geekdojo/geekdojo-brain#496, gate 9).
//
// Several of this system's security properties are not ours. They are
// behaviours of an upstream project that we read once, at one version, and
// then built on: that a rule evaluator will start with no notifier when told
// to blackhole, that a mesh server can expire an API key by prefix, that a
// collector's TLS block refuses a client with no certificate, that a config
// server's load endpoint is a no-op for an unchanged config.
//
// Each of those was true at the version someone checked. None of them is a
// promise. A version bump is exactly the moment a vendor behaviour changes,
// and it is also the moment nobody re-reads the reasoning that depended on it
// — so the bump is where this gate sits: the register records the version, the
// test reads the version the tree actually pins, and a difference fails until
// the row has been re-verified at the new one.
//
// Rows whose pin lives in another repository cannot be checked from here. They
// are recorded anyway, with the file that carries the pin, and reported as
// unchecked rather than counted as verified.

const capRegisterPath = ".github/third-party-capabilities.tsv"

var capCols = []string{"id", "vendor", "version", "capability", "verified", "pin", "cite"}

func root(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p, "go.work")); err != nil {
		t.Fatalf("%s does not look like the repo root: %v", p, err)
	}
	return p
}

func readRegister(t *testing.T, path string, cols []string) []map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []map[string]string
	header := false
	for n, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if !header {
			if len(parts) != len(cols) {
				t.Fatalf("%s:%d: header has %d columns, want %d", path, n+1, len(parts), len(cols))
			}
			for i, c := range cols {
				if parts[i] != c {
					t.Fatalf("%s:%d: column %d is %q, want %q", path, n+1, i+1, parts[i], c)
				}
			}
			header = true
			continue
		}
		if len(parts) != len(cols) {
			t.Fatalf("%s:%d: %d fields, want %d", path, n+1, len(parts), len(cols))
		}
		row := map[string]string{}
		for i, c := range cols {
			row[c] = parts[i]
		}
		out = append(out, row)
	}
	if !header {
		t.Fatalf("%s: no header row", path)
	}
	return out
}

// goConstImage matches `name = "repo/image:tag"` so the tag can be read out of
// a Go constant without building the package.
func goConstImage(src, name string) (string, bool) {
	// The declaration is usually inside a grouped const block, but `const x =`
	// and `var x =` at the top level have to match too, or the resolver reads
	// nothing and every comparison fails for the wrong reason.
	re := regexp.MustCompile(`(?m)^\s*(?:const |var )?` + regexp.QuoteMeta(name) + `\s*=\s*"([^"]+)"`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		return "", false
	}
	ref := m[1]
	// Strip any digest first: "repo:tag@sha256:..." — the tag is what a vendor
	// capability is recorded against.
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i+1:], "/") {
		return "", false
	}
	return ref[i+1:], true
}

// goModVersion reads a module's version out of a go.mod require line.
func goModVersion(src, module string) (string, bool) {
	re := regexp.MustCompile(`(?m)^\s*(?:require )?` + regexp.QuoteMeta(module) + `\s+(v\S+)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// resolvePin reads the version the tree actually pins for a row.
//
// The pin column names where to look:
//
//	go-const:<path>#<Name>   a Go constant holding "repo/image:tag"
//	go-mod:<path>#<module>   a require line in a go.mod
//	elsewhere:<repo path>    the pin lives in another repository
func resolvePin(t *testing.T, repo, pin string) (version string, checkable bool, err string) {
	t.Helper()
	kind, rest, ok := strings.Cut(pin, ":")
	if !ok || rest == "" {
		return "", false, "pin is malformed; want go-const:, go-mod: or elsewhere:"
	}
	if kind == "elsewhere" {
		return "", false, ""
	}
	path, target, ok := strings.Cut(rest, "#")
	if !ok {
		return "", false, "pin names no '#<target>'"
	}
	b, rerr := os.ReadFile(filepath.Join(repo, path))
	if rerr != nil {
		return "", true, "cannot read " + path + ": " + rerr.Error()
	}
	switch kind {
	case "go-const":
		v, found := goConstImage(string(b), target)
		if !found {
			return "", true, "no constant " + target + " holding an image reference in " + path
		}
		return v, true, ""
	case "go-mod":
		v, found := goModVersion(string(b), target)
		if !found {
			return "", true, "no require line for " + target + " in " + path
		}
		return v, true, ""
	}
	return "", false, "unknown pin kind " + kind
}

func TestThirdPartyCapabilityRegister(t *testing.T) {
	repo := root(t)
	rows := readRegister(t, filepath.Join(repo, capRegisterPath), capCols)
	if len(rows) == 0 {
		t.Fatal("the register has no rows, so this gate is checking nothing")
	}

	ids := map[string]bool{}
	checked, elsewhere, unverified := 0, 0, 0

	for _, r := range rows {
		id := r["id"]
		if ids[id] {
			t.Errorf("%s: duplicate id %s", capRegisterPath, id)
		}
		ids[id] = true

		for _, f := range []string{"vendor", "capability", "verified", "pin"} {
			if strings.TrimSpace(r[f]) == "" {
				t.Errorf("%s: %s has an empty %s", capRegisterPath, id, f)
			}
		}

		// "how it was verified" is the column that makes this a record rather
		// than a wish. A row that says only "it works" is one nobody can
		// re-run, which is what a version bump needs.
		if strings.EqualFold(strings.TrimSpace(r["verified"]), "unverified") {
			unverified++
			if strings.TrimSpace(r["cite"]) == "" {
				t.Errorf("%s: %s is unverified with no probe cited. An unchecked "+
					"premise is recorded together with the thing that will settle it.",
					capRegisterPath, id)
			}
			continue
		}

		want := strings.TrimSpace(r["version"])
		if want == "" {
			t.Errorf("%s: %s names no version, so nothing can tell when it moved",
				capRegisterPath, id)
			continue
		}

		got, checkable, problem := resolvePin(t, repo, r["pin"])
		if problem != "" {
			t.Errorf("%s: %s: %s", capRegisterPath, id, problem)
			continue
		}
		if !checkable {
			elsewhere++
			continue
		}
		checked++
		if got != want {
			t.Errorf("%s: %s is recorded against %s %s, but this tree pins %s.\n"+
				"  Capability: %s\n"+
				"  Verified: %s\n"+
				"A version bump is exactly when a vendor behaviour changes, and exactly "+
				"when nobody re-reads what depended on it. Re-verify the capability at "+
				"%s, then update the row — do not update the row to make this pass.",
				capRegisterPath, id, r["vendor"], want, got, r["capability"], r["verified"], got)
		}
	}

	// The posture, always. A green run that printed nothing would read as
	// "every vendor behaviour is confirmed", and several are recorded at a
	// version this repo cannot see.
	t.Logf("third-party capabilities: %d row(s) · %d pinned here and matching · "+
		"%d pinned in another repository · %d unverified",
		len(rows), checked, elsewhere, unverified)
	if checked == 0 {
		t.Error("no row's pin was checkable from this repo, so the gate that is supposed " +
			"to fire on a version bump would never fire")
	}
}

// The register's pin resolver, against inputs that must not be mistaken for a
// version. A resolver that silently returned "" would make every row's
// comparison fail — or, worse, make a row whose constant was renamed look
// unchanged.
func TestResolvePinReadsTheTreesActualVersion(t *testing.T) {
	const src = `package x

const (
	plainTag   = "grafana/alloy:v1.4.2"
	withDigest = "grafana/loki:3.4.1@sha256:aaaa"
	hostPort   = "registry.example.com:5000/thing:9.9.9"
	noTag      = "headscale/headscale"
	portNoTag  = "registry.example.com:5000/thing"
)
`
	for _, tc := range []struct {
		name, konst, want string
		ok                bool
	}{
		{"a plain tag", "plainTag", "v1.4.2", true},
		{"a digest beside the tag", "withDigest", "3.4.1", true},
		{"a registry port is not a tag", "hostPort", "9.9.9", true},
		{"no tag at all", "noTag", "", false},
		{"a registry port and no tag", "portNoTag", "", false},
		{"a constant that is not there", "missing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := goConstImage(src, tc.konst)
			if ok != tc.ok {
				t.Fatalf("goConstImage(%s) ok = %v, want %v (got %q)", tc.konst, ok, tc.ok, got)
			}
			if got != tc.want {
				t.Fatalf("goConstImage(%s) = %q, want %q", tc.konst, got, tc.want)
			}
		})
	}

	const mod = `module x

go 1.26.0

require (
	github.com/nats-io/nats-server/v2 v2.14.6
	github.com/nats-io/nats.go v1.53.1
)
`
	if v, ok := goModVersion(mod, "github.com/nats-io/nats-server/v2"); !ok || v != "v2.14.6" {
		t.Fatalf("goModVersion = %q, %v; want v2.14.6, true", v, ok)
	}
	// A prefix must not match a different module: nats.go and nats-server/v2
	// both begin with the same path.
	if v, ok := goModVersion(mod, "github.com/nats-io/nats.go"); !ok || v != "v1.53.1" {
		t.Fatalf("goModVersion = %q, %v; want v1.53.1, true", v, ok)
	}
	if _, ok := goModVersion(mod, "github.com/nats-io/absent"); ok {
		t.Fatal("goModVersion found a module that is not required")
	}
}
