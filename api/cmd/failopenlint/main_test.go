package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every case here is a tree this lint MUST refuse, or one it must not. A gate
// nobody has fed a bad input to is a gate nobody knows the shape of — and this
// one is the reason a reviewer gets to assume the shapes below are absent, so
// a rule that silently stopped matching would be worse than no rule at all.

// tree writes a throwaway repo: the two registers plus the named Go files.
func tree(t *testing.T, allow, resolvers string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	mk(".github/failopen-allow.tsv",
		"rule\tpath\tsymbol\tverdict\tissue\treasoning\n"+allow)
	mk(".github/security-resolvers.tsv",
		"id\tpath\tsymbol\treads\ttest\tstatus\tcite\n"+resolvers)
	for rel, body := range files {
		mk(rel, body)
	}
	return root
}

// lint runs the gate over a tree and returns its exit code and output.
func lint(t *testing.T, root string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	code, err := run(root, ".github/failopen-allow.tsv", ".github/security-resolvers.tsv", &buf)
	if err != nil {
		return 2, err.Error()
	}
	return code, buf.String()
}

// refuses asserts the gate fails and says why in terms the author can act on.
func refuses(t *testing.T, root, want string) {
	t.Helper()
	code, out := lint(t, root)
	if code == 0 {
		t.Fatalf("gate passed; it must refuse this.\n%s", out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("output does not mention %q.\n%s", want, out)
	}
}

func passes(t *testing.T, root string) string {
	t.Helper()
	code, out := lint(t, root)
	if code != 0 {
		t.Fatalf("gate refused a tree it should accept.\n%s", out)
	}
	return out
}

const pkgHeader = "package x\n\nimport (\n\t\"crypto/tls\"\n\t\"crypto/x509\"\n\t\"os\"\n)\n\nvar _ = os.Getenv\nvar _ = tls.Config{}\nvar _ = x509.ExtKeyUsageServerAuth\n"

func TestFO01_InsecureSkipVerify(t *testing.T) {
	t.Run("in a composite literal", func(t *testing.T) {
		root := tree(t, "", "", map[string]string{"agent/a.go": pkgHeader + `
func dial() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`})
		refuses(t, root, "FO01")
	})

	t.Run("by assignment", func(t *testing.T) {
		root := tree(t, "", "", map[string]string{"agent/a.go": pkgHeader + `
func dial(c *tls.Config) { c.InsecureSkipVerify = true }
`})
		refuses(t, root, "FO01")
	})

	t.Run("explicitly false is not a finding", func(t *testing.T) {
		root := tree(t, "", "", map[string]string{"agent/a.go": pkgHeader + `
func dial() *tls.Config { return &tls.Config{InsecureSkipVerify: false} }
`})
		passes(t, root)
	})

	t.Run("an allowance with a reason accepts it", func(t *testing.T) {
		root := tree(t,
			"FO01\tagent/a.go\tdial\tdeliberate\t\tthe pin is checked in VerifyConnection\n",
			"", map[string]string{"agent/a.go": pkgHeader + `
func dial() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`})
		out := passes(t, root)
		if !strings.Contains(out, "1 allowed") {
			t.Fatalf("posture line does not report the allowance.\n%s", out)
		}
	})
}

func TestFO02_DiscardedAuthorizationError(t *testing.T) {
	src := pkgHeader + `
type S struct{}

func (S) Admit() (bool, error) { return false, nil }

func use(s S) bool { ok, _ := s.Admit(); return ok }
`
	refuses(t, tree(t, "", "", map[string]string{"api/a.go": src}), "FO02")

	t.Run("handling the error is not a finding", func(t *testing.T) {
		ok := pkgHeader + `
type S struct{}

func (S) Admit() (bool, error) { return false, nil }

func use(s S) (bool, error) { return s.Admit() }
`
		passes(t, tree(t, "", "", map[string]string{"api/a.go": ok}))
	})

	t.Run("a call that is not an authorization predicate is not a finding", func(t *testing.T) {
		ok := pkgHeader + `
type S struct{}

func (S) Hostname() (string, error) { return "", nil }

func use(s S) string { h, _ := s.Hostname(); return h }
`
		passes(t, tree(t, "", "", map[string]string{"api/a.go": ok}))
	})
}

func TestFO03_EmptySecretSkipsTheCheck(t *testing.T) {
	for _, body := range []string{
		"if secret == \"\" {\n\t\treturn nil\n\t}\n\treturn check(secret)",
		"if token == \"\" {\n\t\treturn nil\n\t}\n\treturn check(token)",
	} {
		src := pkgHeader + "\nfunc check(string) error { return nil }\n\nfunc f(secret, token string) error {\n\t" + body + "\n}\n"
		refuses(t, tree(t, "", "", map[string]string{"api/a.go": src}), "FO03")
	}

	t.Run("refusing an empty secret is not a finding", func(t *testing.T) {
		src := pkgHeader + `
func f(secret string) error {
	if secret == "" {
		return os.ErrInvalid
	}
	return nil
}
`
		passes(t, tree(t, "", "", map[string]string{"api/a.go": src}))
	})

	t.Run("an ordinary empty-string check is not a finding", func(t *testing.T) {
		src := pkgHeader + `
func f(name string) error {
	if name == "" {
		return nil
	}
	return nil
}
`
		passes(t, tree(t, "", "", map[string]string{"api/a.go": src}))
	})
}

func TestFO04_SecuritySettingReadOutsideAResolver(t *testing.T) {
	src := pkgHeader + `
func boot() string { return os.Getenv("RASPUTIN_BUS_AUTH") }
`
	t.Run("read inline", func(t *testing.T) {
		refuses(t, tree(t, "", "", map[string]string{"api/a.go": src}), "FO04")
	})

	t.Run("read in a declared resolver", func(t *testing.T) {
		root := tree(t, "",
			"R1\tapi/a.go\tboot\tRASPUTIN_BUS_AUTH\tTestBoot\tcovered\t\n",
			map[string]string{
				"api/a.go":      src,
				"api/a_test.go": "package x\n\nimport \"testing\"\n\nfunc TestBoot(t *testing.T) {}\n",
			})
		passes(t, root)
	})

	t.Run("a wrapper reads count too", func(t *testing.T) {
		w := pkgHeader + `
func envOr(k, d string) string { return d }

func boot() string { return envOr("RASPUTIN_TRUST_DIR", "/etc") }
`
		refuses(t, tree(t, "", "", map[string]string{"api/a.go": w}), "RASPUTIN_TRUST_DIR")
	})

	t.Run("a variable with no security bearing is not a finding", func(t *testing.T) {
		ok := pkgHeader + `
func boot() string { return os.Getenv("RASPUTIN_DATA_DIR") }
`
		passes(t, tree(t, "", "", map[string]string{"api/a.go": ok}))
	})

	t.Run("an allowance covers one setting, not the whole function", func(t *testing.T) {
		two := pkgHeader + `
func boot() (string, string) {
	return os.Getenv("RASPUTIN_BUS_AUTH"), os.Getenv("RASPUTIN_TRUST_DIR")
}
`
		root := tree(t,
			"FO04\tapi/a.go\tboot:RASPUTIN_BUS_AUTH\tblocked\tgeekdojo/geekdojo-brain#1\textracted later\n",
			"", map[string]string{"api/a.go": two})
		// The allowed one is covered; the second is still a finding, which is
		// the whole reason the variable's name is part of the key.
		refuses(t, root, "RASPUTIN_TRUST_DIR")
	})
}

func TestFO05_SystemCertPool(t *testing.T) {
	src := pkgHeader + `
func pool() { _, _ = x509.SystemCertPool() }
`
	refuses(t, tree(t, "", "", map[string]string{"agent/a.go": src}), "FO05")
	refuses(t, tree(t, "", "", map[string]string{"backupxfer/a.go": src}), "FO05")

	t.Run("api code may use it", func(t *testing.T) {
		passes(t, tree(t, "", "", map[string]string{"api/a.go": src}))
	})
}

func TestFO06_ExtKeyUsageAny(t *testing.T) {
	src := pkgHeader + `
func usages() []x509.ExtKeyUsage { return []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }
`
	refuses(t, tree(t, "", "", map[string]string{"api/a.go": src}), "FO06")
}

func TestFO07_DevRelaxationWithoutAReleaseMarker(t *testing.T) {
	bad := pkgHeader + `
func arm() string { return os.Getenv("RASPUTIN_DEBUG_UPDATE_FAULT") }
`
	refuses(t, tree(t, "", "", map[string]string{"agent/a.go": bad}), "FO07")

	t.Run("consulting the release marker in the same function clears it", func(t *testing.T) {
		ok := pkgHeader + `
func ImageVersion() string { return "" }

func arm() string {
	if ImageVersion() != "" {
		return ""
	}
	return os.Getenv("RASPUTIN_DEBUG_UPDATE_FAULT")
}
`
		passes(t, tree(t, "", "", map[string]string{"agent/a.go": ok}))
	})
}

func TestTestFilesAreNotLinted(t *testing.T) {
	src := pkgHeader + `
func dial() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`
	passes(t, tree(t, "", "", map[string]string{"agent/a_test.go": src}))
}

func TestAllowanceRegisterHoldsItsOwnContract(t *testing.T) {
	src := pkgHeader + `
func dial() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`
	t.Run("an allowance with no reasoning is a suppression", func(t *testing.T) {
		refuses(t, tree(t, "FO01\tagent/a.go\tdial\tdeliberate\t\t\n", "",
			map[string]string{"agent/a.go": src}), "no reasoning")
	})

	t.Run("blocked with no issue can never be revisited", func(t *testing.T) {
		refuses(t, tree(t, "FO01\tagent/a.go\tdial\tblocked\t\tlater\n", "",
			map[string]string{"agent/a.go": src}), "no issue cited")
	})

	t.Run("an unknown verdict is refused", func(t *testing.T) {
		refuses(t, tree(t, "FO01\tagent/a.go\tdial\tfine\t\tit is fine\n", "",
			map[string]string{"agent/a.go": src}), "unknown verdict")
	})

	t.Run("an allowance that matches nothing is refused", func(t *testing.T) {
		refuses(t, tree(t,
			"FO01\tagent/gone.go\tdial\tdeliberate\t\tthe pin is checked elsewhere\n", "",
			map[string]string{"agent/a.go": pkgHeader}),
			"match nothing any more")
	})

	t.Run("every stale allowance is named, not just the first", func(t *testing.T) {
		// Two of them, because reporting one and stopping would leave the
		// second row looking granted — and a reader who deletes the row the
		// gate named would still not be green.
		root := tree(t,
			"FO01\tagent/gone-a.go\tdial\tdeliberate\t\tthe pin is checked elsewhere\n"+
				"FO06\tapi/gone-b.go\tusages\tblocked\tgeekdojo/geekdojo-brain#1\tretired with the verifier\n",
			"", map[string]string{"agent/a.go": pkgHeader})
		code, out := lint(t, root)
		if code == 0 {
			t.Fatalf("gate passed with two stale allowances.\n%s", out)
		}
		for _, want := range []string{"agent/gone-a.go", "api/gone-b.go", "2 allowance(s)"} {
			if !strings.Contains(out, want) {
				t.Errorf("output does not mention %q.\n%s", want, out)
			}
		}
	})
}

func TestResolverRegisterHoldsItsOwnContract(t *testing.T) {
	src := pkgHeader + `
func boot() string { return os.Getenv("RASPUTIN_BUS_AUTH") }
`
	t.Run("covered with a test nobody wrote", func(t *testing.T) {
		refuses(t, tree(t, "",
			"R1\tapi/a.go\tboot\tRASPUTIN_BUS_AUTH\tTestNobodyWroteThis\tcovered\t\n",
			map[string]string{"api/a.go": src}), "no test named")
	})

	t.Run("pending with no issue cited", func(t *testing.T) {
		refuses(t, tree(t, "",
			"R1\tapi/a.go\tboot\tRASPUTIN_BUS_AUTH\t\tpending\t\n",
			map[string]string{"api/a.go": src}), "no issue cited")
	})

	t.Run("a resolver that no longer exists", func(t *testing.T) {
		refuses(t, tree(t, "",
			"R1\tapi/a.go\tgoneAway\tRASPUTIN_BUS_AUTH\t\tpending\tgeekdojo/geekdojo-brain#1\n",
			map[string]string{"api/a.go": src}), "declares no goneAway")
	})

	t.Run("an unknown status", func(t *testing.T) {
		refuses(t, tree(t, "",
			"R1\tapi/a.go\tboot\tRASPUTIN_BUS_AUTH\t\tsoon\t\n",
			map[string]string{"api/a.go": src}), "unknown status")
	})

	t.Run("a duplicate id", func(t *testing.T) {
		rows := "R1\tapi/a.go\tboot\tRASPUTIN_BUS_AUTH\t\tpending\tgeekdojo/geekdojo-brain#1\n" +
			"R1\tapi/a.go\tboot\tRASPUTIN_BUS_AUTH\t\tpending\tgeekdojo/geekdojo-brain#1\n"
		refuses(t, tree(t, "", rows, map[string]string{"api/a.go": src}), "duplicate id")
	})

	t.Run("a pending row that names a test", func(t *testing.T) {
		refuses(t, tree(t, "",
			"R1\tapi/a.go\tboot\tRASPUTIN_BUS_AUTH\tTestBoot\tpending\tgeekdojo/geekdojo-brain#1\n",
			map[string]string{"api/a.go": src}), "mark it covered")
	})
}

func TestTheRepoItselfPasses(t *testing.T) {
	// The tree this lint ships in. Kept last so a failure here reads as "the
	// repo changed", not "the lint is broken" — every rule above has already
	// proved itself on a fixture by this point.
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	out := passes(t, root)
	if !strings.Contains(out, "failopenlint:") || !strings.Contains(out, "security resolvers:") {
		t.Fatalf("a passing run must still print both posture lines.\n%s", out)
	}
}
