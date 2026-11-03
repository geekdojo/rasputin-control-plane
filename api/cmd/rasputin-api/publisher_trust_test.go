package main

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// sigFixture is a file in artifactsig's testdata: the release pipeline's own
// signatures, reached across modules as the updater and catalogsync tests do.
func sigFixture(name string) string {
	return filepath.Join("..", "..", "..", "artifactsig", "testdata", name)
}

// copyFixture copies an artifactsig fixture to path.
func copyFixture(t *testing.T, name, path string) {
	t.Helper()
	raw, err := os.ReadFile(sigFixture(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// envMap is a getenv that knows only the variables in m.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TC-529-06: a non-release build resolves the catalog source exactly as the
// envOr lines it replaced did, and ignores nothing. The malformed repo is
// passed through unchanged; the fetcher refuses it one layer down
// (TestGitHubRepo_OnlyAPlainRepoOnPublicGitHub). The register rows this
// resolver and the changed trust-root resolver owe are checked too.
func TestCatalogSourceFromEnv_NonReleaseKeepsTodaysBehaviour(t *testing.T) {
	const releaseBase = "https://api.example.test"
	for _, tc := range []struct {
		name       string
		absent     bool
		repo, base string
	}{
		{name: "both unset", absent: true},
		{name: "empty"},
		{name: "whitespace", repo: "   ", base: "  "},
		{name: "app-upgrade-test values", repo: "local/t730", base: "http://127.0.0.1:18730"},
		{name: "malformed repo", repo: "../x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setOrUnset(t, catalogRepoEnv, tc.absent, tc.repo)
			setOrUnset(t, catalogAPIBaseEnv, tc.absent, tc.base)
			// What main.go computed before #529.
			wantRepo := envOr("RASPUTIN_CATALOG_REPO", "")
			wantBase := envOr("RASPUTIN_CATALOG_API_BASE", releaseBase)

			repo, base, ignored := catalogSourceFromEnv(false, os.Getenv, releaseBase)
			if repo != wantRepo || base != wantBase {
				t.Errorf("got (%q, %q), want today's (%q, %q)", repo, base, wantRepo, wantBase)
			}
			if len(ignored) != 0 {
				t.Errorf("a non-release build ignored %v", ignored)
			}
		})
	}

	reg, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "security-resolvers.tsv"))
	if err != nil {
		t.Fatalf("read the resolver register: %v", err)
	}
	rows := map[string]string{}
	for _, line := range strings.Split(string(reg), "\n") {
		if f := strings.Split(line, "\t"); len(f) > 2 && !strings.HasPrefix(line, "#") {
			rows[f[2]] = line
		}
	}
	r12 := rows["TrustRootPath"]
	for _, want := range []string{"RASPUTIN_TRUST_ROOT, non-release builds only", "TestTrustRootPath", "TestReleaseBuild_TrustRootPathIgnoresTheEnvironment"} {
		if !strings.Contains(r12, want) {
			t.Errorf("the TrustRootPath register row lacks %q: %q", want, r12)
		}
	}
	if row := rows["catalogSourceFromEnv"]; !strings.Contains(row, "TestCatalogSourceFromEnv_NonReleaseKeepsTodaysBehaviour") {
		t.Errorf("no register row names catalogSourceFromEnv and this test: %q", row)
	}
	if r35 := rows["trustDirFromEnv"]; r35 == "" || strings.Contains(r35, "bundle-signing root") {
		t.Errorf("the trustDirFromEnv row must exist and no longer claim the bundle-signing root: %q", r35)
	}
}

// TC-529-07: a release build is fixed to Geekdojo's catalog at the release API
// base, whatever the environment says, and names each variable it ignored.
func TestCatalogSourceFromEnv_ReleaseIsFixedToGeekdojo(t *testing.T) {
	const releaseBase = "https://api.example.test"
	for _, tc := range []struct {
		name        string
		env         map[string]string
		wantIgnored []string
	}{
		{"both unset", nil, nil},
		{"repo only", map[string]string{catalogRepoEnv: "evil/catalog"}, []string{catalogRepoEnv}},
		{"api base only", map[string]string{catalogAPIBaseEnv: "https://evil.example"}, []string{catalogAPIBaseEnv}},
		{"both", map[string]string{catalogRepoEnv: "evil/catalog", catalogAPIBaseEnv: "https://evil.example"},
			[]string{catalogRepoEnv, catalogAPIBaseEnv}},
		{"malformed repo", map[string]string{catalogRepoEnv: "../x"}, []string{catalogRepoEnv}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, base, ignored := catalogSourceFromEnv(true, envMap(tc.env), releaseBase)
			if repo != "geekdojo/rasputin-app-catalog" {
				t.Errorf("repo = %q, want Geekdojo's catalog", repo)
			}
			if base != releaseBase {
				t.Errorf("apiBase = %q, want the release API base %q", base, releaseBase)
			}
			if !slices.Equal(ignored, tc.wantIgnored) {
				t.Errorf("ignored = %v, want %v", ignored, tc.wantIgnored)
			}
		})
	}
}

// TC-529-12: a release build writes one WARN per ignored setting that is set,
// naming it and never carrying its value; nothing set, or a non-release build,
// writes none.
func TestWarnIgnoredReleaseSettings(t *testing.T) {
	values := map[string]string{
		artifactsig.TrustRootEnv: "/tmp/x.pem",
		catalogRepoEnv:           "evil/catalog",
		catalogAPIBaseEnv:        "https://evil.example",
	}
	const msg = "setting ignored on a release build"

	h := &recordsHandler{}
	warnIgnoredReleaseSettings(slog.New(h), true, envMap(values))
	got := h.matching(slog.LevelWarn, msg)
	if len(got) != 3 {
		t.Fatalf("got %d WARN records, want one per set variable (3)", len(got))
	}
	var named []string
	for _, r := range got {
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
		named = append(named, attrs["var"])
		if attrs["reason"] == "" {
			t.Errorf("record for %s has no reason", attrs["var"])
		}
	}
	if want := []string{artifactsig.TrustRootEnv, catalogRepoEnv, catalogAPIBaseEnv}; !slices.Equal(named, want) {
		t.Errorf("var attributes = %v, want %v", named, want)
	}
	for _, r := range h.recs {
		text := r.Message
		r.Attrs(func(a slog.Attr) bool { text += " " + a.Value.String(); return true })
		for _, v := range values {
			if strings.Contains(text, v) {
				t.Errorf("a record carries the value %q: %q", v, text)
			}
		}
	}

	for _, tc := range []struct {
		name    string
		release bool
		env     map[string]string
	}{
		{"release, none set", true, nil},
		{"non-release, all set", false, values},
	} {
		h := &recordsHandler{}
		warnIgnoredReleaseSettings(slog.New(h), tc.release, envMap(tc.env))
		if n := len(h.recs); n != 0 {
			t.Errorf("%s: wrote %d records, want none", tc.name, n)
		}
	}
}

// TC-529-14: the legacy-root WARN. A regular file at <trustDir>/root-ca.pem
// whose bytes differ from the publisher root earns exactly one WARN naming its
// path; an identical file, the tmpfiles symlink and an absent path earn
// nothing. No record ever carries the file's PEM text.
func TestWarnLegacyTrustRoot(t *testing.T) {
	publisher := filepath.Join(t.TempDir(), "publisher-root-ca.pem")
	copyFixture(t, "root-ca.pem", publisher)

	for _, tc := range []struct {
		name     string
		make     func(t *testing.T, legacy string)
		wantWarn bool
	}{
		{"a different root", func(t *testing.T, p string) { copyFixture(t, "other-root-ca.pem", p) }, true},
		{"an empty file", func(t *testing.T, p string) {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"byte-identical to the publisher root", func(t *testing.T, p string) { copyFixture(t, "root-ca.pem", p) }, false},
		{"a symlink to the publisher root", func(t *testing.T, p string) {
			if err := os.Symlink(publisher, p); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"absent", func(*testing.T, string) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trustDir := t.TempDir()
			legacy := filepath.Join(trustDir, "root-ca.pem")
			tc.make(t, legacy)

			h := &recordsHandler{}
			warnLegacyTrustRoot(slog.New(h), trustDir, publisher)

			want := 0
			if tc.wantWarn {
				want = 1
			}
			if len(h.recs) != want {
				t.Fatalf("got %d records, want %d", len(h.recs), want)
			}
			for _, r := range h.recs {
				if r.Level != slog.LevelWarn || !strings.Contains(r.Message, "ignored") {
					t.Errorf("record = %s %q, want a WARN saying the file is ignored", r.Level, r.Message)
				}
				var path string
				text := r.Message
				r.Attrs(func(a slog.Attr) bool {
					if a.Key == "path" {
						path = a.Value.String()
					}
					text += " " + a.Value.String()
					return true
				})
				if path != legacy {
					t.Errorf("path = %q, want %q", path, legacy)
				}
				if strings.Contains(text, "BEGIN CERTIFICATE") {
					t.Errorf("a record carries PEM text: %q", text)
				}
			}
		})
	}
}

// TC-529-13: the root's posture goes through the injected logger, and the
// wiring always returns. A missing or unparseable root is one ERROR with the
// root and the reason; a retired RASPUTIN_UPDATE_TRUST is one WARN; the
// standard log package writes nothing.
func TestWirePublisherTrust_LogsRootPostureAndBoots(t *testing.T) {
	var std bytes.Buffer
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	garbage := filepath.Join(t.TempDir(), "root-ca.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		root string
	}{
		{"missing root", filepath.Join(t.TempDir(), "root-ca.pem")},
		{"unparseable root", garbage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(updateTrustEnv, "")
			h := &recordsHandler{}
			upd, _ := wirePublisherTrust(slog.New(h), tc.root)
			if upd.Available() {
				t.Fatal("the verifier is available on a bad root")
			}
			errs := h.matching(slog.LevelError, "OS update verification unavailable")
			if len(errs) != 1 || len(h.recs) != 1 {
				t.Fatalf("got %d matching ERROR records of %d, want exactly one", len(errs), len(h.recs))
			}
			attrs := map[string]string{}
			errs[0].Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
			if attrs["root"] != tc.root || attrs["err"] == "" {
				t.Errorf("attrs = %v, want root=%q and a non-empty err", attrs, tc.root)
			}
		})
	}

	t.Run("RASPUTIN_UPDATE_TRUST=permissive", func(t *testing.T) {
		t.Setenv(updateTrustEnv, "permissive")
		root := filepath.Join(t.TempDir(), "root-ca.pem")
		copyFixture(t, "root-ca.pem", root)
		h := &recordsHandler{}
		upd, _ := wirePublisherTrust(slog.New(h), root)
		if !upd.Available() {
			t.Fatal("a valid root did not load")
		}
		if n := len(h.matching(slog.LevelWarn, "")); n != 1 || len(h.recs) != 1 {
			t.Errorf("got %d WARN records of %d, want exactly one", n, len(h.recs))
		}
	})

	if std.Len() != 0 {
		t.Errorf("the standard log package wrote %q; root posture goes through the injected logger", std.String())
	}
}
