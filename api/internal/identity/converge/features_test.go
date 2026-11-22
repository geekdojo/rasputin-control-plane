package converge

import (
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// shippedConf is the repo's keycloak-build.conf.
func shippedConf(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../../../identity/keycloak-build.conf")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// matchingFeatures are the features a server built with conf reports: each
// disabled key's feature off, and the required set on.
func matchingFeatures(t *testing.T, conf []byte) []map[string]any {
	t.Helper()
	keys, err := parseBuildConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	enum := map[string]string{
		"account": "ACCOUNT_V3", "admin": "ADMIN_V2", "token-exchange-standard": "TOKEN_EXCHANGE_STANDARD_V2",
		"identity-brokering-api": "IDENTITY_BROKERING_API_V1",
	}
	var out []map[string]any
	for _, k := range keys {
		name, ok := enum[k]
		if !ok {
			name = strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
		}
		out = append(out, map[string]any{"name": name, "enabled": false})
	}
	out = append(out, map[string]any{"name": "ADMIN_FINE_GRAINED_AUTHZ_V2", "enabled": false})
	for _, n := range RequiredFeatures {
		out = append(out, map[string]any{"name": n, "enabled": true})
	}
	return append(out, map[string]any{"name": "WEB_AUTHN", "enabled": true})
}

type featureRig struct {
	kc   *fakeKC
	conf []byte
	cerr error
	f    *FeatureCheck
	rec  *logkittest.Recorder
}

func newFeatureRig(t *testing.T) *featureRig {
	t.Helper()
	r := &featureRig{kc: newFakeKC(), conf: shippedConf(t)}
	r.kc.features = matchingFeatures(t, r.conf)
	log, rec := logkittest.New()
	r.rec = rec
	f, err := NewFeatureCheck(r.kc, func() ([]byte, error) { return r.conf, r.cerr }, log)
	if err != nil {
		t.Fatal(err)
	}
	r.f = f
	return r
}

func (r *featureRig) serverInfoReads() int { return r.kc.seen["GET /admin/serverinfo"] }

func setFeature(fs []map[string]any, name string, enabled bool) []map[string]any {
	for _, f := range fs {
		if f["name"] == name {
			f["enabled"] = enabled
			return fs
		}
	}
	return append(fs, map[string]any{"name": name, "enabled": enabled})
}

func dropFeature(fs []map[string]any, name string) []map[string]any {
	var out []map[string]any
	for _, f := range fs {
		if f["name"] != name {
			out = append(out, f)
		}
	}
	return out
}

// TC-981-07: a match reads no mismatch; each way the running features differ
// reads as one.
func TestFeatureCheck_MatchAndMismatches(t *testing.T) {
	r := newFeatureRig(t)
	if m, err := r.f.Mismatch(t.Context(), "inv-1"); err != nil || m {
		t.Fatalf("shipped conf against a matching server = %v, %v; want no mismatch", m, err)
	}
	for _, c := range []struct {
		name string
		set  func(r *featureRig)
	}{
		{"a disabled key reported enabled", func(r *featureRig) { r.kc.features = setFeature(r.kc.features, "ACCOUNT_V3", true) }},
		{"either admin-fine-grained-authz version enabled", func(r *featureRig) {
			r.kc.features = setFeature(r.kc.features, "ADMIN_FINE_GRAINED_AUTHZ_V2", true)
		}},
		{"a conf key that matches no feature", func(r *featureRig) { r.kc.features = dropFeature(r.kc.features, "PAR") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newFeatureRig(t)
			c.set(r)
			if m, err := r.f.Mismatch(t.Context(), "inv-1"); err != nil || !m {
				t.Errorf("Mismatch = %v, %v; want a mismatch", m, err)
			}
		})
	}
	for _, name := range RequiredFeatures {
		for _, absent := range []bool{true, false} {
			r := newFeatureRig(t)
			if absent {
				r.kc.features = dropFeature(r.kc.features, name)
			} else {
				r.kc.features = setFeature(r.kc.features, name, false)
			}
			if m, err := r.f.Mismatch(t.Context(), "inv-1"); err != nil || !m {
				t.Errorf("required %s absent=%t: Mismatch = %v, %v; want a mismatch", name, absent, m, err)
			}
		}
	}
}

// TC-981-07: the enum names map to the conf's keys.
func TestFeatureKey(t *testing.T) {
	for enum, key := range map[string]string{
		"ACCOUNT_V3": "account", "ADMIN_V2": "admin", "TOKEN_EXCHANGE_STANDARD_V2": "token-exchange-standard",
		"ADMIN_FINE_GRAINED_AUTHZ": "admin-fine-grained-authz", "ADMIN_FINE_GRAINED_AUTHZ_V2": "admin-fine-grained-authz",
		"ACCOUNT_API": "account-api", "PAR": "par", "DEVICE_FLOW": "device-flow",
	} {
		if got := featureKey(enum); got != key {
			t.Errorf("featureKey(%s) = %q, want %q", enum, got, key)
		}
	}
}

// TC-981-07: parseBuildConf fails closed on an empty or malformed conf, and
// a conf that is absent or unreadable fails the check; none of those
// verdicts is cached, so the next call reads again.
func TestParseBuildConf_FailsClosed(t *testing.T) {
	for name, conf := range map[string]string{
		"empty":                     "",
		"blank lines only":          "\n  \n",
		"a line without =":          "db=postgres\nfeatures-disabled account\n",
		"no features-disabled line": "db=postgres\nvault=file\n",
		"two features-disabled":     "features-disabled=account\nfeatures-disabled=par\n",
		"an empty entry":            "features-disabled=account,,par\n",
		"an entry not a key":        "features-disabled=account,Par!\n",
		"an empty key":              "=x\nfeatures-disabled=account\n",
	} {
		if keys, err := parseBuildConf([]byte(conf)); err == nil {
			t.Errorf("%s: parseBuildConf = %v, want an error", name, keys)
		}
	}
	keys, err := parseBuildConf([]byte("# build options\ndb=postgres\n\nfeatures-disabled=account, par\n"))
	if err != nil || len(keys) != 2 || keys[0] != "account" || keys[1] != "par" {
		t.Errorf("a good conf = %v, %v", keys, err)
	}

	for name, set := range map[string]func(r *featureRig){
		"absent":     func(r *featureRig) { r.cerr = fs.ErrNotExist },
		"unreadable": func(r *featureRig) { r.cerr = fs.ErrPermission },
		"malformed":  func(r *featureRig) { r.conf = []byte("features-disabled account\n") },
		"empty":      func(r *featureRig) { r.conf = nil },
		"serverinfo unreadable": func(r *featureRig) {
			r.kc.fail["GET /admin/serverinfo"] = &idclient.Error{Op: "admin", Path: "/admin/serverinfo", Kind: idclient.ErrDenied, OAuthError: "invalid_client"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newFeatureRig(t)
			set(r)
			for range 2 {
				if _, err := r.f.Mismatch(t.Context(), "inv-1"); err == nil {
					t.Fatal("Mismatch = nil error, want the check to fail closed")
				}
			}
			// Not cached: once fixed, the same invocation reads again.
			r.conf, r.cerr = shippedConf(t), nil
			delete(r.kc.fail, "GET /admin/serverinfo")
			if m, err := r.f.Mismatch(t.Context(), "inv-1"); err != nil || m {
				t.Errorf("after the fix: Mismatch = %v, %v", m, err)
			}
		})
	}
}

// TC-981-07: one invocation reads serverinfo once, a new one reads it
// again, and a mismatch logs one ERROR per invocation naming the features.
func TestFeatureCheck_CachedPerInvocation(t *testing.T) {
	r := newFeatureRig(t)
	r.kc.features = setFeature(r.kc.features, "ACCOUNT_V3", true)
	for range 3 {
		if m, err := r.f.Mismatch(t.Context(), "inv-1"); err != nil || !m {
			t.Fatalf("Mismatch = %v, %v", m, err)
		}
	}
	if n := r.serverInfoReads(); n != 1 {
		t.Errorf("%d serverinfo reads in one invocation, want 1", n)
	}
	errs := r.rec.AtLevel(slog.LevelError)
	if len(errs) != 1 {
		t.Fatalf("records:\n%s\nwant one ERROR", r.rec.Text())
	}
	if f, _ := logkittest.Attr(errs[0], "features"); !strings.Contains(f, "account") {
		t.Errorf("features = %q, want it to name account", f)
	}
	r.kc.features = setFeature(r.kc.features, "ACCOUNT_V3", false)
	if m, err := r.f.Mismatch(t.Context(), "inv-2"); err != nil || m {
		t.Errorf("new invocation: Mismatch = %v, %v; want a fresh match", m, err)
	}
	if n := r.serverInfoReads(); n != 2 {
		t.Errorf("%d serverinfo reads after a new invocation, want 2", n)
	}
	if len(r.rec.AtLevel(slog.LevelError)) != 1 {
		t.Error("a match logged an ERROR")
	}
	if _, err := NewFeatureCheck(nil, func() ([]byte, error) { return nil, nil }, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a nil Admin was accepted")
	}
}
