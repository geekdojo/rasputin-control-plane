package doors

import (
	"errors"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-983-01 (doors half): every name the table hands out for a door is
// byte-equal to the proto constructor's output.
func TestNew_NamesComeFromTheConstructor(t *testing.T) {
	tbl, err := New("bench")
	if err != nil {
		t.Fatal(err)
	}
	app, home := proto.SignInFQDN("bench"), proto.SignInHomeFQDN("bench")
	if app != "signin.bench.internal" || home != "sso-bench.local" {
		t.Fatalf("constructors = %q, %q", app, home)
	}
	for _, c := range []struct {
		d    Door
		host string
	}{{tbl.App, app}, {tbl.Home, home}} {
		spec := c.d.LeafSpec()
		for what, got := range map[string]string{
			"Host":        c.d.Host,
			"RPID":        c.d.RPID,
			"CommonName":  spec.CommonName,
			"issuer host": strings.TrimSuffix(strings.TrimPrefix(c.d.Issuer, "https://"), "/realms/rasputin"),
		} {
			if got != c.host {
				t.Errorf("%s %s = %q, want %q", c.d.Name, what, got, c.host)
			}
		}
		if len(spec.DNSNames) != 1 || spec.DNSNames[0] != c.host || len(spec.IPAddresses) != 0 || !spec.ExactDNSNames {
			t.Errorf("%s spec = %+v", c.d.Name, spec)
		}
		if c.d.Port != 443 {
			t.Errorf("%s port = %d", c.d.Name, c.d.Port)
		}
	}
	if tbl.App.Issuer != "https://signin.bench.internal/realms/rasputin" || tbl.Home.Issuer != "https://sso-bench.local/realms/rasputin" {
		t.Errorf("issuers = %q, %q", tbl.App.Issuer, tbl.Home.Issuer)
	}
	// The reserved label is the app door's first label.
	if first, _, _ := strings.Cut(tbl.App.Host, "."); !proto.IsReservedLabel(first) {
		t.Errorf("%q is not reserved", first)
	}
	if h := tbl.Hosts(); len(h) != 2 || h[0] != home || h[1] != app {
		t.Errorf("Hosts = %v", h)
	}
	wantClients := map[string][]string{
		"signin-home": {"rasputin-console", "rasputin-reset-home", "rasputin-mesh"},
		"signin-app":  {"rasputin-account", "rasputin-reset-app"},
	}
	for _, d := range []Door{tbl.Home, tbl.App} {
		if strings.Join(d.Clients, ",") != strings.Join(wantClients[d.Name], ",") {
			t.Errorf("%s clients = %v", d.Name, d.Clients)
		}
	}
}

// TC-983-15 (doors half): New fails closed on every shape of a bad id.
func TestNew_RefusesEveryBadClusterID(t *testing.T) {
	if _, err := New(""); !errors.Is(err, ErrNoClusterID) {
		t.Errorf("empty: %v, want ErrNoClusterID", err)
	}
	for _, cid := range []string{"Bench", "ben_ch", "-bench", " bench", strings.Repeat("a", 60)} {
		tbl, err := New(cid)
		var refused *RefusedError
		if !errors.As(err, &refused) || refused.ClusterID != cid {
			t.Errorf("New(%q) = %+v, %v; want a RefusedError naming it", cid, tbl, err)
		}
		if tbl.App.Host != "" || tbl.Home.Host != "" {
			t.Errorf("New(%q) returned doors with its refusal", cid)
		}
	}
	if _, err := New(strings.Repeat("a", 59)); err != nil {
		t.Errorf("59-character id refused: %v", err)
	}
}

func TestWithheldBy(t *testing.T) {
	for _, c := range []struct {
		names []string
		want  string
	}{
		{nil, ""},
		{[]string{"jellyfin", "signin2", "my-signin"}, ""},
		{[]string{"signin", "jellyfin"}, "signin"},
		{[]string{"radius"}, "radius"},
		{[]string{"signin", "radius"}, "radius"},
	} {
		if got := WithheldBy(c.names); got != c.want {
			t.Errorf("WithheldBy(%v) = %q, want %q", c.names, got, c.want)
		}
	}
}

// TC-995-16 (doors half): the door table applies the one cluster-id rule, so
// an sso- id turns both doors off, and each refusal carries the rule it broke.
func TestNew_AppliesTheClusterIDRule(t *testing.T) {
	for cid, want := range map[string]error{
		"sso-bench":             proto.ErrClusterIDReservedPrefix,
		strings.Repeat("a", 60): proto.ErrClusterIDTooLong,
		"Bench":                 ErrNotLabel,
	} {
		tbl, err := New(cid)
		var refused *RefusedError
		if !errors.As(err, &refused) || refused.ClusterID != cid || !errors.Is(err, want) {
			t.Errorf("New(%q) = %v; want a RefusedError naming it, carrying %v", cid, err, want)
		}
		if tbl.App.Host != "" || tbl.Home.Host != "" {
			t.Errorf("New(%q) returned doors with its refusal", cid)
		}
	}
	for _, cid := range []string{"ssobench", "sso"} {
		if _, err := New(cid); err != nil {
			t.Errorf("New(%q) refused: %v", cid, err)
		}
	}
}
