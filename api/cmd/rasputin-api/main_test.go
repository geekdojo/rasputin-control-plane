package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/logkit"
)

// Secure is derived from whether this process terminates TLS, because that is
// the condition under which the cookie can only travel over TLS. The bug this
// replaces was an opt-in env var that defaulted OFF and was set nowhere, so
// the appliance — which serves https on :443 — shipped session cookies without
// Secure. The unset-override row is the one that regressed.
//
// The override can force Secure on at any time, and can turn it off only when
// there is no HTTPS listener (geekdojo/geekdojo-brain#591, D1-B).
func TestSecureCookies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		httpsAddr string
		set       *string
		want      bool
	}{
		{"appliance: https listener, no override", ":443", nil, true},
		{"dev: no https listener, no override", "", nil, false},
		{"override forces on behind a TLS-terminating proxy", "", ptr("true"), true},
		{"override off is honoured with no https listener", "", ptr("false"), false},
		{"override off is refused with an https listener", ":443", ptr("false"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setSecureCookiesEnv(t, tc.set)
			if got, _, _ := secureCookies(tc.httpsAddr); got != tc.want {
				t.Errorf("secureCookies(%q) with %s = %v, want %v",
					tc.httpsAddr, describeEnv(tc.set), got, tc.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// setSecureCookiesEnv sets RASPUTIN_SECURE_COOKIES to *v, or makes it absent
// when v is nil. Either way it is restored after the test.
func setSecureCookiesEnv(t *testing.T, v *string) {
	t.Helper()
	const env = "RASPUTIN_SECURE_COOKIES"
	if v != nil {
		t.Setenv(env, *v)
		return
	}
	t.Setenv(env, "")
	if err := os.Unsetenv(env); err != nil {
		t.Fatalf("unset %s: %v", env, err)
	}
}

func describeEnv(v *string) string {
	if v == nil {
		return "RASPUTIN_SECURE_COOKIES absent"
	}
	return "RASPUTIN_SECURE_COOKIES=" + strconv.Quote(*v)
}

// Fail-closed table test for secureCookies (security-resolvers R01). Every row
// asserts all three return values, with and without an HTTPS listener.
func TestSecureCookies_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	type want struct {
		secure          bool
		ignored, reason string
	}
	type row struct {
		tc    string
		set   *string
		https want // secureCookies(":443")
		plain want // secureCookies("")
	}
	var rows []row

	// TC-591-18: absent or blank is derived.
	for _, v := range []*string{nil, ptr(""), ptr("   ")} {
		rows = append(rows, row{"TC-591-18", v, want{true, "", ""}, want{false, "", ""}})
	}
	// TC-591-19: a recognised off is honoured only with no HTTPS listener.
	// ignored keeps the operator's case and loses only the padding (F-591-09).
	for _, v := range []struct{ set, ignored string }{
		{"0", "0"}, {"false", "false"}, {"no", "no"}, {"off", "off"}, {"FALSE", "FALSE"}, {" off ", "off"},
	} {
		rows = append(rows, row{"TC-591-19", ptr(v.set),
			want{true, v.ignored, reasonOffRefused}, want{false, "", ""}})
	}
	// TC-591-20: a recognised on is honoured both ways.
	for _, v := range []string{"1", "true", "yes", "on", "TRUE", " on "} {
		rows = append(rows, row{"TC-591-20", ptr(v), want{true, "", ""}, want{true, "", ""}})
	}
	// TC-591-20: an unrecognised value forces Secure on and is reported both
	// ways, with its case kept (F-591-09).
	for _, v := range []struct{ set, ignored string }{
		{"ture", "ture"}, {"2", "2"}, {"enable", "enable"}, {"nope", "nope"}, {" ture ", "ture"}, {"Enable", "Enable"},
	} {
		rows = append(rows, row{"TC-591-20", ptr(v.set),
			want{true, v.ignored, reasonUnrecognised}, want{true, v.ignored, reasonUnrecognised}})
	}

	for _, r := range rows {
		for _, c := range []struct {
			addr string
			want want
		}{{":443", r.https}, {"", r.plain}} {
			t.Run(r.tc+" "+describeEnv(r.set)+" https="+strconv.Quote(c.addr), func(t *testing.T) {
				setSecureCookiesEnv(t, r.set)
				secure, ignored, reason := secureCookies(c.addr)
				got := want{secure, ignored, reason}
				if got != c.want {
					t.Errorf("secureCookies(%q) with %s = %+v, want %+v",
						c.addr, describeEnv(r.set), got, c.want)
				}
				// TC-591-21: the three values stay consistent in every row.
				if ignored != "" && !secure {
					t.Errorf("ignored %q while Secure is off: a value that was not honoured must leave Secure on", ignored)
				}
				if (reason == "") != (ignored == "") {
					t.Errorf("reason %q and ignored %q disagree on whether the value was honoured", reason, ignored)
				}
				if reason != "" && reason != reasonUnrecognised && reason != reasonOffRefused {
					t.Errorf("reason %q is not one of the two constants", reason)
				}
			})
		}
	}

	// TC-591-21: the fail-open regressions. On the base SHA each of these gave
	// false with an HTTPS listener: envBoolPtr turned empty and unrecognised
	// values into false, and a recognised off overrode the derivation.
	for _, v := range []string{"", "false", "ture"} {
		t.Run("TC-591-21 regression "+strconv.Quote(v), func(t *testing.T) {
			t.Setenv("RASPUTIN_SECURE_COOKIES", v)
			if secure, _, _ := secureCookies(":443"); !secure {
				t.Errorf("RASPUTIN_SECURE_COOKIES=%q with an HTTPS listener removed Secure", v)
			}
		})
	}

	// The refused-off reason names the variable that makes it refused.
	if !strings.Contains(reasonOffRefused, "RASPUTIN_HTTPS_ADDR") {
		t.Errorf("reasonOffRefused = %q, must name RASPUTIN_HTTPS_ADDR", reasonOffRefused)
	}
}

// F-591-06: a value secureCookies did not honour earns exactly one WARN with
// value, reason and fix; an honoured value earns none.
func TestWarnSecureCookiesNotHonoured(t *testing.T) {
	const msg = "RASPUTIN_SECURE_COOKIES is not honoured"
	t.Run("not honoured", func(t *testing.T) {
		h := &recordsHandler{}
		warnSecureCookiesNotHonoured(slog.New(h), "FALSE", reasonOffRefused)
		recs := h.matching(slog.LevelWarn, msg)
		if len(recs) != 1 {
			t.Fatalf("got %d WARN entries, want 1", len(recs))
		}
		attrs := map[string]string{}
		recs[0].Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		if attrs["value"] != "FALSE" {
			t.Errorf("value = %q, want FALSE", attrs["value"])
		}
		if attrs["reason"] != reasonOffRefused {
			t.Errorf("reason = %q, want reasonOffRefused", attrs["reason"])
		}
		if !strings.Contains(attrs["fix"], "RASPUTIN_HTTPS_ADDR") {
			t.Errorf("fix = %q, must tell the operator what to do", attrs["fix"])
		}
	})
	t.Run("honoured", func(t *testing.T) {
		h := &recordsHandler{}
		warnSecureCookiesNotHonoured(slog.New(h), "", "")
		if n := len(h.matching(slog.LevelWarn, msg)); n != 0 {
			t.Errorf("got %d WARN entries for an honoured value, want 0", n)
		}
	})
}

func TestAPILeafSpec_SANs(t *testing.T) {
	spec := apiLeafSpec("nodex", net.ParseIP("192.168.7.2"))

	wantDNS := []string{"rasputin.local", "localhost", "nodex", "nodex.local"}
	if !slices.Equal(spec.DNSNames, wantDNS) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, wantDNS)
	}
	if len(spec.IPAddresses) != 2 {
		t.Fatalf("IPAddresses = %v, want 127.0.0.1 + LAN IP", spec.IPAddresses)
	}
	if !spec.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("first IP SAN = %v, want 127.0.0.1", spec.IPAddresses[0])
	}
	if !spec.IPAddresses[1].Equal(net.ParseIP("192.168.7.2")) {
		t.Errorf("second IP SAN = %v, want 192.168.7.2", spec.IPAddresses[1])
	}
}

func TestAPILeafSpec_FQDNHostnameNoDoubleLocal(t *testing.T) {
	// Hostname already carries a dot → no "<host>.local" appended on top.
	spec := apiLeafSpec("nodex.local", nil)
	want := []string{"rasputin.local", "localhost", "nodex.local"}
	if !slices.Equal(spec.DNSNames, want) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, want)
	}
	if len(spec.IPAddresses) != 1 { // air-gapped: just loopback
		t.Errorf("IPAddresses = %v, want only 127.0.0.1", spec.IPAddresses)
	}
}

func TestAPILeafSpec_HostnameIsRasputinLocal_NoDup(t *testing.T) {
	spec := apiLeafSpec("rasputin.local", nil)
	want := []string{"rasputin.local", "localhost"}
	if !slices.Equal(spec.DNSNames, want) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, want)
	}
}

// End-to-end: mint the api leaf via ensureAPILeaf's underlying path and
// assert the SANs survive onto the actual certificate.
func TestEnsureAPILeaf_CertCarriesSANs(t *testing.T) {
	dir := t.TempDir()
	ca, err := tlsca.Ensure(tlsca.ControlplaneConfig(), dir, "test", tlscatest.Deps())
	if err != nil {
		t.Fatalf("tlsca.Ensure: %v", err)
	}

	spec := apiLeafSpec("nodex", net.ParseIP("10.0.0.5"))
	certPEM, _, err := ca.MintLeaf(spec)
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	for _, dns := range []string{"rasputin.local", "localhost", "nodex", "nodex.local"} {
		if !slices.Contains(cert.DNSNames, dns) {
			t.Errorf("leaf missing DNS SAN %q (have %v)", dns, cert.DNSNames)
		}
	}
	wantIPs := []string{"127.0.0.1", "10.0.0.5"}
	for _, want := range wantIPs {
		found := false
		for _, ip := range cert.IPAddresses {
			if ip.String() == want {
				found = true
			}
		}
		if !found {
			t.Errorf("leaf missing IP SAN %s (have %v)", want, cert.IPAddresses)
		}
	}
	// And the browser-facing check that actually matters:
	if err := cert.VerifyHostname("rasputin.local"); err != nil {
		t.Errorf("VerifyHostname(rasputin.local): %v", err)
	}
}

func TestLoadBusPreseed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := busauth.OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Missing file is normal — (0, nil), no error.
	if n, err := loadBusPreseed(ctx, store, filepath.Join(dir, "nope.json")); err != nil || n != 0 {
		t.Fatalf("missing preseed = (%d,%v); want (0,nil)", n, err)
	}

	// A valid preseed loads and the bound hashes validate.
	pt, h, _ := busauth.GenerateToken()
	path := filepath.Join(dir, "preseed.json")
	body := `[{"hash":"` + h + `","nodeId":"node-a","label":"compute"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write preseed: %v", err)
	}
	if n, err := loadBusPreseed(ctx, store, path); err != nil || n != 1 {
		t.Fatalf("loadBusPreseed = (%d,%v); want (1,nil)", n, err)
	}
	if ok, _ := store.Validate(ctx, pt, "node-a"); !ok {
		t.Error("preloaded token must validate for its bound node")
	}
	if ok, _ := store.Validate(ctx, pt, "node-b"); ok {
		t.Error("preloaded token must not validate for another node")
	}

	// Malformed JSON surfaces an error (caller logs and continues).
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	if _, err := loadBusPreseed(ctx, store, bad); err == nil {
		t.Error("malformed preseed should error")
	}

	// A preseed binding a token to an invalid node id is refused as a whole:
	// the error names it, and not even the valid entry beside it is stored.
	ptOK, hOK, _ := busauth.GenerateToken()
	_, hBad, _ := busauth.GenerateToken()
	invalid := filepath.Join(dir, "invalid-node.json")
	invalidBody := `[{"hash":"` + hOK + `","nodeId":"node-c","label":"compute"},` +
		`{"hash":"` + hBad + `","nodeId":"Node_D","label":"compute"}]`
	if err := os.WriteFile(invalid, []byte(invalidBody), 0o600); err != nil {
		t.Fatalf("write invalid: %v", err)
	}
	n, err := loadBusPreseed(ctx, store, invalid)
	if !errors.Is(err, busauth.ErrInvalidNodeID) || n != 0 {
		t.Fatalf("preseed with an invalid node id = (%d,%v); want (0, ErrInvalidNodeID)", n, err)
	}
	if !strings.Contains(err.Error(), "Node_D") {
		t.Errorf("preseed error %q should name the offending node id", err)
	}
	if ok, _ := store.Validate(ctx, ptOK, "node-c"); ok {
		t.Error("a rejected preseed must not store any of its entries")
	}
}

// A preseed entry naming no node id is refused as a whole (every token is
// bound, geekdojo-brain#423), and a live legacy unbound token already in the
// database is reported at startup until it is revoked.
func TestUnboundBusTokens_PreseedRefusedAndStartupLogged(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rasputin.db")
	store, err := busauth.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	_, h, _ := busauth.GenerateToken()
	path := filepath.Join(dir, "unbound.json")
	if err := os.WriteFile(path, []byte(`[{"hash":"`+h+`","label":"compute"}]`), 0o600); err != nil {
		t.Fatalf("write preseed: %v", err)
	}
	if n, err := loadBusPreseed(ctx, store, path); !errors.Is(err, busauth.ErrUnboundToken) || n != 0 {
		t.Fatalf("preseed with an unbound entry = (%d, %v); want (0, ErrUnboundToken)", n, err)
	}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// No unbound tokens: nothing is logged.
	if _, _, err := store.MintBound(ctx, "compute", "node-a", "compute"); err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	logUnboundBusTokens(ctx, store)
	if logs.Len() != 0 {
		t.Fatalf("logged %q with no unbound tokens; want nothing", logs.String())
	}

	// A legacy row, written as a pre-#423 store wrote it.
	_, legacyID, _ := busauth.GenerateToken()
	raw, err := dbutil.Open(ctx, dbPath, "SELECT 1", "test")
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, 'legacy', ?, NULL)`,
		legacyID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("insert legacy unbound token: %v", err)
	}
	logUnboundBusTokens(ctx, store)
	if got := logs.String(); !strings.Contains(got, "1 live UNBOUND bus join token(s)") {
		t.Fatalf("startup log %q should report 1 live unbound token", got)
	}

	// Revoked, it is no longer reported.
	logs.Reset()
	if _, err := store.Revoke(ctx, legacyID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	logUnboundBusTokens(ctx, store)
	if logs.Len() != 0 {
		t.Fatalf("logged %q after the unbound token was revoked; want nothing", logs.String())
	}
}

// A live bound token whose row names no role is refused at the bus (busauth
// role.go), so it is reported at startup until it is revoked; a token with a
// role, a revoked role-less one and an unbound one (reported by the unbound
// line instead) are not.
func TestRolelessBusTokens_StartupLogged(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	store, err := busauth.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if _, _, err := store.MintBound(ctx, "compute", "node-a", "compute"); err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	raw, err := dbutil.Open(ctx, dbPath, "SELECT 1", "test")
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_, unboundID, _ := busauth.GenerateToken()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, 'legacy', ?, NULL)`,
		unboundID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("insert unbound: %v", err)
	}
	logRolelessBusTokens(ctx, store)
	if logs.Len() != 0 {
		t.Fatalf("logged %q with no role-less bound tokens; want nothing", logs.String())
	}

	_, legacyID, _ := busauth.GenerateToken()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, 'laptop agent', ?, 'dev1')`,
		legacyID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("insert role-less: %v", err)
	}
	logRolelessBusTokens(ctx, store)
	if got := logs.String(); !strings.Contains(got, "WARNING 1 live bus join token(s) name no node role") {
		t.Fatalf("startup log %q should report 1 live role-less token", got)
	}

	logs.Reset()
	if _, err := store.Revoke(ctx, legacyID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	logRolelessBusTokens(ctx, store)
	if logs.Len() != 0 {
		t.Fatalf("logged %q after the role-less token was revoked; want nothing", logs.String())
	}

	// A store that cannot answer is reported, not mistaken for "none".
	_ = store.Close()
	logRolelessBusTokens(ctx, store)
	if got := logs.String(); !strings.Contains(got, "counting role-less bus tokens") || strings.Contains(got, "WARNING") {
		t.Fatalf("with a closed store, logged %q; want the counting error only", got)
	}
}

// At start the tombstones come before the preseed: a revoked matched-set token
// in the preseed stays out, and an unreadable tombstone file stops the preseed
// from loading at all.
func TestLoadBusTokenState(t *testing.T) {
	ctx := context.Background()
	t.Setenv("RASPUTIN_BUS_PRESEED", "") // the default, <dataDir>/bus/preseed.json
	open := func(t *testing.T, dataDir string) *busauth.Store {
		t.Helper()
		st, err := busauth.OpenStore(ctx, filepath.Join(dataDir, "rasputin.db"))
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		return st
	}
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "bus"), 0o700); err != nil {
		t.Fatal(err)
	}
	ptKeep, hKeep, _ := busauth.GenerateToken()
	ptGone, hGone, _ := busauth.GenerateToken()
	preseed := `[{"hash":"` + hKeep + `","nodeId":"keep","label":"compute"},{"hash":"` + hGone + `","nodeId":"gone","label":"compute"}]`
	if err := os.WriteFile(filepath.Join(dataDir, "bus", "preseed.json"), []byte(preseed), 0o600); err != nil {
		t.Fatal(err)
	}

	st := open(t, dataDir)
	if n := loadBusTokenState(ctx, st, dataDir); n != 2 {
		t.Fatalf("first start loaded %d, want 2", n)
	}
	if _, err := st.Revoke(ctx, hGone); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	// The database is lost; the bus directory is not.
	if err := os.Remove(filepath.Join(dataDir, "rasputin.db")); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{"-wal", "-shm"} {
		_ = os.Remove(filepath.Join(dataDir, "rasputin.db"+sidecar))
	}
	st = open(t, dataDir)
	if n := loadBusTokenState(ctx, st, dataDir); n != 1 {
		t.Fatalf("start after the loss loaded %d, want 1", n)
	}
	if ok, _ := st.Validate(ctx, ptGone, "gone"); ok {
		t.Error("the revoked matched-set token came back")
	}
	if ok, _ := st.Validate(ctx, ptKeep, "keep"); !ok {
		t.Error("the unrevoked matched-set token did not load")
	}

	// An unreadable tombstone file: nothing is preloaded.
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "bus"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "bus", "preseed.json"), []byte(preseed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "bus", busauth.TombstoneFileName), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	st2 := open(t, other)
	if n := loadBusTokenState(ctx, st2, other); n != 0 {
		t.Fatalf("with an unreadable tombstone file, loaded %d, want 0", n)
	}
	if ok, _ := st2.Validate(ctx, ptKeep, "keep"); ok {
		t.Error("the preseed loaded despite an unreadable tombstone file")
	}
}

func TestSeedBMCHostNode(t *testing.T) {
	ctx := context.Background()
	st, err := setup.OpenStore(ctx, filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Empty host id: nothing seeded (and IsSet stays false).
	seedBMCHostNode(ctx, st, "")
	if set, _ := st.IsSet(ctx, setup.KeyBMCHostNode); set {
		t.Error("empty id must not seed")
	}

	// First boot: env value seeds.
	seedBMCHostNode(ctx, st, "cp-env")
	if v, _ := st.Get(ctx, setup.KeyBMCHostNode); v != "cp-env" {
		t.Errorf("seeded: %q", v)
	}

	// Operator choice wins permanently: a later boot never re-seeds.
	if err := st.Set(ctx, setup.KeyBMCHostNode, "cp-chosen"); err != nil {
		t.Fatal(err)
	}
	seedBMCHostNode(ctx, st, "cp-env")
	if v, _ := st.Get(ctx, setup.KeyBMCHostNode); v != "cp-chosen" {
		t.Errorf("re-seeded over operator choice: %q", v)
	}
}

// --- cluster-name derivation (ADR-0003) --------------------------------------

// RASPUTIN_CLUSTER_ID is written by firstboot and by nothing else, so its
// PRESENCE is what distinguishes a provisioned appliance from a dev box. Get
// this wrong and every developer's origin silently renames, breaking the local
// passkey flow.
func TestClusterHostname(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "")
	if got := clusterHostname(); got != "" {
		t.Errorf("unset cluster id should yield %q (dev box), got %q", "", got)
	}
	t.Setenv("RASPUTIN_CLUSTER_ID", "home1")
	if got := clusterHostname(); got != "home1.local" {
		t.Errorf("clusterHostname() = %q, want home1.local", got)
	}
	// Whitespace from a hand-edited node.env must not produce " home1 .local".
	t.Setenv("RASPUTIN_CLUSTER_ID", "  home1  ")
	if got := clusterHostname(); got != "home1.local" {
		t.Errorf("clusterHostname() = %q, want the id trimmed", got)
	}
}

// The whole no-migration promise of ADR-0003 rests on this: a node whose
// cluster id is the default derives EXACTLY the values the OS image hardcodes
// today. If this drifts, every existing installation renames on upgrade.
func TestDefaultClusterIDDerivesTodaysApplianceValues(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "rasputin")
	host := func(h string) string { return h }
	https := func(h string) string { return "https://" + h }
	hs := func(h string) string { return "https://" + h + ":18080" }

	for _, tc := range []struct{ name, got, want string }{
		{"RP ID", applianceOr(host, "localhost"), "rasputin.local"},
		{"RP origin", applianceOr(https, "dev"), "https://rasputin.local"},
		{"public base URL", applianceOr(https, "dev"), "https://rasputin.local"},
		{"headscale server_url", applianceOr(hs, ""), "https://rasputin.local:18080"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q — an existing installation would RENAME on upgrade", tc.name, tc.got, tc.want)
		}
	}
}

// A dev box keeps its localhost defaults untouched.
func TestNoClusterIDKeepsDevDefaults(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "")
	if got := applianceOr(func(h string) string { return h }, "localhost"); got != "localhost" {
		t.Errorf("RP ID default = %q, want localhost on a dev box", got)
	}
	if got := applianceOr(func(h string) string { return "https://" + h }, ""); got != "" {
		t.Errorf("headscale ServerURL default = %q, want empty so the supervisor falls back to resolveServerHost", got)
	}
}

// A non-default cluster id derives its own name everywhere.
func TestNonDefaultClusterIDDerivesItsOwnName(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "home1")
	if got := applianceOr(func(h string) string { return h }, "localhost"); got != "home1.local" {
		t.Errorf("RP ID = %q, want home1.local", got)
	}
	if got := applianceOr(func(h string) string { return "https://" + h + ":18080" }, ""); got != "https://home1.local:18080" {
		t.Errorf("headscale server_url = %q, want https://home1.local:18080", got)
	}
}

// ⚠️ The api half of "mock is never inferred".
//
// RASPUTIN_MESH_BACKEND=auto used to fall through to the mock when it found no
// external Headscale and no docker CLI. That is the same shape as the
// 2026-09-01 storage incident: the mock mesh mints keys and the enroll saga
// invents a 100.64.0.x address per node, which /api/mesh/devices then serves as
// a real tailnet address. `auto` must detect a REAL backend or report none.
func TestWireMesh_AutoNeverInfersMock(t *testing.T) {
	// No external Headscale creds, and a docker binary name that cannot
	// resolve — the exact condition that used to select the mock.
	t.Setenv("RASPUTIN_HEADSCALE_URL", "")
	t.Setenv("RASPUTIN_HEADSCALE_API_KEY", "")
	t.Setenv("RASPUTIN_HEADSCALE_SUPERVISOR", "")
	t.Setenv("RASPUTIN_HEADSCALE_DOCKER_BIN", "rasputin-no-such-docker-binary")

	for _, backend := range []string{"auto", ""} {
		t.Setenv("RASPUTIN_MESH_BACKEND", backend)
		mw, err := wireMesh(t.TempDir(), nil, "dev@example.com")
		if err != nil {
			t.Fatalf("RASPUTIN_MESH_BACKEND=%q: wireMesh must not fail — the api has to boot and "+
				"serve /healthz even with no mesh: %v", backend, err)
		}
		if got := mw.client.Backend(); got == "mock" {
			t.Errorf("RASPUTIN_MESH_BACKEND=%q selected the mock with no real backend present. "+
				"A mock mesh reports nodes as enrolled with invented tailnet addresses; the "+
				"honest result is an unavailable backend.", backend)
		}
		if got := mw.client.Backend(); got != "unavailable" {
			t.Errorf("RASPUTIN_MESH_BACKEND=%q: backend = %q, want unavailable", backend, got)
		}
		// And the refusal has to say what is missing, or an operator cannot
		// act on it.
		if _, _, err := mw.client.CreatePreAuthKey(context.Background(),
			mesh.CreatePreAuthKeyInput{User: "u"}); err == nil {
			t.Error("an unavailable mesh must refuse key creation, not succeed quietly")
		} else if !errors.Is(err, mesh.ErrMeshUnavailable) {
			t.Errorf("error %v must wrap ErrMeshUnavailable so callers can tell "+
				"'not configured' from 'Headscale said no'", err)
		}
	}
}

// The other half: an operator who asks for the mock still gets it. Dev and CI
// depend on this, and breaking it would push people back to the inference.
func TestWireMesh_ExplicitMockIsHonoured(t *testing.T) {
	t.Setenv("RASPUTIN_MESH_BACKEND", "mock")
	mw, err := wireMesh(t.TempDir(), nil, "dev@example.com")
	if err != nil {
		t.Fatalf("wireMesh: %v", err)
	}
	if got := mw.client.Backend(); got != "mock" {
		t.Errorf("backend = %q, want mock — an explicit request must always win", got)
	}
}

// ⚠️ The api half of "an absent trust root is a refusal, not a downgrade".
//
// A missing <trustDir>/root-ca.pem used to select a permissive updater.Verifier
// all by itself: bundle signatures were parsed but never chain-verified, and
// every bundle was recorded SignedBy "<unverified>". That is a fail-open on the
// artifact that decides what code a node boots, signalled only by a string
// nobody watches. Making it opt-in by name kept it one environment variable
// away; "dev-permissive" is now a value with no mode behind it, and this test
// asserts that naming it changes nothing.
func TestWireBundleVerifier_MissingTrustRootIsNeverPermissive(t *testing.T) {
	for _, mode := range []string{"", "require", "REQUIRE", "dev-permissive", "permissive", "yes", "1"} {
		t.Setenv(updateTrustEnv, mode)
		v := wireBundleVerifier(t.TempDir()) // no root-ca.pem anywhere in it
		if v.Available() {
			t.Errorf("%s=%q produced a usable verifier with no trust root — no value of this "+
				"variable may select a mode that skips the check", updateTrustEnv, mode)
		}
		if got := v.Mode(); got != updater.TrustUnavailable {
			t.Errorf("%s=%q: mode = %q, want %q", updateTrustEnv, mode, got, updater.TrustUnavailable)
		}
		// The api still has to BOOT — #89. wireBundleVerifier returning at all,
		// with no fatal and no error, is that contract.
		if _, err := v.VerifyArtifact("artifact", "artifact.sig"); !errors.Is(err, updater.ErrTrustUnavailable) {
			t.Errorf("%s=%q: want ErrTrustUnavailable, got %v", updateTrustEnv, mode, err)
		}
	}
}

// And a provisioned box verifies for real, which is the case that matters on
// hardware: the OS image ships root-ca.pem, so this is the normal posture.
func TestWireBundleVerifier_LoadsTheTrustRootWhenPresent(t *testing.T) {
	dir := t.TempDir()
	ca, err := tlsca.Ensure(tlsca.ControlplaneConfig(), dir, "test", tlscatest.Deps()) // any real CA PEM will do here
	if err != nil {
		t.Fatalf("tlsca.Ensure: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	if err := os.WriteFile(filepath.Join(dir, "root-ca.pem"), pemBytes, 0o600); err != nil {
		t.Fatalf("write root-ca.pem: %v", err)
	}
	t.Setenv(updateTrustEnv, "")
	v := wireBundleVerifier(dir)
	if got := v.Mode(); got != updater.TrustEnforced {
		t.Errorf("mode = %q, want %q", got, updater.TrustEnforced)
	}
}

// A run the scheduler starts records reason "scheduled" (geekdojo-brain#438).
// The entry once carried no Spec: the scheduler substituted {} and
// ParseRunSpec read that as manual, so every scheduled run was labelled a
// press of Back up now. This parses the spec the ENTRY submits, not a spec
// written for the test.
func TestBackupRunEntry_SpecRecordsScheduled(t *testing.T) {
	e := backupRunEntry(time.Hour, nil)
	if e.Kind != storage.RunJobKind {
		t.Fatalf("Kind = %q, want %q", e.Kind, storage.RunJobKind)
	}
	if len(e.Spec) == 0 {
		t.Fatal("Spec is empty; the scheduler would submit {} and the run would record manual")
	}
	spec, err := storage.ParseRunSpec(e.Spec)
	if err != nil {
		t.Fatalf("ParseRunSpec(%s): %v", e.Spec, err)
	}
	if spec.Reason != storage.ReasonScheduled {
		t.Fatalf("Reason = %q, want %q", spec.Reason, storage.ReasonScheduled)
	}
	if e.Interval != time.Hour {
		t.Fatalf("Interval = %s, want the check interval passed in", e.Interval)
	}
}

// TC-539-16: ensureSelfAgentToken is the api's zero-touch mint for its own
// agent (geekdojo-brain#140): a dev api with no self node id writes nothing, a
// controlplane writes a live token bound to its id and keeps it across
// restarts, and an id the bus would never accept is reported and writes
// nothing — the api still starts. Each outcome is one structured record at a
// level through the injected logger, and no record carries the token.
func TestEnsureSelfAgentToken(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := busauth.OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	path := filepath.Join(dir, "bus", "agent.token")
	var all bytes.Buffer // every record of the test, checked for the token at the end

	// step runs one call and returns its single record.
	step := func(selfNodeID, p, wantLevel, wantMsg string, wantFields ...string) string {
		t.Helper()
		var buf bytes.Buffer
		ensureSelfAgentToken(ctx, logkit.New(&buf), store, p, selfNodeID)
		all.Write(buf.Bytes())
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("ensureSelfAgentToken(%q): want one record, got %d:\n%s", selfNodeID, len(lines), buf.String())
		}
		rec := lines[0]
		if !strings.Contains(rec, "level="+wantLevel+" ") {
			t.Errorf("ensureSelfAgentToken(%q) record %q: want level=%s", selfNodeID, rec, wantLevel)
		}
		if !strings.Contains(rec, wantMsg) {
			t.Errorf("ensureSelfAgentToken(%q) record %q: want message %q", selfNodeID, rec, wantMsg)
		}
		for _, f := range wantFields {
			if !strings.Contains(rec, f) {
				t.Errorf("ensureSelfAgentToken(%q) record %q: want %q", selfNodeID, rec, f)
			}
		}
		return rec
	}

	rec := step("", path, "INFO", "not minting a bus token", "RASPUTIN_CP_JOIN_TOKEN_FILE")
	if strings.Contains(strings.ReplaceAll(rec, "RASPUTIN_CP_JOIN_TOKEN_FILE", ""), "RASPUTIN_CP_JOIN_TOKEN") {
		t.Errorf("the dev record %q names the retired RASPUTIN_CP_JOIN_TOKEN", rec)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dev api (no self node id) wrote the token file: %v", err)
	}

	step("cp-1", path, "INFO", "minted a bus token for this controlplane's agent", "node_id=cp-1", "path="+path, "reason=")
	tok, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no token file after the mint: %v", err)
	}
	if ok, err := store.Validate(ctx, strings.TrimSpace(string(tok)), "cp-1"); err != nil || !ok {
		t.Fatalf("the minted token does not validate for cp-1: (%v, %v)", ok, err)
	}

	step("cp-1", path, "INFO", "is live", "node_id=cp-1", "path="+path)
	if again, _ := os.ReadFile(path); string(again) != string(tok) {
		t.Fatal("a restart replaced a live token")
	}

	other := filepath.Join(dir, "other", "agent.token")
	step("CP_1", other, "ERROR", "cannot join the bus", "node_id=CP_1", "path="+other, "err=")
	if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an invalid self node id wrote a token file: %v", err)
	}

	if strings.Contains(all.String(), strings.TrimSpace(string(tok))) {
		t.Errorf("a record carries the minted token:\n%s", all.String())
	}
}

// A node always gets its own cluster's controlplane CA, whoever runs Headscale
// (geekdojo/geekdojo-brain#506). The operator's CA is APPENDED when they name
// one; before this it replaced the controlplane CA, so a node on an external Headscale
// trusted the operator's root and not the CA that signs its own controlplane's
// HTTPS leaf and app leaves.
func TestWireExternalMesh_ShipsTheMeshCAPlusTheOperatorCA(t *testing.T) {
	meshCA, err := tlsca.Ensure(tlsca.ControlplaneConfig(), filepath.Join(t.TempDir(), "trust"), "wire-test", tlscatest.Deps())
	if err != nil {
		t.Fatalf("tlsca.Ensure: %v", err)
	}
	operatorCA, err := tlsca.Ensure(tlsca.ControlplaneConfig(), filepath.Join(t.TempDir(), "operator"), "operator", tlscatest.Deps())
	if err != nil {
		t.Fatalf("tlsca.Ensure(operator): %v", err)
	}
	t.Setenv("RASPUTIN_HEADSCALE_SUPERVISOR", "noop")

	t.Run("no CA file: the controlplane CA alone, unchanged", func(t *testing.T) {
		t.Setenv("RASPUTIN_HEADSCALE_CA_FILE", "")
		mw, err := wireExternalMesh(t.TempDir(), meshCA, "dev@example.com", "https://hs.example", "hskey-test")
		if err != nil {
			t.Fatalf("wireExternalMesh: %v", err)
		}
		if got := nodeTrustBundle(meshCA, mw); !bytes.Equal(got, meshCA.CertPEM) {
			t.Errorf("node bundle = %q, want the controlplane CA PEM byte for byte", got)
		}
	})

	t.Run("CA file: the operator's CA appended to the controlplane CA", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "operator-ca.pem")
		if err := os.WriteFile(caFile, operatorCA.CertPEM, 0o644); err != nil {
			t.Fatalf("write CA file: %v", err)
		}
		t.Setenv("RASPUTIN_HEADSCALE_CA_FILE", caFile)
		mw, err := wireExternalMesh(t.TempDir(), meshCA, "dev@example.com", "https://hs.example", "hskey-test")
		if err != nil {
			t.Fatalf("wireExternalMesh: %v", err)
		}
		bundle := nodeTrustBundle(meshCA, mw)
		if !bytes.Contains(bundle, bytes.TrimSpace(meshCA.CertPEM)) {
			t.Error("the node bundle dropped the controlplane CA when the operator named their own")
		}
		if !bytes.Contains(bundle, bytes.TrimSpace(operatorCA.CertPEM)) {
			t.Error("the node bundle does not carry the operator's CA")
		}
	})

	t.Run("unreadable CA file: the api refuses to start", func(t *testing.T) {
		t.Setenv("RASPUTIN_HEADSCALE_CA_FILE", filepath.Join(t.TempDir(), "absent.pem"))
		if _, err := wireExternalMesh(t.TempDir(), meshCA, "dev@example.com", "https://hs.example", "hskey-test"); err == nil {
			t.Fatal("a CA file that cannot be read was ignored; nodes would be shipped a CA the api itself does not trust")
		}
	})

	t.Run("unusable CA file: the api refuses to start", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "junk.pem")
		if err := os.WriteFile(caFile, []byte("not a certificate"), 0o644); err != nil {
			t.Fatalf("write CA file: %v", err)
		}
		t.Setenv("RASPUTIN_HEADSCALE_CA_FILE", caFile)
		if _, err := wireExternalMesh(t.TempDir(), meshCA, "dev@example.com", "https://hs.example", "hskey-test"); err == nil {
			t.Fatal("a CA file with no certificates in it was accepted; the client would fall back to the system pool")
		}
	})
}

// The self-hosted path goes through the same helper, so a controlplane CA that holds
// no certificate stops the api there too, instead of leaving the Headscale
// client on the system pool.
func TestWireSelfHostedMesh_UnusableMeshCAIsRefused(t *testing.T) {
	t.Setenv("RASPUTIN_HEADSCALE_URL", "https://127.0.0.1:18080")
	_, err := wireSelfHostedMesh(t.TempDir(), &tlsca.CA{CertPEM: []byte("not a certificate")}, "dev@example.com")
	if err == nil {
		t.Fatal("a controlplane CA with no certificate in it was accepted")
	}
	if !strings.Contains(err.Error(), "controlplane CA") {
		t.Errorf("error %q does not name the controlplane CA as the input to fix", err)
	}
}

// TC-733-10: the process logger built at this composition root redacts
// secrets. Every logkit.New call in main.go must pass logkit.RedactSecrets();
// a logger built without it would write a self-rendering secret holder's
// bytes (geekdojo/geekdojo-brain#733). Comment lines are not calls.
func TestProcessLoggerRedactsSecrets(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	calls := 0
	for _, line := range strings.Split(string(src), "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "//") || !strings.Contains(code, "logkit.New(") {
			continue
		}
		calls++
		if !strings.Contains(code, "logkit.RedactSecrets()") {
			t.Errorf("main.go builds a logger without logkit.RedactSecrets() (#733):\n\t%s", code)
		}
	}
	if calls == 0 {
		t.Fatal("main.go has no logkit.New( call; the process logger must be built there with logkit.RedactSecrets() (#733)")
	}
}
