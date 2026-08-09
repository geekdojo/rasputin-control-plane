package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDNSForwardingHandlers(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)

	decode := func(w *httptest.ResponseRecorder) dnsForwardingResponse {
		var resp dnsForwardingResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v (body %s)", err, w.Body.String())
		}
		return resp
	}

	// Default (unset): everything off/empty.
	w := f.do(t, http.MethodGet, "/api/settings/dns-forwarding", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("GET default: %d %s", w.Code, w.Body.String())
	}
	if got := decode(w); got.Enabled || got.Upstream != "" || got.EffectiveUpstream != "" {
		t.Errorf("default should be all-empty, got %+v", got)
	}

	// Set a valid explicit upstream; it round-trips.
	w = f.do(t, http.MethodPost, "/api/settings/dns-forwarding", `{"enabled":true,"upstream":"9.9.9.9"}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("POST valid: %d %s", w.Code, w.Body.String())
	}
	if got := decode(w); !got.Enabled || got.Upstream != "9.9.9.9" {
		t.Errorf("POST should reflect the set, got %+v", got)
	}
	if got := decode(f.do(t, http.MethodGet, "/api/settings/dns-forwarding", "", c)); !got.Enabled || got.Upstream != "9.9.9.9" {
		t.Errorf("GET after set should persist, got %+v", got)
	}

	// An IPv6 upstream is rejected (decision #9).
	w = f.do(t, http.MethodPost, "/api/settings/dns-forwarding", `{"enabled":true,"upstream":"2001:db8::1"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("IPv6 upstream should 400, got %d %s", w.Code, w.Body.String())
	}

	// With the reconcile + host-info hooks wired, the response surfaces the
	// effective upstream + fellBack and the CP's IP/MAC (reservation guidance).
	f.srv.SetHostLANInfo(func() (string, string) { return "192.168.207.56", "d8:3a:dd:12:34:56" })
	f.srv.SetDNSForwardingApplier(func(context.Context) (string, bool, error) {
		return "1.1.1.1:53", true, nil
	})
	w = f.do(t, http.MethodPost, "/api/settings/dns-forwarding", `{"enabled":true,"upstream":""}`, c)
	got := decode(w)
	if got.EffectiveUpstream != "1.1.1.1:53" || !got.FellBack {
		t.Errorf("applier should surface effective + fellBack, got %+v", got)
	}
	if got.ControlPlaneIP != "192.168.207.56" || got.ControlPlaneMAC != "d8:3a:dd:12:34:56" {
		t.Errorf("host LAN info should surface, got ip=%q mac=%q", got.ControlPlaneIP, got.ControlPlaneMAC)
	}
}
