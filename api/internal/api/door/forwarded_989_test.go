package door

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// TC-989-26 (ARCH-DRY): the relay and the identity client's forwarding
// (the console's key fetch) both write the door's forwarded headers through
// doors.Door.SetForwarded, and the identity service receives identical
// X-Forwarded-Host, -Proto and -Port, and the same Host, from each.
func TestForwarded_RelayAndClientAgree(t *testing.T) {
	f := newFixture(t)
	if w := f.do(Home, req{target: realmPrefix + ".well-known/openid-configuration", remote: "192.0.2.1:4000"}); w.Code != http.StatusOK {
		t.Fatalf("relay: %d", w.Code)
	}
	relayed := f.up.last(t)

	pool := x509.NewCertPool()
	pool.AddCert(f.up.srv.Certificate())
	u, _ := url.Parse(f.up.srv.URL)
	c, err := idclient.New(idclient.Config{Addr: u, MgmtAddr: u, TLS: &tls.Config{RootCAs: pool}, CallTimeout: 10 * time.Second,
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	door := f.door(Home).cfg.Door
	resp, err := c.Forwarding(door.SetForwarded).Get(door.Issuer + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	fetched := f.up.last(t)
	for _, k := range []string{"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port"} {
		if a, b := relayed.header.Values(k), fetched.header.Values(k); len(a) != 1 || len(b) != 1 || a[0] != b[0] {
			t.Errorf("%s: relay %q, client %q", k, a, b)
		}
	}
	if relayed.host != fetched.host || fetched.host != door.Host {
		t.Errorf("Host: relay %q, client %q, door %q", relayed.host, fetched.host, door.Host)
	}
	if fetched.path != "/realms/rasputin/protocol/openid-connect/certs" {
		t.Errorf("the client fetched %s", fetched.path)
	}
}
