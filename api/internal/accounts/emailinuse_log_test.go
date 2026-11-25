package accounts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// tokened is the production identity client under a fixed token, the Admin
// a Users is wired with (main wires the idclient.Session over it).
type tokened struct {
	c   *idclient.Client
	tok secret.Value
}

func (a tokened) Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error) {
	return a.c.Admin(ctx, a.tok, method, path, in, out)
}

// F-990-09 (LOG-SECRETS): when the identity service fails the in-use email
// check, the production client writes its failure record, and neither that
// record, nor the error EmailInUse returns, nor any request the service
// received carries the address typed at sign-up.
func TestEmailInUse_F990_09_FailureLogsNoEmail(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	c, err := idclient.New(idclient.Config{Addr: u, MgmtAddr: u, TLS: &tls.Config{RootCAs: pool}, CallTimeout: 10 * time.Second, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	users, err := NewUsers(UsersDeps{Admin: tokened{c: c, tok: secret.New([]byte("t"))}, Realm: realm, ConsoleClient: consoleClient})
	if err != nil {
		t.Fatal(err)
	}

	const typed = " Registrant+990@Example.org "
	_, err = users.EmailInUse(t.Context(), typed)
	if err == nil {
		t.Fatal("a 503 from the identity service was not an error")
	}
	if len(rec.Matching(slog.LevelWarn, "identity service call failed")) == 0 {
		t.Fatalf("the client wrote no failure record, so the check proves nothing: %s", rec.Text())
	}
	mu.Lock()
	requests := strings.Join(seen, "\n")
	mu.Unlock()
	if requests == "" {
		t.Fatal("the identity service received no request")
	}
	for _, needle := range []string{"registrant", "example.org", "Registrant", "Example.org"} {
		for what, text := range map[string]string{"the log": rec.Text(), "the error": err.Error(), "a request": requests} {
			if strings.Contains(text, needle) {
				t.Errorf("%s carries %q: %s", what, needle, text)
			}
		}
	}
}
