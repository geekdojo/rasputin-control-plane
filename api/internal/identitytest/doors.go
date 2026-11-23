package identitytest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The door tests' cluster (geekdojo/geekdojo-brain#985): cluster id ci, so
// the home door is sso-ci.local and the app door signin.ci.internal; the
// console stands at ci.local and a test app at app.ci.internal, a sibling of
// the app door's site.
const (
	DoorClusterID = "ci"
	ConsoleHost   = "ci.local"
	AppSiteHost   = "app.ci.internal"
)

// DoorSites are the door tests' four TLS sites, each on its own loopback
// port with a test-CA leaf for its one name. The browser maps each name's
// port 443 to its server, and Client does the same, so every origin keeps
// port 443 as on a cluster.
type DoorSites struct {
	Table                       doors.Table
	Home, App, Console, AppSite *httptest.Server
	addrs                       map[string]string // host -> 127.0.0.1:<port>
	roots                       *tlsca.CA
}

// DoorTransport is the relay's connection pool, built as Identity 4.4 builds
// it: idclient.NewTransport over a client leaf with the door's subject
// (CN rasputin-door) under the Env's CA.
func (e *Env) DoorTransport() (*http.Transport, error) {
	leaf, err := e.ca.MintLeafToDisk(filepath.Join(e.root, "door-client"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-door"})
	if err != nil {
		return nil, fmt.Errorf("identitytest: the door leaf: %w", err)
	}
	cfg, err := looptls.NewClientTLS(e.ca.CertPEM, leaf.CertPath, leaf.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("identitytest: the door leaf: %w", err)
	}
	return idclient.NewTransport(cfg), nil
}

// KeycloakUpstream is Keycloak's https listener, the doors' upstream.
func (e *Env) KeycloakUpstream() *url.URL {
	https, _ := e.ports.get()
	return &url.URL{Scheme: "https", Host: "127.0.0.1:" + strconv.Itoa(https)}
}

// ServeDoors starts the four sites over the handlers and records the browser
// flags they need. It must be called before Browser; the sites close with
// the Env.
func (e *Env) ServeDoors(home, app, console, appSite http.Handler) (*DoorSites, error) {
	if e.br != nil {
		return nil, errors.New("identitytest: ServeDoors after the browser started cannot reach it")
	}
	table, err := doors.New(DoorClusterID)
	if err != nil {
		return nil, err
	}
	d := &DoorSites{Table: table, addrs: map[string]string{}, roots: e.ca}
	var rules []string
	start := func(host string, h http.Handler) (*httptest.Server, error) {
		leaf, err := e.ca.MintLeafToDisk(filepath.Join(e.root, "site-"+host), tlsca.LeafSpec{
			Usage: tlsca.UsageServer, CommonName: host, DNSNames: []string{host},
		})
		if err != nil {
			return nil, fmt.Errorf("identitytest: the %s leaf: %w", host, err)
		}
		pair, err := tls.LoadX509KeyPair(leaf.CertPath, leaf.KeyPath)
		if err != nil {
			return nil, err
		}
		spki, err := spkiHash(leaf.CertPath)
		if err != nil {
			return nil, err
		}
		srv := httptest.NewUnstartedServer(h)
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
		srv.Config.ErrorLog = slog.NewLogLogger(e.log.Handler(), slog.LevelDebug)
		srv.StartTLS()
		e.doorSites = append(e.doorSites, srv)
		addr := srv.Listener.Addr().String()
		d.addrs[host] = addr
		rules = append(rules, "MAP "+host+":443 "+addr)
		e.browserSPKI = append(e.browserSPKI, spki)
		return srv, nil
	}
	for _, s := range []struct {
		host string
		h    http.Handler
		into **httptest.Server
	}{
		{table.Home.Host, home, &d.Home}, {table.App.Host, app, &d.App},
		{ConsoleHost, console, &d.Console}, {AppSiteHost, appSite, &d.AppSite},
	} {
		srv, err := start(s.host, s.h)
		if err != nil {
			return nil, err
		}
		*s.into = srv
	}
	e.browserRules = strings.Join(rules, ",")
	return d, nil
}

// Client is an HTTP client that reaches the four sites by name on port 443,
// trusting only the Env's CA, from the loopback source address local (so a
// test can sign in from 127.0.0.1 and 127.0.0.2), with jar. It follows no
// redirect.
func (d *DoorSites) Client(local netip.Addr, jar http.CookieJar) *http.Client {
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: local.AsSlice()}, Timeout: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			to, ok := d.addrs[host]
			if !ok || port != "443" {
				return nil, fmt.Errorf("identitytest: no door site at %s", addr)
			}
			return dialer.DialContext(ctx, network, to)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootsOf(d.roots)},
	}
	return &http.Client{Transport: tr, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// rootsOf is a pool holding only ca.
func rootsOf(ca *tlsca.CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}
