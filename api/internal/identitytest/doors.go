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

// DoorSites are the door tests' TLS sites. The sign-in sites, the home door,
// the app door and the console, share one loopback address behind the
// handler a test gives (the api's :443 dispatcher, geekdojo/geekdojo-brain#986),
// with a test-CA leaf for each name chosen by SNI; the console's leaf also
// names 127.0.0.1 and localhost, and answers any other name and none. The
// test app's site has its own address. The browser maps each name's port 443
// to its server, and Client does the same, so every origin keeps port 443 as
// on a cluster.
type DoorSites struct {
	Table          doors.Table
	Sites, AppSite *httptest.Server
	addrs          map[string]string // host -> 127.0.0.1:<port>
	roots          *tlsca.CA
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

// ServeDoors starts the sign-in sites over sites and the test app's site
// over appSite, and records the browser flags they need. It must be called
// before Browser; the sites close with the Env.
func (e *Env) ServeDoors(sites, appSite http.Handler) (*DoorSites, error) {
	if e.br != nil {
		return nil, errors.New("identitytest: ServeDoors after the browser started cannot reach it")
	}
	table, err := doors.New(DoorClusterID)
	if err != nil {
		return nil, err
	}
	d := &DoorSites{Table: table, addrs: map[string]string{}, roots: e.ca}
	leaf := func(host string, spec tlsca.LeafSpec) (tls.Certificate, error) {
		p, err := e.ca.MintLeafToDisk(filepath.Join(e.root, "site-"+host), spec)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("identitytest: the %s leaf: %w", host, err)
		}
		spki, err := spkiHash(p.CertPath)
		if err != nil {
			return tls.Certificate{}, err
		}
		e.browserSPKI = append(e.browserSPKI, spki)
		return tls.LoadX509KeyPair(p.CertPath, p.KeyPath)
	}
	oneName := func(host string) (tls.Certificate, error) {
		return leaf(host, tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: host, DNSNames: []string{host}})
	}
	byName := map[string]tls.Certificate{}
	for _, host := range []string{table.Home.Host, table.App.Host} {
		if byName[host], err = oneName(host); err != nil {
			return nil, err
		}
	}
	console, err := leaf(ConsoleHost, tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: ConsoleHost,
		DNSNames: []string{ConsoleHost, "localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	if err != nil {
		return nil, err
	}
	appCert, err := oneName(AppSiteHost)
	if err != nil {
		return nil, err
	}
	start := func(h http.Handler, cfg *tls.Config) *httptest.Server {
		srv := httptest.NewUnstartedServer(h)
		srv.TLS = cfg
		srv.Config.ErrorLog = slog.NewLogLogger(e.log.Handler(), slog.LevelDebug)
		srv.StartTLS()
		e.doorSites = append(e.doorSites, srv)
		return srv
	}
	d.Sites = start(sites, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{console},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, ok := byName[strings.TrimSuffix(strings.ToLower(h.ServerName), ".")]; ok {
				return &c, nil
			}
			return &console, nil
		}})
	d.AppSite = start(appSite, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{appCert}})
	var rules []string
	for host, srv := range map[string]*httptest.Server{
		table.Home.Host: d.Sites, table.App.Host: d.Sites, ConsoleHost: d.Sites, AppSiteHost: d.AppSite,
	} {
		addr := srv.Listener.Addr().String()
		d.addrs[host] = addr
		rules = append(rules, "MAP "+host+":443 "+addr)
	}
	// The console's other names, for the Go clients only: the browser keeps
	// its own loopback.
	d.addrs["127.0.0.1"] = d.Sites.Listener.Addr().String()
	d.addrs["localhost"] = d.Sites.Listener.Addr().String()
	e.browserRules = strings.Join(rules, ",")
	return d, nil
}

// Client is an HTTP client that reaches the sites by name on port 443,
// trusting only the Env's CA, from the loopback source address local (so a
// test can sign in from 127.0.0.1 and 127.0.0.2), with jar. It follows no
// redirect, and sends each URL's host as its TLS server name.
func (d *DoorSites) Client(local netip.Addr, jar http.CookieJar) *http.Client {
	return d.client(local, jar, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootsOf(d.roots)})
}

// ClientSNI is Client with the TLS server name set to sni whatever the URL's
// host, so a test can send one name in SNI and another in Host; "" with an
// IP-literal URL sends none.
func (d *DoorSites) ClientSNI(local netip.Addr, sni string) *http.Client {
	return d.client(local, nil, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootsOf(d.roots), ServerName: sni})
}

func (d *DoorSites) client(local netip.Addr, jar http.CookieJar, cfg *tls.Config) *http.Client {
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
		TLSClientConfig: cfg,
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
