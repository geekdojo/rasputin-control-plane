package api

import (
	"bytes"
	_ "embed"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// The :443 site dispatcher (geekdojo/geekdojo-brain#986, Identity 4.4;
// signin-origin.md §3.2, §5.1). One TLS listener serves three sites, chosen by
// the TLS server name: the home sign-in door at sso-<cid>.local, the app
// sign-in door at signin.<cid>.internal, and the console at every other name.
// The certificate for each is chosen by the same names (sniCertificate in
// main). A request whose server name and Host header name different sites is
// refused with 421 (D25's second guard against a connection a browser shares
// between sites), so no door path is ever answered on the console's host and
// no console route on a door's.

// sentenceMisdirected is the 421's message.
const sentenceMisdirected = "This page was requested over a connection opened for a different address, so it was refused. Reload the page to try again."

// The door not-ready page's sentence, used when a door site is reached but
// its door is not served (signin-origin.md §5.1).
const sentenceSigninUnavailable = "Sign-in isn't available right now. Try again in a moment. If it stays like this, tell whoever runs this cluster."

// notReadyPolicy is the not-ready page's content policy: it runs no script.
const notReadyPolicy = "script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

// siteRoute is the refusal record's route for a request the dispatcher
// refused itself: no mux pattern matched it, and the path the client sent is
// never logged.
const siteRoute = "site dispatch"

//go:embed sites_notready.html.tmpl
var notReadyTemplate string

var notReadyTmpl = template.Must(template.New("not-ready").Parse(notReadyTemplate))

// SitesConfig is the dispatcher's collaborators. NewSites refuses a nil
// Console, Now, IDs or Log, a lifetime that is not positive, or one door host
// set without the other. Home and App may be nil: the door is not served, and
// its site answers the not-ready page.
type SitesConfig struct {
	// Console is the console's handler (Server.Handler).
	Console http.Handler
	// Home and App are the doors' handlers (*door.Handler).
	Home, App http.Handler
	// HomeHost and AppHost are the doors' names from the door table; both
	// empty is doors off, where every name is the console.
	HomeHost, AppHost string
	// RequestLifetime bounds one door request: its body is read and its
	// answer written before now plus this, or the connection is closed. It
	// bounds I/O only and decides no state.
	RequestLifetime time.Duration
	Now             func() time.Time
	// IDs mints the correlation id of a refusal.
	IDs func() string
	Log *slog.Logger
}

// site is one of the three sites on :443.
type site int

const (
	siteConsole site = iota
	siteHome
	siteApp
)

func (s site) String() string {
	switch s {
	case siteHome:
		return "home"
	case siteApp:
		return "app"
	}
	return "console"
}

type sites struct {
	cfg       SitesConfig
	home, app string
}

// NewSites checks cfg and returns the :443 handler.
func NewSites(cfg SitesConfig) (http.Handler, error) {
	missing := ""
	switch {
	case cfg.Console == nil:
		missing = "Console"
	case cfg.Now == nil:
		missing = "Now"
	case cfg.IDs == nil:
		missing = "IDs"
	case cfg.Log == nil:
		missing = "Log"
	case cfg.RequestLifetime <= 0:
		missing = "RequestLifetime"
	case (cfg.HomeHost == "") != (cfg.AppHost == ""):
		missing = "HomeHost or AppHost"
	}
	if missing != "" {
		return nil, errors.New("api: SitesConfig." + missing + " is missing or invalid")
	}
	return &sites{cfg: cfg, home: siteName(cfg.HomeHost), app: siteName(cfg.AppHost)}, nil
}

// siteName is a name as the sites compare it: lowercased, any trailing dot
// trimmed.
func siteName(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

// hostName is a Host header's name: its port and IPv6 brackets dropped.
func hostName(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return siteName(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
}

// siteOf is the site a name belongs to. With the doors off every name is the
// console's, and so is an empty one.
func (s *sites) siteOf(name string) site {
	switch {
	case s.home != "" && name == s.home:
		return siteHome
	case s.app != "" && name == s.app:
		return siteApp
	}
	return siteConsole
}

// ServeHTTP dispatches one request to its site.
func (s *sites) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sni := ""
	if r.TLS != nil {
		sni = siteName(r.TLS.ServerName)
	}
	bySNI, byHost := s.siteOf(sni), s.siteOf(hostName(r.Host))
	if bySNI != byHost {
		securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := s.cfg.IDs()
			// Only the sites' kinds are logged, never the names the client sent.
			logRefusal(r.Context(), s.cfg.Log, id, siteRoute, codeMisdirectedRequest,
				slog.String("sni_site", bySNI.String()), slog.String("host_site", byHost.String()))
			writeCodedBody(w, http.StatusMisdirectedRequest, codeMisdirectedRequest, sentenceMisdirected, id)
		})).ServeHTTP(w, r)
		return
	}
	var door http.Handler
	switch bySNI {
	case siteConsole:
		s.cfg.Console.ServeHTTP(w, r)
		return
	case siteHome:
		door = s.cfg.Home
	case siteApp:
		door = s.cfg.App
	}
	if door == nil {
		s.notReady(w, r, bySNI, "door not served")
		return
	}
	// The per-request bound on a door request (carried fact 2 from #985): a
	// slow uploader or a slow reader holds the sign-in history drain's floor
	// only until it passes. The server keeps no such bound itself, because a
	// hijacked console WebSocket would inherit it. Go resets the connection's
	// deadlines after the request, so this bound never reaches the next one.
	rc := http.NewResponseController(w)
	deadline := s.cfg.Now().Add(s.cfg.RequestLifetime)
	if err := rc.SetReadDeadline(deadline); err != nil {
		s.notReady(w, r, bySNI, "request deadline unsupported")
		return
	}
	if err := rc.SetWriteDeadline(deadline); err != nil {
		s.notReady(w, r, bySNI, "request deadline unsupported")
		return
	}
	door.ServeHTTP(w, r)
}

// notReadyPage is the not-ready page's data.
type notReadyPage struct {
	Sentence, TryAgain, CorrelationID string
}

// notReady answers a door site whose door is not served with the not-ready
// page, 503, and the refusal record.
func (s *sites) notReady(w http.ResponseWriter, r *http.Request, at site, reason string) {
	id := s.cfg.IDs()
	logRefusal(r.Context(), s.cfg.Log, id, siteRoute, codeSigninUnavailable,
		slog.String("sni_site", at.String()), slog.String("reason", reason))
	// TRY AGAIN is the same address on this site: a path, never one a
	// browser would read as another host's.
	again := r.URL.RequestURI()
	if !strings.HasPrefix(again, "/") || strings.HasPrefix(again, "//") {
		again = "/"
	}
	ctype := "text/html; charset=utf-8"
	var b bytes.Buffer
	if err := notReadyTmpl.Execute(&b, notReadyPage{Sentence: sentenceSigninUnavailable, TryAgain: again, CorrelationID: id}); err != nil {
		// The template is fixed and parsed at init, and its data is strings:
		// a failure is a programming error, answered with the sentence alone.
		b.Reset()
		b.WriteString(sentenceSigninUnavailable + "\n")
		ctype = "text/plain; charset=utf-8"
	}
	h := w.Header()
	h.Set("Content-Security-Policy", notReadyPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(b.Bytes())
}
