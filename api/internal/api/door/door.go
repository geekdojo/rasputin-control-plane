// Package door is the sign-in doors' endpoint and relay
// (geekdojo/geekdojo-brain#985, Identity 4.3; signin-origin.md §5.2-§5.3):
// one handler type, configured twice by Build, once for the home door
// (sso-<cid>.local) and once for the app door (signin.<cid>.internal).
//
// A handler checks the raw path's shape, matches the request to its door's
// allowlist (routes.go) or answers the 404 door page, parses what is left into
// the policy's typed request (parse.go), asks the policy service (policy/),
// and either renders the refusal with its sentence or relays the request to
// the identity service over the door's own connection pool (relay.go). It
// writes the forwarded headers itself, owns the cookie rules both ways and
// sets one script policy per page class.
//
// The handlers are built and tested here; Identity 4.4 mounts them on their
// SNI sites and publishes their metrics.
package door

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
)

// Policy is the door policy service, as the endpoint calls it.
type Policy interface {
	Check(ctx context.Context, r policy.Request) policy.Decision
}

// Throttle is the throttle's answer hook: the endpoint reports when the
// identity service has answered a held credential post.
type Throttle interface {
	Answered(k policy.Key)
}

// Dirty is the sign-in history drain's signal (*events.Drainer): Begin
// records a relayed request that can store events until its end is called,
// and MarkDirty asks for a pass.
type Dirty interface {
	Begin() (end func())
	MarkDirty()
}

// Version is the identity service's resource version as last learned
// (*ResourceVersion): the theme files are served, and the app door's script
// policy names them, only under the version Current reports. Stale reports
// the fact that the service redirected a theme file, so the version changed.
type Version interface {
	Current() (v string, known bool)
	Stale()
}

// Config is one door handler's collaborators. New refuses a missing one.
type Config struct {
	// Door is the door's entry in the door table, and Kind which door it is.
	Door doors.Door
	Kind Kind
	// ConsoleOrigin is https://<cid>.local, which the home door's 404 page
	// and the registration refusals link to.
	ConsoleOrigin string
	Policy        Policy
	Throttle      Throttle
	// Transport is the relay's connection pool, over the rasputin-door leaf
	// (idclient.NewTransport): never the api's own.
	Transport http.RoundTripper
	// Upstream is the identity service's https listener on loopback.
	Upstream *url.URL
	// Theme is the built theme's allowlist, and Assets its login/resources
	// tree, whose css/ and img/ the door serves at /_signin/.
	Theme  Allowlist
	Assets fs.FS
	// Version is the learned resource version the theme files are served
	// under.
	Version Version
	// InstallName reads setup.install_name for the not-ready sentence.
	InstallName func(ctx context.Context) (string, error)
	Dirty       Dirty
	// IDs mints one correlation id per request.
	IDs func() string
	// Breach is the breached-password check a new password is asked of
	// before it is relayed (breach.go).
	Breach Breach
	Log    *slog.Logger
}

// Handler is one door.
type Handler struct {
	cfg      Config
	log      *slog.Logger
	pol      policies
	assets   map[string]asset
	mux      *http.ServeMux
	proxy    *httputil.ReverseProxy
	cop      *http.CrossOriginProtection
	handler  http.Handler
	requests atomic.Uint64
}

// New checks cfg and builds the handler. It does no network I/O; it reads
// Assets into memory.
func New(cfg Config) (*Handler, error) {
	missing := ""
	switch {
	case cfg.Door.Host == "" || cfg.Door.Issuer == "" || len(cfg.Door.Clients) == 0:
		missing = "Door"
	case cfg.Kind != Home && cfg.Kind != App:
		missing = "Kind"
	case cfg.ConsoleOrigin == "":
		missing = "ConsoleOrigin"
	case cfg.Policy == nil:
		missing = "Policy"
	case cfg.Throttle == nil:
		missing = "Throttle"
	case cfg.Transport == nil:
		missing = "Transport"
	case cfg.Upstream == nil || cfg.Upstream.Scheme != "https" || cfg.Upstream.Host == "":
		missing = "Upstream"
	case len(cfg.Theme.login) == 0:
		missing = "Theme"
	case cfg.Assets == nil:
		missing = "Assets"
	case cfg.Version == nil:
		missing = "Version"
	case cfg.InstallName == nil:
		missing = "InstallName"
	case cfg.Dirty == nil:
		missing = "Dirty"
	case cfg.IDs == nil:
		missing = "IDs"
	case cfg.Breach == nil:
		missing = "Breach"
	case cfg.Log == nil:
		missing = "Log"
	}
	if missing != "" {
		return nil, errors.New("door: Config." + missing + " is missing")
	}
	assets, err := loadAssets(cfg.Assets)
	if err != nil {
		return nil, err
	}
	h := &Handler{
		cfg:    cfg,
		log:    cfg.Log.With("component", "signin-door"),
		pol:    policiesFor(cfg.Kind, cfg.Door.Host),
		assets: assets,
		mux:    http.NewServeMux(),
	}
	for _, r := range Routes(cfg.Kind) {
		h.mux.HandleFunc(r.Pattern, h.route(r))
	}
	h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { h.notFound(w, r, stateOf(r)) })
	h.proxy = h.newProxy()
	h.cop = http.NewCrossOriginProtection()
	if cfg.Kind == App {
		// A SAML device's POST binding arrives from the device's own site.
		h.cop.AddInsecureBypassPattern("POST " + realmPrefix + "protocol/saml")
	}
	h.cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := stateOf(r)
		st.refused = "cross_origin"
		h.render(w, http.StatusForbidden, h.refusalPage(sentenceCrossOrigin, st))
	}))
	h.handler = h.cop.Handler(h.mux)
	return h, nil
}

// Shared is what both doors share in Build.
type Shared struct {
	ConsoleOrigin string
	Policy        Policy
	Throttle      Throttle
	Transport     http.RoundTripper
	Upstream      *url.URL
	Theme         Allowlist
	Assets        fs.FS
	Version       Version
	InstallName   func(ctx context.Context) (string, error)
	Dirty         Dirty
	IDs           func() string
	Breach        Breach
	Log           *slog.Logger
}

// Build is the one place both doors are assembled from the door table.
func Build(table doors.Table, s Shared) (home, app *Handler, err error) {
	cfg := func(d doors.Door, k Kind) Config {
		return Config{Door: d, Kind: k, ConsoleOrigin: s.ConsoleOrigin, Policy: s.Policy, Throttle: s.Throttle,
			Transport: s.Transport, Upstream: s.Upstream, Theme: s.Theme, Assets: s.Assets, Version: s.Version,
			InstallName: s.InstallName, Dirty: s.Dirty, IDs: s.IDs, Breach: s.Breach, Log: s.Log}
	}
	if home, err = New(cfg(table.Home, Home)); err != nil {
		return nil, nil, err
	}
	if app, err = New(cfg(table.App, App)); err != nil {
		return nil, nil, err
	}
	return home, app, nil
}

// Kind is which door the handler is.
func (h *Handler) Kind() Kind { return h.cfg.Kind }

// The endpoint's own sentences.
const (
	sentenceCrossOrigin = "This sign-in request came from another site, so it was refused. Start signing in again."
	sentenceMethod      = "This sign-in page can't be used that way, so the request was refused. Start signing in again."
	sentenceNotFound    = "There is nothing here. "
)

// reqState is one request's record, carried in its context.
type reqState struct {
	id         string
	pattern    string
	refused    string
	errorClass string
	level      slog.Level
	// breach is the breach check's outcome on a post that sets a password,
	// and breachErrorClass its error's class when it could not finish.
	breach           string
	breachErrorClass string
}

type stateKey struct{}

func stateOf(r *http.Request) *reqState {
	if st, ok := r.Context().Value(stateKey{}).(*reqState); ok {
		return st
	}
	return &reqState{}
}

// statusWriter records the status a handler set. A handler that writes a
// body without setting one, or writes nothing, has answered 200 (net/http
// sends it), so the record reads 200 then.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

// written is the status the client was sent.
func (s *statusWriter) written() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ServeHTTP serves one door request and writes its one log record.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.requests.Add(1)
	st := &reqState{id: h.cfg.IDs(), pattern: "none", level: slog.LevelDebug}
	sw := &statusWriter{ResponseWriter: w}
	defer h.logRequest(r.Context(), st, sw)
	r = r.WithContext(context.WithValue(r.Context(), stateKey{}, st))
	if bad := checkShape(r.RequestURI); bad != nil {
		st.refused, st.level = bad.reason, slog.LevelInfo
		h.render(sw, http.StatusBadRequest, h.refusalPage(bad.sentence, st))
		return
	}
	h.handler.ServeHTTP(sw, r)
}

// logRequest writes the request's one record: its door, pattern, status and
// correlation id, a refusal's reason, and the breach check's outcome. Never the URL, its query, a
// cookie, the address or a user (LOG-SECRETS).
func (h *Handler) logRequest(ctx context.Context, st *reqState, sw *statusWriter) {
	attrs := []slog.Attr{
		slog.String("door", h.cfg.Kind.String()), slog.String("pattern", st.pattern),
		slog.Int("status", sw.written()), slog.String("correlation_id", st.id),
	}
	level, msg := st.level, "sign-in door request relayed"
	if st.refused != "" {
		attrs = append(attrs, slog.String("refused", st.refused))
		msg = "sign-in door request refused"
		if level < slog.LevelInfo {
			level = slog.LevelInfo
		}
	}
	attrs, level, msg = breachRecord(st, attrs, level, msg)
	if st.errorClass != "" {
		attrs = append(attrs, slog.String("error_class", st.errorClass))
		msg, level = "sign-in door upstream failed", slog.LevelWarn
	}
	h.log.LogAttrs(ctx, level, msg, attrs...)
}

// notFound is the 404 door page; at the home door it names the console.
func (h *Handler) notFound(w http.ResponseWriter, r *http.Request, st *reqState) {
	st.refused = "not_found"
	sentence := sentenceNotFound + "Sign in from the app you were using."
	p := h.refusalPage("", st)
	if h.cfg.Kind == Home {
		sentence = sentenceNotFound + "The Rasputin console is at " + h.cfg.ConsoleOrigin + "."
		p.Back, p.BackText = h.cfg.ConsoleOrigin, "Go to "+h.cfg.ConsoleOrigin
	}
	p.Sentence, p.Heading, p.Title = sentence, "NOT FOUND", "Not found"
	h.render(w, http.StatusNotFound, p)
}

// route is one allowlisted route's handler.
func (h *Handler) route(rt Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := stateOf(r)
		st.pattern = rt.Pattern
		if !slices.Contains(rt.Methods, r.Method) {
			st.refused, st.level = "method", slog.LevelInfo
			h.render(w, http.StatusMethodNotAllowed, h.refusalPage(sentenceMethod, st))
			return
		}
		switch rt.Kind {
		case policy.RouteSignin:
			h.serveAsset(w, r, st)
			return
		case policy.RouteTheme:
			common := strings.Contains(rt.Pattern, "/common/keycloak/")
			// Only the exact version learned from the running service; with
			// none known, every theme path is the 404 door page.
			v, known := h.cfg.Version.Current()
			if !known || r.PathValue("v") != v || !h.cfg.Theme.allows(common, r.PathValue("file")) {
				h.notFound(w, r, st)
				return
			}
		}
		d := h.cfg.Policy.Check(r.Context(), parse(r, h.cfg.Kind, rt.Kind))
		if !d.Allow {
			h.refuse(w, r, st, d)
			return
		}
		if h.warned(w, r, rt, st) {
			return
		}
		h.relay(w, r, rt, d)
	}
}

// refuse renders a policy refusal.
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, st *reqState, d policy.Decision) {
	st.refused, st.level = d.Reason, slog.LevelInfo
	if d.Reason == policy.ReasonAdminAccount || d.Reason == policy.ReasonUnreadable || d.Reason == policy.ReasonRegistrationPaused {
		st.level = slog.LevelWarn
	}
	if d.NotReady {
		h.render(w, d.Status, h.notReadyPage(r, st))
		return
	}
	if d.RetryAfter > 0 {
		w.Header().Set("Retry-After", retryAfter(d.RetryAfter))
	}
	p := h.refusalPage(d.Sentence, st)
	if d.BackLink {
		p.Back, p.BackText = h.cfg.ConsoleOrigin+"/login", "Back to sign-in"
	}
	h.render(w, d.Status, p)
}

// retryAfter is a Retry-After value in whole seconds, rounded up.
func retryAfter(d time.Duration) string {
	return strconv.FormatInt(int64((d+time.Second-1)/time.Second), 10)
}
