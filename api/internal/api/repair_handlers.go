package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The break-glass repair session's endpoints (geekdojo/geekdojo-brain#321).
//
// A repair session authenticates by its own cookie, __Host-rasputin-repair,
// bound to the origin it was opened at: the console's, or the control
// plane's primary LAN address, which the console's origin allowlist never
// holds. So repair routes never pass through RequireSession; gate() wraps
// them in RequireRepair, and wraps every console route in refuseRepair. The
// business rules (which origins, which code, which session) are
// breakglass.Service's; these handlers parse and map.

// repairCookieName is the repair session's cookie.
const repairCookieName = "__Host-rasputin-repair"

// maxRepairBody bounds POST /api/auth/break-glass's body.
const maxRepairBody = 1 << 10

// repairService is the break-glass business layer as the endpoints use it
// (breakglass.Service).
type repairService interface {
	Redeem(ctx context.Context, source netip.Addr, origin string, code secret.Value) (secret.Value, error)
	Resolve(ctx context.Context, cookie secret.Value, origin string) (breakglass.Session, bool)
	End(ctx context.Context, sess breakglass.Session)
	State(ctx context.Context, sess breakglass.Session) breakglass.StateView
	Ways() breakglass.Ways
	RecordJob(sess breakglass.Session, id string)
}

// SetRepair wires the break-glass service. Unset, the repair routes answer
// 401 and 503 and no console route is refused for a repair session. main
// calls it before Handler.
func (s *Server) SetRepair(r repairService) { s.repair = r }

// The sentences the repair endpoints answer with.
const (
	sentenceRepairOrigin       = "Repair codes are typed only at the console's own address or the control plane's address on your network."
	sentenceRepairSourceRefuse = "This device sent five wrong repair codes, so it can't try again until a new code is made."
	sentenceRepairCodeNone     = "No repair code is waiting. Run rasputin-api repair-code on the control plane first."
	sentenceRepairCodeWrong    = "That repair code isn't right. Check it and try again."
	sentenceRepairCodeBody     = "Send the repair code in the form, not the address."
	sentenceRepairUnavailable  = "Repair codes aren't available on this control plane."
	sentenceRepairSession      = "Open a repair session with a repair code first."
	sentenceRepairCookieTwice  = "The request carried the repair session's cookie more than once. Clear this site's cookies and open the repair session again."
	sentenceRepairOnly         = "A repair session can only repair sign-in."
	sentenceRepairFailed       = "The repair session couldn't be opened. Try again."
	sentenceJobUnavailable     = "This job can't run on this control plane."
)

// repairAttrs are the fields every break-glass refusal record carries.
func repairAttrs(event string, extra ...slog.Attr) []slog.Attr {
	return append([]slog.Attr{slog.String("event", event), slog.String("component", "breakglass"),
		slog.String("actor", "break-glass")}, extra...)
}

// requestOrigin is the origin r was sent to, https://<Host>, normalized; and
// whether every Origin header r carries equals it.
func requestOrigin(r *http.Request) (string, bool) {
	o, err := auth.NormalizeOrigin("https://" + r.Host)
	if err != nil {
		return "", false
	}
	for _, h := range r.Header.Values("Origin") {
		if n, err := auth.NormalizeOrigin(h); err != nil || n != o {
			return o, false
		}
	}
	return o, true
}

// requestSource is the address r came from, without its port: the same
// derivation as the sign-in doors' (door/parse.go). No header is read.
func requestSource(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// repairCookie is the one repair cookie r carries: found is false with
// none, and twice is true with more than one.
func repairCookie(r *http.Request) (value secret.Value, found, twice bool) {
	cs := r.CookiesNamed(repairCookieName)
	switch len(cs) {
	case 0:
		return secret.Value{}, false, false
	case 1:
		return secret.New([]byte(cs[0].Value)), true, false
	}
	return secret.Value{}, false, true
}

// setRepairCookie writes the repair session's cookie: HttpOnly, Secure,
// SameSite=Strict, Path=/ and no Domain, for the session's seven days.
func setRepairCookie(w http.ResponseWriter, v secret.Value) {
	http.SetCookie(w, &http.Cookie{
		Name: repairCookieName, Value: string(v.Reveal()), Path: "/",
		MaxAge: int(auth.SessionLifetime.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// clearRepairCookie expires the repair session's cookie.
func clearRepairCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: repairCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// noRepairSession answers 401 repair_session_required. Like RequireSession's
// 401 it writes no record: /login asks on every visit whether a repair
// session is live, and a browser without one is the normal case.
func (s *Server) noRepairSession(w http.ResponseWriter) {
	writeCodedBody(w, http.StatusUnauthorized, codeRepairSessionRequired, sentenceRepairSession, s.newCorrelationID())
}

// RequireRepair runs next with the live repair session in its context: 401
// without one at this origin, 400 for the cookie sent twice, and 403 for an
// Origin header that differs from the request's own.
func (s *Server) RequireRepair(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.repair == nil {
			s.noRepairSession(w)
			return
		}
		origin, same := requestOrigin(r)
		if !same {
			s.writeCodedError(w, r, http.StatusForbidden, codeRepairOrigin, sentenceRepairOrigin,
				repairAttrs("breakglass.session_refused", slog.String("reason", "origin"))...)
			return
		}
		cookie, found, twice := repairCookie(r)
		defer cookie.Destroy()
		switch {
		case twice:
			s.writeCodedError(w, r, http.StatusBadRequest, codeRepairCookieDuplicate, sentenceRepairCookieTwice)
			return
		case !found:
			s.noRepairSession(w)
			return
		}
		sess, ok := s.repair.Resolve(r.Context(), cookie, origin)
		if !ok {
			s.noRepairSession(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(breakglass.WithSession(r.Context(), sess)))
	})
}

// refuseRepair answers 403 repair_only, ahead of RequireSession, for a
// request that carries a live repair session: a repair session reaches no
// console route, whatever else the request carries.
func (s *Server) refuseRepair(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.repair != nil {
			if cookie, found, _ := repairCookie(r); found {
				origin, _ := requestOrigin(r)
				_, live := s.repair.Resolve(r.Context(), cookie, origin)
				cookie.Destroy()
				if live {
					s.writeCodedError(w, r, http.StatusForbidden, codeRepairOnly, sentenceRepairOnly,
						repairAttrs("breakglass.route_refused")...)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// repairCodeBody is POST /api/auth/break-glass's body.
type repairCodeBody struct {
	Code string `json:"code"`
}

// handleBreakGlass is POST /api/auth/break-glass: open, the code is the
// authentication. The code travels only in the body.
func (s *Server) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	if s.repair == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeRepairUnavailable, sentenceRepairUnavailable)
		return
	}
	refuse := func(status int, code, msg, reason string, source netip.Addr) {
		s.writeCodedError(w, r, status, code, msg, repairAttrs("breakglass.redeem_refused",
			slog.String("source", source.String()), slog.String("reason", reason))...)
	}
	source, ok := requestSource(r)
	if !ok {
		refuse(http.StatusBadRequest, codeRepairCodeBody, sentenceRepairCodeBody, "source", source)
		return
	}
	origin, same := requestOrigin(r)
	if !same {
		refuse(http.StatusForbidden, codeRepairOrigin, sentenceRepairOrigin, "origin", source)
		return
	}
	if r.URL.RawQuery != "" {
		refuse(http.StatusBadRequest, codeRepairCodeBody, sentenceRepairCodeBody, "query", source)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRepairBody))
	var body repairCodeBody
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	clear(raw)
	if err != nil || strings.TrimSpace(body.Code) == "" {
		refuse(http.StatusBadRequest, codeRepairCodeBody, sentenceRepairCodeBody, "body", source)
		return
	}
	code := secret.New([]byte(body.Code))
	defer code.Destroy()
	cookie, err := s.repair.Redeem(r.Context(), source, origin, code)
	switch {
	case errors.Is(err, breakglass.ErrOrigin):
		refuse(http.StatusForbidden, codeRepairOrigin, sentenceRepairOrigin, "origin", source)
		return
	case errors.Is(err, breakglass.ErrSourceRefused):
		refuse(http.StatusTooManyRequests, codeRepairSourceRefused, sentenceRepairSourceRefuse, "source_refused", source)
		return
	case errors.Is(err, breakglass.ErrNoCode):
		refuse(http.StatusUnauthorized, codeRepairCodeNone, sentenceRepairCodeNone, "no_code", source)
		return
	case errors.Is(err, breakglass.ErrWrongCode):
		refuse(http.StatusUnauthorized, codeRepairCodeWrong, sentenceRepairCodeWrong, "wrong_code", source)
		return
	case err != nil:
		id := s.newCorrelationID()
		s.log.LogAttrs(r.Context(), slog.LevelError, "api: a repair session could not be opened",
			append(repairAttrs("breakglass.redeem_failed"), slog.String("correlation_id", id), slog.String("err", err.Error()))...)
		writeCodedBody(w, http.StatusInternalServerError, codeRepairUnavailable, sentenceRepairFailed, id)
		return
	}
	setRepairCookie(w, cookie)
	cookie.Destroy()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRepairWays is GET /api/repair/ways: open, the ways to make a code on
// this control plane. No secret and no session.
func (s *Server) handleRepairWays(w http.ResponseWriter, r *http.Request) {
	if s.repair == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeRepairUnavailable, sentenceRepairUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, s.repair.Ways())
}

// handleRepairState is GET /api/repair/state: what the session may see and
// do now.
func (s *Server) handleRepairState(w http.ResponseWriter, r *http.Request) {
	sess, _ := breakglass.SessionFrom(r.Context()) // RequireRepair put it there
	writeJSON(w, http.StatusOK, s.repair.State(r.Context(), sess))
}

// handleRepairEnd is POST /api/repair/end: the operator ends the session.
func (s *Server) handleRepairEnd(w http.ResponseWriter, r *http.Request) {
	sess, _ := breakglass.SessionFrom(r.Context()) // RequireRepair put it there
	s.repair.End(r.Context(), sess)
	clearRepairCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRepairRestart is POST /api/repair/restart: submits identity.restart
// for the session. The runner's kind policy decides it.
func (s *Server) handleRepairRestart(w http.ResponseWriter, r *http.Request) {
	sess, _ := breakglass.SessionFrom(r.Context()) // RequireRepair put it there
	job, err := s.runner.SubmitFor(r.Context(), submitter(r), breakglass.RestartKind, nil, nil)
	if err != nil {
		if s.refusedSubmit(w, r, breakglass.RestartKind, err) {
			return
		}
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeJobUnavailable, sentenceJobUnavailable,
			slog.String("kind", breakglass.RestartKind), slog.String("err", err.Error()))
		return
	}
	s.repair.RecordJob(sess, job.ID)
	writeJSON(w, http.StatusAccepted, job)
}
