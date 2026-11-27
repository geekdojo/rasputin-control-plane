package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/move"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
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
	Ways(ctx context.Context) breakglass.Ways
	RecordJob(sess breakglass.Session, id string)
	Reset(ctx context.Context, sess breakglass.Session, by authz.Submitter, id, token string, pw secret.Value) (*jobs.Job, error)
	MoveState(ctx context.Context) (breakglass.MoveRepair, error)
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
	sentenceJobStartFailed     = "The job couldn't be started. Try again."
	sentenceRepairActionBody   = "The request body must be a small JSON object with the fields this action takes."
	sentenceRepairNoPassword   = "Type a temporary password for this person, then confirm."
	sentenceRepairResetTarget  = "Only an administrator's or a designated account's sign-in can be reset here."
	sentenceRepairResetUsed    = "This repair session has already reset a sign-in. Make a new repair code to reset another."
	sentenceRepairResetOff     = "Resetting a sign-in isn't available on this control plane."
	sentenceRepairMoveUnread   = "The accounts from before the update couldn't be read. Try again."
	// sentenceRepairResetNext follows the account's name in the reset's
	// confirmation.
	sentenceRepairResetNext = "They sign in with it, choose a new password, add a passkey, security key or authenticator app " +
		"and save new recovery codes, then they are an administrator again. This is recorded and raises an alert."
)

// maxRepairActionBody bounds the reset's and the move's bodies.
const maxRepairActionBody = 8 << 10

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
	writeJSON(w, http.StatusOK, s.repair.Ways(r.Context()))
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
// for the session. The runner's kind policy decides it (repairSubmitFailed).
func (s *Server) handleRepairRestart(w http.ResponseWriter, r *http.Request) {
	sess, _ := breakglass.SessionFrom(r.Context()) // RequireRepair put it there
	job, err := s.runner.SubmitFor(r.Context(), submitter(r), breakglass.RestartKind, nil, nil)
	if err != nil {
		s.repairSubmitFailed(w, r, breakglass.RestartKind, err)
		return
	}
	s.repair.RecordJob(sess, job.ID)
	writeJSON(w, http.StatusAccepted, job)
}

// repairConfirm is a 409 repair_confirm's body: what the action would do,
// and the token a confirmed request carries back.
type repairConfirm struct {
	codedError
	StateToken string             `json:"stateToken"`
	Account    *breakglass.Target `json:"account,omitempty"`
	Accounts   *int               `json:"accounts,omitempty"`
}

// writeRepairConfirm answers 409 repair_confirm. It is the normal flow, so
// it writes no refusal record.
func (s *Server) writeRepairConfirm(w http.ResponseWriter, body repairConfirm) {
	body.Code, body.CorrelationID = codeRepairConfirm, s.newCorrelationID()
	writeJSON(w, http.StatusConflict, body)
}

// repairResetBody is POST /api/repair/reset's body. The password is copied
// into a secret.Value at once and never logged.
type repairResetBody struct {
	AccountID  string  `json:"accountId"`
	StateToken string  `json:"stateToken"`
	Password   *string `json:"password"`
}

// handleRepairReset is POST /api/repair/reset: the session's one reset of
// an administrator's or designated account's sign-in (C1). Without the
// current token it answers 409 with the account and the token; confirmed,
// it takes the temporary password and submits accounts.repair_reset, 202.
// breakglass.Service decides it; this maps its answers.
func (s *Server) handleRepairReset(w http.ResponseWriter, r *http.Request) {
	sess, _ := breakglass.SessionFrom(r.Context()) // RequireRepair put it there
	var body repairResetBody
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRepairActionBody)).Decode(&body)
	if err != nil || body.AccountID == "" {
		// The decoder's own text can quote the body, which may hold the
		// password, so only a fixed cause is logged.
		cause := "no_account"
		if err != nil {
			cause = bodyCause(err)
		}
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, sentenceRepairActionBody, slog.String("cause", cause))
		return
	}
	var pw secret.Value
	if body.Password != nil {
		pw = secret.New([]byte(*body.Password))
		body.Password = nil
	}
	defer pw.Destroy()
	job, err := s.repair.Reset(r.Context(), sess, submitter(r), body.AccountID, body.StateToken, pw)
	var confirm *breakglass.ResetConfirm
	var refused *accounts.PasswordRefused
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, job)
	case errors.As(err, &confirm):
		s.writeRepairConfirm(w, repairConfirm{
			codedError: codedError{Error: "This resets " + confirm.Target.Name + "'s sign-in: it removes their passkeys, security keys, " +
				"authenticator apps, recovery codes and roles, and sets the temporary password you type. " + sentenceRepairResetNext},
			StateToken: confirm.Token, Account: &confirm.Target})
	case errors.Is(err, breakglass.ErrNoPassword):
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, sentenceRepairNoPassword, slog.String("cause", "no_password"))
	case errors.Is(err, breakglass.ErrSessionEnded):
		s.noRepairSession(w)
	case errors.Is(err, accounts.ErrNotRepairTarget):
		s.writeCodedError(w, r, http.StatusForbidden, codeRepairResetTarget, sentenceRepairResetTarget, repairAttrs("breakglass.reset_refused")...)
	case errors.Is(err, breakglass.ErrResetUsed):
		s.writeCodedError(w, r, http.StatusForbidden, codeRepairResetUsed, sentenceRepairResetUsed, repairAttrs("breakglass.reset_refused")...)
	case errors.Is(err, breakglass.ErrResetUnavailable):
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeJobUnavailable, sentenceRepairResetOff, slog.String("kind", accounts.RepairResetKind))
	case errors.As(err, &refused):
		s.writeCodedError(w, r, http.StatusBadRequest, codePasswordRefused, refused.Sentence, slog.String("rule", refused.Rule))
	case errors.Is(err, accounts.ErrPasswordCheckUnavailable):
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codePasswordCheckUnavailable, msgPasswordCheckUnavailable)
	case errors.Is(err, accounts.ErrIdentityUnavailable):
		// The identity error names the account in its path: a fixed cause.
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgIdentityNotReady, slog.String("cause", "identity"))
	default:
		s.repairSubmitFailed(w, r, accounts.RepairResetKind, err)
	}
}

// handleRepairMove is POST /api/repair/move: the re-run of identity.move
// for the session (C9). The runner's kind table decides it on C9's state:
// a missing or stale token answers 409 with how many accounts come back and
// the current token; a confirmed one submits the job, 202.
func (s *Server) handleRepairMove(w http.ResponseWriter, r *http.Request) {
	sess, _ := breakglass.SessionFrom(r.Context()) // RequireRepair put it there
	var body struct {
		StateToken string `json:"stateToken"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRepairActionBody)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, sentenceRepairActionBody, slog.String("cause", bodyCause(err)))
		return
	}
	job, err := s.runner.SubmitFor(r.Context(), submitter(r), move.Kind, move.Spec{Repair: true, StateToken: body.StateToken}, nil)
	var kr *authz.KindRefusal
	switch {
	case err == nil:
		s.repair.RecordJob(sess, job.ID)
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "A repair session brought back the accounts from before the update.",
			repairAttrs("breakglass.move_submitted", slog.String("job_id", job.ID))...)
		writeJSON(w, http.StatusAccepted, job)
	case errors.As(err, &kr) && kr.Code == authz.CodeStateChanged:
		st, serr := s.repair.MoveState(r.Context())
		switch {
		case serr != nil:
			s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, sentenceRepairMoveUnread,
				slog.String("cause", "move_state"), slog.String("err", serr.Error()))
		case !st.Holds:
			s.writeCodedError(w, r, http.StatusForbidden, "job_"+authz.CodeMoveState, authz.KindSentence(authz.CodeMoveState),
				slog.String("kind", move.Kind))
		default:
			n := st.Accounts
			s.writeRepairConfirm(w, repairConfirm{codedError: codedError{Error: moveConfirmSentence(n)}, StateToken: st.Token, Accounts: &n})
		}
	default:
		s.repairSubmitFailed(w, r, move.Kind, err)
	}
}

// moveConfirmSentence is the move's confirmation for n accounts.
func moveConfirmSentence(n int) string {
	what := "the " + strconv.Itoa(n) + " accounts"
	if n == 1 {
		what = "the 1 account"
	}
	return "This brings back " + what + " this cluster had before its sign-in update, with no passwords: each person sets one " +
		"with their old passkey. Accounts and sign-in methods made since then are not in it, so if a backup from this version " +
		"exists, restore that instead."
}

// repairSubmitFailed answers a repair job's failed submission: the kind
// table's refusal (refusedSubmit); 503 job_unavailable for a kind this
// runner has no workflow for; any other failure 500 job_start_failed, under
// one ERROR record.
func (s *Server) repairSubmitFailed(w http.ResponseWriter, r *http.Request, kind string, err error) {
	if s.refusedSubmit(w, r, kind, err) {
		return
	}
	if errors.Is(err, jobs.ErrUnknownKind) {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeJobUnavailable, sentenceJobUnavailable,
			slog.String("kind", kind), slog.String("err", err.Error()))
		return
	}
	id := s.newCorrelationID()
	s.log.LogAttrs(r.Context(), slog.LevelError, "api: a repair job could not be started",
		append(repairAttrs("breakglass.job_failed"), slog.String("correlation_id", id),
			slog.String("kind", kind), slog.String("err", err.Error()))...)
	writeCodedBody(w, http.StatusInternalServerError, codeJobStartFailed, sentenceJobStartFailed, id)
}
