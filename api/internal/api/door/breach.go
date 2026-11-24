package door

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The breached-password warning (geekdojo/geekdojo-brain#1145, PR 2): when
// a person sets a new password, the door asks the breach check before the
// identity service sees it. A listed password gets the door's warning page,
// and the post is not relayed; the person chooses another or keeps it. The
// door keeps nothing between requests: "keep" is carried only by the page
// the person's own browser holds.

// Breach is the breached-password check, as the door calls it
// (breachcheck.Checker).
type Breach interface {
	Listed(ctx context.Context, password secret.Value) (bool, error)
}

// keepField marks a post the person sent from the warning page's Keep form.
// It reaches the identity service unchanged, which ignores it.
const keepField = "rasputin-keep-password"

// The breach check's outcomes, as the request's log record names them.
const (
	breachListed      = "listed"
	breachNotListed   = "not_listed"
	breachKept        = "kept"
	breachUnavailable = "unavailable"
)

// The warning page's words. The hint never names the service behind the
// check (principles.md: the UI never names backend technology).
const (
	sentenceBreached = "This password has appeared in a data breach, so attackers may already be trying it. You can choose a different one, or keep it."
	hintBreached     = "Checked against a public list of breached passwords. Your password was not sent."
)

// newPasswordField is the form field that carries a route's new password
// at the identity service's pin: registration's "password" and
// UPDATE_PASSWORD's "password-new". A reset's new password arrives at
// UPDATE_PASSWORD, and a sign-in sets none.
func newPasswordField(k policy.RouteKind) (string, bool) {
	switch k {
	case policy.RouteRegistration:
		return "password", true
	case policy.RouteRequiredAction:
		return "password-new", true
	}
	return "", false
}

// warned runs the breach check on an admitted post that sets a password,
// and reports whether it answered with the warning page (nothing relayed).
// The form is already parsed into r.PostForm by the policy's reading of the
// request. The field's first value is the one checked, as the identity
// service reads it; an absent or empty one is the identity service's to
// refuse.
func (h *Handler) warned(w http.ResponseWriter, r *http.Request, rt Route, st *reqState) bool {
	field, ok := newPasswordField(rt.Kind)
	if !ok || r.Method != http.MethodPost {
		return false
	}
	values := r.PostForm[field]
	if len(values) == 0 || len(values[0]) == 0 {
		return false
	}
	if _, kept := r.PostForm[keepField]; kept {
		st.breach = breachKept
		return false
	}
	pw := secret.New([]byte(values[0]))
	defer pw.Destroy()
	listed, err := h.cfg.Breach.Listed(r.Context(), pw)
	if err != nil {
		// Fail-open, by approved exception EX-1 (EXCEPTIONS.md, ERR-CLOSED;
		// geekdojo/geekdojo-brain#1146): the check grants nothing, relaying
		// without it is what Keep gives the person, and the identity
		// service's deny list still refuses common passwords offline. The
		// skip is logged at WARN with the error's class only.
		st.breach, st.breachErrorClass = breachUnavailable, errorClass(err)
		return false
	}
	if !listed {
		st.breach = breachNotListed
		return false
	}
	st.breach = breachListed
	h.render(w, http.StatusOK, h.warningPage(r, st))
	return true
}

// warningPage is the listed password's page: a link that re-renders the
// identity service's form (its action URL without session_code, which the
// identity service answers by showing the current step again), and a form
// that re-posts every original field with the keep marker to the original
// URL, whose session_code is still current because the first post never
// reached the identity service. The values are plain strings: the page goes
// only to the browser that just posted them, under no-store, and
// html/template escapes each one.
func (h *Handler) warningPage(r *http.Request, st *reqState) page {
	q := r.URL.Query()
	q.Del("session_code")
	choose := url.URL{Path: r.URL.Path, RawQuery: q.Encode()}
	var fields []hiddenField
	for _, name := range slices.Sorted(maps.Keys(r.PostForm)) {
		for _, v := range r.PostForm[name] {
			fields = append(fields, hiddenField{Name: name, Value: v})
		}
	}
	return page{
		Kind: pageWarning, Title: "Password found in a data breach", Heading: "PASSWORD FOUND IN A DATA BREACH",
		Sentence: sentenceBreached, Hint: hintBreached, Choose: choose.RequestURI(), Keep: r.URL.RequestURI(),
		KeepField: keepField, Fields: fields, CorrelationID: st.id, Error: true,
	}
}

// breachRecord adds the breach check's outcome to the request's record and
// returns its level and message.
func breachRecord(st *reqState, attrs []slog.Attr, level slog.Level, msg string) ([]slog.Attr, slog.Level, string) {
	if st.breach == "" {
		return attrs, level, msg
	}
	attrs = append(attrs, slog.String("breach_check", st.breach))
	switch st.breach {
	case breachListed:
		msg, level = "sign-in door password warning shown", max(level, slog.LevelInfo)
	case breachKept:
		level = max(level, slog.LevelInfo)
	case breachUnavailable:
		attrs = append(attrs, slog.String("breach_error_class", st.breachErrorClass))
		msg, level = "sign-in door relayed without the breach check", slog.LevelWarn
	}
	return attrs, level, msg
}
