package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The move's bridge (geekdojo/geekdojo-brain#1005, Identity 5.2; the
// bridge's register row): a moved operator's only credential after the
// update is the passkey in rasputin.db. On the console's origin it does one
// thing: a ceremony against the old tables, with user verification
// required, yields a single-use grant bound to the moved account and to
// this browser's host-only cookie. The grant opens no session and
// authorizes only accounts.set_first_password for that account, which sets
// the account's first password and email. Nothing here writes the old
// tables.

const (
	// bridgeCookieName names this browser's ceremony, then its grant.
	bridgeCookieName = "__Host-rasputin-bridge"
	// bridgeLifetime bounds a ceremony and a grant (the bridge's register
	// row, its timer-audit row). The grant is spent by its submission, or
	// replaced by a newer ceremony from the same browser, which are the
	// facts that end it; one abandoned produces no fact the api could
	// observe, so this bound is what frees its memory.
	bridgeLifetime = 15 * time.Minute
	// maxBridgeRecords caps the in-memory map: /api/auth/bridge/begin is
	// open, so without a cap it grows with every request.
	maxBridgeRecords = 1024
	// bridgeBodyLimit bounds the finish and password bodies.
	bridgeBodyLimit = 8 << 10
	// bridgeKeyBytes is the cookie's length in random bytes.
	bridgeKeyBytes = 32
	// bridgeNext is where the browser goes once the password is set.
	bridgeNext = "/api/auth/signin"
	// bridgeChooser is the CHOOSE A PASSWORD page.
	bridgeChooser = "/login/bridge"
)

// The bridge's refusal codes (ERR-BOUNDARY).
const (
	BridgeCodeExpired                  = "bridge_expired"
	BridgeCodeDuplicateCookie          = "duplicate_cookie"
	BridgeCodePasskeyRefused           = "passkey_refused"
	BridgeCodeNotMoved                 = "not_moved"
	BridgeCodeHasPassword              = "has_password"
	BridgeCodeUnavailable              = "bridge_unavailable"
	BridgeCodeInvalidRequest           = "invalid_request"
	BridgeCodeEmailInvalid             = "email_invalid"
	BridgeCodeEmailListed              = "email_listed"
	BridgeCodeEmailTaken               = "email_taken"
	BridgeCodePasswordRefused          = "password_refused"
	BridgeCodePasswordCheckUnavailable = "password_check_unavailable"
	BridgeCodeGrantUsed                = "grant_used"
	BridgeCodeNotSet                   = "not_set"
)

// The bridge's sentences (ERR-MESSAGE).
const (
	sentenceBridgeExpired   = "This step has expired. Start again from the sign-in page."
	sentenceBridgeDuplicate = "The request carried the " + bridgeCookieName + " cookie more than once. Clear this site's cookies and start again from the sign-in page."
	sentencePasskeyRefused  = "That passkey wasn't accepted. Use the passkey you signed in to this Rasputin with before the update."
	sentenceNotMoved        = "Your account hasn't moved to the new sign-in yet. Try again in a few minutes."
	// SentenceHasPassword is an account that already holds a password, at
	// the bridge's finish or in accounts.set_first_password.
	SentenceHasPassword       = "This account already has a password, so sign in with it instead."
	sentenceBridgeUnavailable = "Sign-in isn't available right now, so your passkey couldn't be checked. Try again shortly."
	// sentenceCheckUnavailable is a dependency that failed while the
	// password step checked the password and email: the passkey was
	// accepted and the grant is unspent, so trying again works.
	sentenceCheckUnavailable = "Your passkey was accepted, but Rasputin couldn't check your new password and email right now. Try again shortly."
	sentenceBridgeOff        = "Signing in with a passkey from before the update isn't available on this Rasputin."
	sentenceBridgeTooLarge   = "The request is too large."
	sentenceBridgeBadRequest = "The request couldn't be read. Start again from the sign-in page."
	sentenceEmailInvalid     = "Enter your email address, such as name@example.com."
	sentenceGrantUsed        = "This step has already been used. Start again from the sign-in page."
	sentencePasswordNotSet   = "Rasputin couldn't set your password. Start again from the sign-in page."
	sentenceOfferUnreadable  = "Rasputin couldn't check for accounts from before the update."
)

// MovedAccount is a pre-update operator's moved account, as the bridge and
// the pre-update session read it (*move.Accounts).
type MovedAccount struct {
	// Sub is the moved account's id; Name its sign-in name, OldName the
	// pre-update one.
	Sub, Name, OldName string
	// Designated is that the account holds a designation: only then does a
	// pre-update session resolve (F-1005-06).
	Designated bool
	// Roles are the console roles a pre-update session carries: admin
	// while the moved designation stands, otherwise none (C25).
	Roles []string
	// NeedsPassword is that the account has not set its first password.
	NeedsPassword bool
}

// MovedAccounts reads the move's local facts (*move.Accounts).
type MovedAccounts interface {
	// Account is the moved account of the old user handle, and false when
	// the handle has no move row.
	Account(ctx context.Context, handle []byte) (MovedAccount, bool, error)
	// Offered is whether /login offers the bridge.
	Offered(ctx context.Context) (bool, error)
}

// FirstPassword is the moved account's first password and email
// (*accounts.FirstPassword). Check and Set refuse with *BridgeRefusal;
// any other error is a dependency that did not answer.
type FirstPassword interface {
	HasPassword(ctx context.Context, sub string) (bool, error)
	Check(ctx context.Context, sub string, pw, email secret.Value) error
	Set(ctx context.Context, by authz.Submitter, sub string, pw, email secret.Value) error
}

// BridgeRefusal is a refusal the person reads: a stable code and its
// sentence.
type BridgeRefusal struct{ Code, Sentence string }

func (e *BridgeRefusal) Error() string { return "auth: the bridge refused: " + e.Code }

// status is the refusal's HTTP status.
func (e *BridgeRefusal) status() int {
	switch e.Code {
	case BridgeCodePasswordCheckUnavailable, BridgeCodeUnavailable:
		return http.StatusServiceUnavailable
	case BridgeCodeHasPassword, BridgeCodeNotSet, BridgeCodeGrantUsed:
		return http.StatusConflict
	}
	return http.StatusUnprocessableEntity
}

// BridgeDeps are the bridge's collaborators. InstallBridge refuses a
// missing one.
type BridgeDeps struct {
	Accounts      MovedAccounts
	FirstPassword FirstPassword
	// SignInOrigin is the home door's origin, https://sso-<cid>.local,
	// which the CHOOSE A PASSWORD page names as where the person goes next.
	SignInOrigin string
	// NewCorrelationID ties a refusal's body to its log record.
	NewCorrelationID func() string
	Now              func() time.Time
	Rand             io.Reader
	Log              *slog.Logger
}

// bridgeRecord is one browser's ceremony or grant.
type bridgeRecord struct {
	// session is a ceremony's WebAuthn state; nil for a grant.
	session *webauthn.SessionData
	grant   *bridgeGrant
	expires time.Time
}

// bridgeGrant is a verified pre-update passkey's grant: its moved account.
// spent is set once, by the submission that uses it.
type bridgeGrant struct {
	sub, name, oldName string
	spent              atomic.Bool
}

// Bridge serves the bridge's routes.
type Bridge struct {
	d       BridgeDeps
	web     *webauthn.WebAuthn
	store   *Store
	records *expiring[*bridgeRecord]
	log     *slog.Logger
}

// InstallBridge installs the bridge and the pre-update session over the
// relying party and the old store the Service already holds. It refuses a
// missing collaborator and does no I/O. Until it is called, the bridge's
// routes answer 404 and no pre-update session resolves.
func (s *Service) InstallBridge(d BridgeDeps) error {
	switch {
	case d.Accounts == nil, d.FirstPassword == nil, d.SignInOrigin == "", d.NewCorrelationID == nil,
		d.Now == nil, d.Rand == nil, d.Log == nil, s.store == nil:
		return errNilDep("InstallBridge")
	}
	b := &Bridge{d: d, web: s.web, store: s.store, log: d.Log.With("component", "auth"),
		records: newExpiring(d.Now, maxBridgeRecords,
			func(r *bridgeRecord) time.Time { return r.expires },
			func(*bridgeRecord) {})}
	pu := &preUpdate{store: s.store, accounts: d.Accounts, now: d.Now}
	s.signInMu.Lock()
	defer s.signInMu.Unlock()
	s.bridge, s.preUpdate = b, pu
	return nil
}

// bridgeOf is the installed bridge, or nil.
func (s *Service) bridgeOf() *Bridge {
	s.signInMu.RLock()
	defer s.signInMu.RUnlock()
	return s.bridge
}

// bridged runs h on the installed bridge, or answers 404 without one.
func (s *Service) bridged(h func(*Bridge, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := s.bridgeOf()
		if b == nil {
			writeJSON(w, http.StatusNotFound, bridgeError{Error: sentenceBridgeOff, Code: BridgeCodeUnavailable})
			return
		}
		h(b, w, r)
	}
}

// bridgeError is the api's coded error body: "error" is the sentence the
// UI shows (body.error), with the code and the correlation id beside it.
type bridgeError struct {
	Error         string `json:"error"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlationId,omitempty"`
}

// refuse answers a refusal in the coded shape and writes its one log
// record, under the same correlation id, at level, with attrs. Never a
// handle, name, email, password, assertion or cookie.
func (b *Bridge) refuse(w http.ResponseWriter, r *http.Request, status int, code, sentence string, level slog.Level, event string, attrs ...slog.Attr) {
	id := b.d.NewCorrelationID()
	all := append([]slog.Attr{slog.String("event", event), slog.String("correlation_id", id), slog.String("code", code)}, attrs...)
	b.log.LogAttrs(r.Context(), level, "The pre-update passkey step was refused.", all...)
	writeJSON(w, status, bridgeError{Error: sentence, Code: code, CorrelationID: id})
}

// unavailable is a dependency that did not answer: 503, one ERROR record.
func (b *Bridge) unavailable(w http.ResponseWriter, r *http.Request, kind string, err error) {
	b.unavailableWith(w, r, kind, sentenceBridgeUnavailable, err)
}

// unavailableWith is unavailable with the sentence for the step it failed
// at. The error itself is not logged: an identity-service error names the
// account in its path, so only its cause and status go in the record
// (LOG-SECRETS), as in SignIn's claim (signin.go).
func (b *Bridge) unavailableWith(w http.ResponseWriter, r *http.Request, kind, sentence string, err error) {
	attrs := []slog.Attr{slog.String("kind", kind), slog.String("cause", dependencyCause(err))}
	var ie *idclient.Error
	if errors.As(err, &ie) {
		attrs = append(attrs, slog.Int("status", ie.Status))
	}
	b.refuse(w, r, http.StatusServiceUnavailable, BridgeCodeUnavailable, sentence, slog.LevelError, "bridge.unavailable", attrs...)
}

// dependencyCause is a fixed word for why a dependency failed.
func dependencyCause(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	return kindOf(err)
}

// key is a fresh cookie value from the injected randomness.
func (b *Bridge) key() (string, error) {
	raw := make([]byte, bridgeKeyBytes)
	if _, err := io.ReadFull(b.d.Rand, raw); err != nil {
		return "", fmt.Errorf("auth: bridge key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// cookie reads the browser's one bridge cookie. A duplicate answers 400
// and a missing one 401; either way ok is false.
func (b *Bridge) cookie(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := oneCookie(r, bridgeCookieName)
	switch {
	case errors.Is(err, errDuplicateCookie):
		b.refuse(w, r, http.StatusBadRequest, BridgeCodeDuplicateCookie, sentenceBridgeDuplicate, slog.LevelWarn,
			"bridge.refused", slog.String("reason", "record"))
		return "", false
	case err != nil:
		b.expired(w, r)
		return "", false
	}
	return c.Value, true
}

// expired answers a missing, spent or expired record.
func (b *Bridge) expired(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, bridgeCookieName)
	b.refuse(w, r, http.StatusUnauthorized, BridgeCodeExpired, sentenceBridgeExpired, slog.LevelWarn,
		"bridge.refused", slog.String("reason", "record"))
}

// body reads at most bridgeBodyLimit bytes: 413 beyond it, 400 on any
// other read error.
func (b *Bridge) body(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bridgeBodyLimit))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		b.refuse(w, r, http.StatusRequestEntityTooLarge, BridgeCodeInvalidRequest, sentenceBridgeTooLarge, slog.LevelWarn,
			"bridge.refused", slog.String("reason", "body"), slog.String("cause", "too_large"))
		return nil, false
	case err != nil:
		b.refuse(w, r, http.StatusBadRequest, BridgeCodeInvalidRequest, sentenceBridgeBadRequest, slog.LevelWarn,
			"bridge.refused", slog.String("reason", "body"), slog.String("cause", "read"))
		return nil, false
	}
	return raw, true
}

// POST /api/auth/bridge/begin — open. Starts a ceremony against the old
// passkeys: discoverable, user verification required, no
// allowCredentials. A ceremony or grant this browser already holds is
// replaced.
func (b *Bridge) begin(w http.ResponseWriter, r *http.Request) {
	switch c, err := oneCookie(r, bridgeCookieName); {
	case errors.Is(err, errDuplicateCookie):
		b.refuse(w, r, http.StatusBadRequest, BridgeCodeDuplicateCookie, sentenceBridgeDuplicate, slog.LevelWarn,
			"bridge.refused", slog.String("reason", "record"))
		return
	case err == nil:
		b.records.take(c.Value)
	}
	assertion, sd, err := b.web.BeginDiscoverableLogin()
	if err != nil {
		b.unavailable(w, r, "ceremony", err)
		return
	}
	key, err := b.key()
	if err != nil {
		b.unavailable(w, r, "random", err)
		return
	}
	b.records.put(key, &bridgeRecord{session: sd, expires: b.d.Now().Add(bridgeLifetime)})
	setCookie(w, bridgeCookieName, key, bridgeLifetime)
	writeJSON(w, http.StatusOK, assertion)
}

// errUnknownHandle is an assertion whose user handle names no old user.
var errUnknownHandle = errors.New("auth: no pre-update user has that handle")

// POST /api/auth/bridge/finish — open. Takes the ceremony (so it runs
// once), verifies the assertion against the old passkeys, and grants the
// moved account its first password, under a new cookie value. It writes
// nothing to the old tables (sign_count, clone_warning and last_login are
// left as they are), sets no session cookie and stores no session.
func (b *Bridge) finish(w http.ResponseWriter, r *http.Request) {
	key, ok := b.cookie(w, r)
	if !ok {
		return
	}
	rec, ok := b.records.take(key)
	if !ok || rec.session == nil {
		b.expired(w, r)
		return
	}
	raw, ok := b.body(w, r)
	if !ok {
		clearCookie(w, bridgeCookieName)
		return
	}
	ctx := r.Context()
	var lookupErr error
	handler := func(_, handle []byte) (webauthn.User, error) {
		u, err := b.store.GetUserByID(ctx, handle)
		switch {
		case err != nil:
			lookupErr = err
			return nil, err
		case u == nil:
			return nil, errUnknownHandle
		}
		return u, nil
	}
	user, err := b.verify(handler, *rec.session, raw)
	switch {
	case lookupErr != nil:
		clearCookie(w, bridgeCookieName)
		b.unavailable(w, r, "old_user", lookupErr)
		return
	case err != nil:
		clearCookie(w, bridgeCookieName)
		b.refuse(w, r, http.StatusUnauthorized, BridgeCodePasskeyRefused, sentencePasskeyRefused, slog.LevelWarn,
			"bridge.refused", slog.String("reason", "assertion"), slog.String("kind", assertionKind(err)))
		return
	}
	acct, moved, err := b.d.Accounts.Account(ctx, user.WebAuthnID())
	switch {
	case err != nil:
		clearCookie(w, bridgeCookieName)
		b.unavailable(w, r, "move_row", err)
		return
	case !moved:
		clearCookie(w, bridgeCookieName)
		b.refuse(w, r, http.StatusConflict, BridgeCodeNotMoved, sentenceNotMoved, slog.LevelWarn,
			"bridge.refused", slog.String("reason", "not_moved"))
		return
	}
	has, err := b.d.FirstPassword.HasPassword(ctx, acct.Sub)
	switch {
	case err != nil:
		clearCookie(w, bridgeCookieName)
		b.unavailable(w, r, "identity", err)
		return
	case has:
		clearCookie(w, bridgeCookieName)
		b.refuse(w, r, http.StatusConflict, BridgeCodeHasPassword, SentenceHasPassword, slog.LevelInfo,
			"bridge.has_password", slog.String("sub", acct.Sub))
		return
	}
	next, err := b.key()
	if err != nil {
		clearCookie(w, bridgeCookieName)
		b.unavailable(w, r, "random", err)
		return
	}
	b.records.put(next, &bridgeRecord{grant: &bridgeGrant{sub: acct.Sub, name: acct.Name, oldName: acct.OldName},
		expires: b.d.Now().Add(bridgeLifetime)})
	setCookie(w, bridgeCookieName, next, bridgeLifetime)
	b.log.LogAttrs(ctx, slog.LevelInfo, "A pre-update passkey was verified; its moved account may set its first password.",
		slog.String("event", "bridge.granted"), slog.String("sub", acct.Sub))
	writeJSON(w, http.StatusOK, map[string]string{"next": bridgeChooser})
}

// verify parses and checks the assertion in raw against sd.
func (b *Bridge) verify(handler webauthn.DiscoverableUserHandler, sd webauthn.SessionData, raw []byte) (webauthn.User, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return nil, err
	}
	user, _, err := b.web.ValidatePasskeyLogin(handler, sd, parsed)
	return user, err
}

// assertionKind is a refused assertion's class for the log: the protocol
// error's type, never its details, which can quote the response.
func assertionKind(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Type != "" {
		return pe.Type
	}
	return "other"
}

// grantView is a live grant as the CHOOSE A PASSWORD page reads it.
type grantView struct {
	Offered      bool   `json:"offered"`
	Name         string `json:"name,omitempty"`
	PreviousName string `json:"previousName,omitempty"`
	SignInOrigin string `json:"signInOrigin,omitempty"`
}

// GET /api/auth/bridge — open. offered drives /login's offer; with this
// browser's live, unspent grant it also names the account, its previous
// name when that changed, and the home door's origin.
func (b *Bridge) state(w http.ResponseWriter, r *http.Request) {
	offered, err := b.d.Accounts.Offered(r.Context())
	if err != nil {
		id := b.d.NewCorrelationID()
		b.log.LogAttrs(r.Context(), slog.LevelWarn, "The bridge's offer could not be read, so none is shown.",
			slog.String("event", "bridge.offer_unreadable"), slog.String("correlation_id", id))
		writeJSON(w, http.StatusInternalServerError, bridgeError{Error: sentenceOfferUnreadable, Code: BridgeCodeUnavailable, CorrelationID: id})
		return
	}
	v := grantView{Offered: offered}
	if c, err := oneCookie(r, bridgeCookieName); err == nil {
		if rec, ok := b.records.peek(c.Value); ok && rec.grant != nil && !rec.grant.spent.Load() {
			v.Name, v.SignInOrigin = rec.grant.name, b.d.SignInOrigin
			if rec.grant.oldName != rec.grant.name {
				v.PreviousName = rec.grant.oldName
			}
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// POST /api/auth/bridge/password — open, behind a live, unspent grant.
// Body: {"password": "…", "email": "…"}. The email is parsed here; Check's
// refusals answer 422 and keep the grant; then the grant is spent and Set
// runs the job and waits for its outcome.
func (b *Bridge) password(w http.ResponseWriter, r *http.Request) {
	key, ok := b.cookie(w, r)
	if !ok {
		return
	}
	rec, ok := b.records.peek(key)
	if !ok || rec.grant == nil {
		b.expired(w, r)
		return
	}
	g := rec.grant
	if g.spent.Load() {
		b.grantUsed(w, r)
		return
	}
	raw, ok := b.body(w, r)
	if !ok {
		return
	}
	var req struct {
		Password *string `json:"password"`
		Email    *string `json:"email"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Password == nil || req.Email == nil {
		// The decoder's text can quote the body, so only a fixed cause.
		clear(raw)
		b.refuse(w, r, http.StatusBadRequest, BridgeCodeInvalidRequest, sentenceBridgeBadRequest, slog.LevelWarn,
			"bridge.refused", slog.String("reason", "body"), slog.String("cause", "json"))
		return
	}
	clear(raw)
	addr, ok := parseEmail(*req.Email)
	if !ok {
		b.refuse(w, r, http.StatusUnprocessableEntity, BridgeCodeEmailInvalid, sentenceEmailInvalid, slog.LevelWarn,
			"bridge.password_refused", slog.String("cause", "email"))
		return
	}
	pw, email := secret.New([]byte(*req.Password)), secret.New([]byte(addr))
	defer pw.Destroy()
	defer email.Destroy()
	ctx := r.Context()
	if err := b.d.FirstPassword.Check(ctx, g.sub, pw, email); err != nil {
		b.refused(w, r, err, "bridge.password_refused", sentenceCheckUnavailable)
		return
	}
	if !g.spent.CompareAndSwap(false, true) {
		b.grantUsed(w, r)
		return
	}
	if err := b.d.FirstPassword.Set(ctx, authz.BridgeGrant(g.sub), g.sub, pw, email); err != nil {
		// The grant is spent, so a failure here sends the person back to
		// the sign-in page rather than to grant_used.
		b.refused(w, r, err, "bridge.not_set", sentencePasswordNotSet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"next": bridgeNext})
}

// grantUsed answers a second submission of one grant.
func (b *Bridge) grantUsed(w http.ResponseWriter, r *http.Request) {
	b.refuse(w, r, http.StatusConflict, BridgeCodeGrantUsed, sentenceGrantUsed, slog.LevelWarn,
		"bridge.refused", slog.String("reason", "grant_used"))
}

// refused answers Check's or Set's error: a *BridgeRefusal with its own
// code and sentence, anything else as a dependency that did not answer,
// told with down, the sentence for the step that failed.
func (b *Bridge) refused(w http.ResponseWriter, r *http.Request, err error, event, down string) {
	var ref *BridgeRefusal
	if !errors.As(err, &ref) {
		if errors.Is(err, context.Canceled) {
			b.refuse(w, r, http.StatusConflict, BridgeCodeNotSet, sentencePasswordNotSet, slog.LevelWarn, event, slog.String("cause", "cancelled"))
			return
		}
		b.unavailableWith(w, r, "first_password", down, err)
		return
	}
	level := slog.LevelWarn
	if ref.status() == http.StatusServiceUnavailable {
		level = slog.LevelError
	}
	b.refuse(w, r, ref.status(), ref.Code, ref.Sentence, level, event)
}

// parseEmail is the email the person typed, trimmed, when it parses as a
// bare address (no display name, no angle brackets).
func parseEmail(in string) (string, bool) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return "", false
	}
	return s, true
}

// prune drops expired ceremonies and grants (the janitor's sweep).
func (b *Bridge) prune() { b.records.prune() }
