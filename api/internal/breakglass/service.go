// Package breakglass is the console's last resort (geekdojo/geekdojo-brain#321):
// a one-time code, made by root on the control plane, opens one repair-only
// session at the console's own origin or at the control plane's address on
// the LAN.
//
// Service is the business layer and holds everything in memory, so an api
// restart retires the code and ends the session. It holds at most one
// outstanding code, as its SHA-256 hash only, and at most one session, as
// its cookie's SHA-256 hash only. Every state change follows a fact:
//
//   - a code retires when it is redeemed, when a newer code is issued, when
//     an administrator signs in normally (AdminSignedIn), or when the api
//     restarts. Wrong entries never retire it: 100 bits cannot be guessed,
//     and a counter would let any device switch the last resort off. A
//     source address that sends five wrong codes is refused until the code
//     retires;
//   - a session ends when the operator ends it, when a newer code is
//     redeemed, when an administrator signs in normally, or when the api
//     restarts. The console session's seven days (auth.SessionLifetime,
//     register row C72, D22) are its backstop.
//
// The transport is the caller's: Service takes the source address, the
// origin and the secrets, never a request (ARCH-BL). The repair-code socket
// (socket.go) and the api's endpoints call it.
package breakglass

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// maxWrong is how many wrong codes a source may send before it is refused
// until the code retires.
const maxWrong = 5

// cookieBytes is the repair session cookie's random length.
const cookieBytes = 32

// The refusals Redeem returns.
var (
	// ErrOrigin: the request did not come to the console's origin or the
	// control plane's primary LAN address.
	ErrOrigin = errors.New("breakglass: the origin is not one a repair code is redeemed at")
	// ErrSourceRefused: the source sent five wrong codes for the
	// outstanding code.
	ErrSourceRefused = errors.New("breakglass: the source is refused until a new code is made")
	// ErrNoCode: no code is outstanding.
	ErrNoCode = errors.New("breakglass: no repair code is outstanding")
	// ErrWrongCode: the code is not the outstanding one.
	ErrWrongCode = errors.New("breakglass: the repair code is wrong")
)

// The refusals Reset returns, besides accounts.ErrNotRepairTarget,
// *ResetConfirm and Resets.Submit's own.
var (
	// ErrResetUnavailable: no repair reset is wired (no sign-in service).
	ErrResetUnavailable = errors.New("breakglass: the repair reset isn't available on this control plane")
	// ErrResetUsed: the session has already reset an account.
	ErrResetUsed = errors.New("breakglass: this repair session has already reset a sign-in")
	// ErrNoPassword: a confirmed reset carried no temporary password.
	ErrNoPassword = errors.New("breakglass: the reset carries no temporary password")
	// ErrSessionEnded: the session ended while its reset was decided.
	ErrSessionEnded = errors.New("breakglass: the repair session has ended")
	// ErrMoveUnavailable: no move state is wired (no sign-in service).
	ErrMoveUnavailable = errors.New("breakglass: the accounts from before the update can't be read on this control plane")
)

// ResetConfirm is a reset that has not been confirmed: the request carried
// no token, or one that is not Token. Nothing was claimed.
type ResetConfirm struct {
	Target Target
	Token  string
}

func (e *ResetConfirm) Error() string { return "breakglass: confirm the reset of " + e.Target.ID }

// Alerts raises the event alerts (alerts.Service).
type Alerts interface {
	RaiseBreakGlassIssued(ctx context.Context, eventID string) error
	RaiseBreakGlassRedeemed(ctx context.Context, eventID string) error
	RaiseBreakGlassReset(ctx context.Context, eventID, accountID string) error
}

// Resets is the repair reset (accounts.RepairResets).
type Resets interface {
	Targets(ctx context.Context) ([]accounts.RepairTarget, error)
	Confirm(ctx context.Context, id string) (accounts.RepairTarget, string, error)
	Submit(ctx context.Context, by authz.Submitter, id string, pw secret.Value) (*jobs.Job, error)
}

// MoveRepair is C9's state as the repair page reads it: move.Repair's
// fields. This package can't import identity/move, whose tests import it.
type MoveRepair struct {
	Holds    bool
	Accounts int
	Token    string
}

// MoveState reads C9's state (move.State, through main's holder).
type MoveState interface {
	Repair(ctx context.Context) (MoveRepair, error)
}

// Jobs reads a job the session submitted (jobs.Store).
type Jobs interface {
	GetJob(ctx context.Context, id string) (*jobs.Job, error)
}

// Identity reads the sign-in service's state (identitystate.Monitor).
type Identity interface {
	State(ctx context.Context) (identitystate.State, error)
}

// Facts are what the control plane is, read when they are needed.
type Facts struct {
	// ConsoleHost is the console's host name, <cid>.local.
	ConsoleHost string
	// PrimaryIP is the control plane's primary LAN address now, or nil
	// (lanaddr.Watcher.PrimaryIP).
	PrimaryIP func() net.IP
	// BMCHost reports that this control plane is its BMC link's host, so its
	// serial port carries the link and no serial login
	// (<dataDir>/bmc-host).
	BMCHost func() bool
	// SerialLogin reports that a serial login getty runs on this control
	// plane now, so its serial console offers a root login
	// (geekdojo/geekdojo-brain#321, F-321-42).
	SerialLogin func(ctx context.Context) (bool, error)
}

// Deps are Service's collaborators. New refuses a nil one, except Identity:
// a control plane with no sign-in service has none.
type Deps struct {
	Now func() time.Time
	// Rand is the cookie's source (crypto/rand.Reader).
	Rand io.Reader
	// IDs mints each alert's event id.
	IDs    func() string
	Log    *slog.Logger
	Alerts Alerts
	Jobs   Jobs
	// Identity is nil when the sign-in service is off.
	Identity Identity
	// Busy reports a guard that keeps identity.restart from running now,
	// with the sentence a person reads (restart.Restarter.Busy).
	Busy  func(ctx context.Context) (reason string, busy bool)
	Facts Facts
	// Resets is the repair reset (C1), and Move C9's state; both nil when
	// the sign-in service is off.
	Resets Resets
	Move   MoveState
}

// session is the one repair session.
type session struct {
	cookie    [32]byte
	origin    string
	createdAt time.Time
	jobs      []string
	// reset is the session's one reset, claimed (C1).
	reset bool
}

// Service is the break-glass business layer.
type Service struct {
	d   Deps
	log *slog.Logger

	mu    sync.Mutex
	code  *[32]byte
	wrong map[netip.Addr]int
	sess  *session
}

// New checks d. It does no I/O.
func New(d Deps) (*Service, error) {
	switch {
	case d.Now == nil:
		return nil, errors.New("breakglass: Deps.Now is nil")
	case d.Rand == nil:
		return nil, errors.New("breakglass: Deps.Rand is nil")
	case d.IDs == nil:
		return nil, errors.New("breakglass: Deps.IDs is nil")
	case d.Log == nil:
		return nil, errors.New("breakglass: Deps.Log is nil")
	case d.Alerts == nil:
		return nil, errors.New("breakglass: Deps.Alerts is nil")
	case d.Jobs == nil:
		return nil, errors.New("breakglass: Deps.Jobs is nil")
	case d.Busy == nil:
		return nil, errors.New("breakglass: Deps.Busy is nil")
	case d.Facts.ConsoleHost == "" || d.Facts.PrimaryIP == nil || d.Facts.BMCHost == nil ||
		d.Facts.SerialLogin == nil:
		return nil, errors.New("breakglass: Deps.Facts is incomplete")
	}
	return &Service{
		d:     d,
		log:   d.Log.With("component", "breakglass", "actor", "break-glass"),
		wrong: map[netip.Addr]int{},
	}, nil
}

// Hash is a typed repair code's hash: the code with its spaces and dashes
// removed and its letters upper-cased, then SHA-256. The command hashes the
// code it prints through it, and Redeem hashes what was typed.
func Hash(code []byte) [32]byte {
	canon := make([]byte, 0, len(code))
	for _, r := range strings.ToUpper(string(code)) {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		canon = append(canon, string(r)...)
	}
	sum := sha256.Sum256(canon)
	clear(canon)
	return sum
}

// Issue makes hash the outstanding code, retiring any earlier one, and
// raises the issue alert. An alert that cannot be raised is logged and the
// code still stands: the alert is a notification, not a check, and a broken
// alert store must not switch the last resort off.
func (s *Service) Issue(ctx context.Context, hash [32]byte) error {
	s.mu.Lock()
	newer := s.code != nil
	h := hash
	s.code = &h
	clear(s.wrong)
	s.mu.Unlock()
	if newer {
		s.log.InfoContext(ctx, "The outstanding repair code was retired.", "event", "breakglass.code_retired", "reason", "newer")
	}
	s.log.WarnContext(ctx, "A repair code was issued on the control plane.", "event", "breakglass.code_issued")
	s.raise(ctx, "issued", s.d.Alerts.RaiseBreakGlassIssued)
	return nil
}

// raise raises one event alert under a fresh event id, logging a failure.
func (s *Service) raise(ctx context.Context, which string, fn func(context.Context, string) error) {
	if err := fn(ctx, s.d.IDs()); err != nil {
		s.log.ErrorContext(ctx, "A break-glass alert could not be raised.", "alert", "not_raised", "which", which, "err", err.Error())
	}
}

// RepairURLs are the two addresses a repair code is redeemed at: the
// console's origin, and the control plane's primary LAN address while it
// has one.
func (s *Service) RepairURLs() []string {
	out := []string{"https://" + s.d.Facts.ConsoleHost + "/repair"}
	if o := s.ipOrigin(); o != "" {
		out = append(out, o+"/repair")
	}
	return out
}

// ipOrigin is https://<primary LAN address>, or "" with none.
func (s *Service) ipOrigin() string {
	ip, ok := netip.AddrFromSlice(s.d.Facts.PrimaryIP())
	if !ok {
		return ""
	}
	o, err := auth.NormalizeOrigin("https://" + netip.AddrPortFrom(ip.Unmap(), 443).String())
	if err != nil {
		return ""
	}
	return o
}

// originAllowed reports whether origin, already normalized, is the console's
// or the primary LAN address's.
func (s *Service) originAllowed(origin string) bool {
	console, err := auth.NormalizeOrigin("https://" + s.d.Facts.ConsoleHost)
	if err == nil && origin == console {
		return true
	}
	ip := s.ipOrigin()
	return ip != "" && origin == ip
}

// Redeem opens a session for code typed at origin from source. It returns
// the session's cookie, which the caller sets and destroys, or ErrOrigin,
// ErrSourceRefused, ErrNoCode or ErrWrongCode. A redemption retires the code
// and ends any earlier session. Only a wrong code counts against source; an
// attempt with no code outstanding never does.
func (s *Service) Redeem(ctx context.Context, source netip.Addr, origin string, code secret.Value) (secret.Value, error) {
	if !s.originAllowed(origin) {
		return secret.Value{}, ErrOrigin
	}
	typed := Hash(code.Reveal())
	cookie := make([]byte, cookieBytes)
	if _, err := io.ReadFull(s.d.Rand, cookie); err != nil {
		return secret.Value{}, errors.Join(errors.New("breakglass: the session cookie could not be drawn"), err)
	}
	value := secret.New(encodeCookie(cookie))
	clear(cookie)

	s.mu.Lock()
	switch {
	case s.wrong[source] >= maxWrong:
		s.mu.Unlock()
		value.Destroy()
		return secret.Value{}, ErrSourceRefused
	case s.code == nil:
		s.mu.Unlock()
		value.Destroy()
		return secret.Value{}, ErrNoCode
	case subtle.ConstantTimeCompare(typed[:], s.code[:]) != 1:
		s.wrong[source]++
		s.mu.Unlock()
		value.Destroy()
		return secret.Value{}, ErrWrongCode
	}
	s.code = nil
	clear(s.wrong)
	ended := s.sess != nil
	s.sess = &session{cookie: cookieHash(value), origin: origin, createdAt: s.d.Now()}
	s.mu.Unlock()

	s.log.InfoContext(ctx, "The outstanding repair code was retired.", "event", "breakglass.code_retired", "reason", "redeemed")
	if ended {
		s.log.InfoContext(ctx, "A repair session ended.", "event", "breakglass.session_ended", "reason", "newer")
	}
	s.log.WarnContext(ctx, "A repair code opened a repair session.", "event", "breakglass.session_opened",
		"origin", origin, "source", source.String())
	s.raise(ctx, "redeemed", s.d.Alerts.RaiseBreakGlassRedeemed)
	return value, nil
}

// Resolve is the live session cookie names at origin, or false: no session,
// another cookie, another origin, or a session past its seven days, which it
// ends.
func (s *Service) Resolve(ctx context.Context, cookie secret.Value, origin string) (Session, bool) {
	if cookie.Len() == 0 {
		return Session{}, false
	}
	h := cookieHash(cookie)
	s.mu.Lock()
	sess := s.sess
	if sess == nil || subtle.ConstantTimeCompare(h[:], sess.cookie[:]) != 1 || sess.origin != origin {
		s.mu.Unlock()
		return Session{}, false
	}
	if !s.d.Now().Before(sess.createdAt.Add(auth.SessionLifetime)) {
		s.sess = nil
		s.mu.Unlock()
		s.log.InfoContext(ctx, "A repair session ended.", "event", "breakglass.session_ended", "reason", "lifetime")
		return Session{}, false
	}
	s.mu.Unlock()
	return Session{cookie: h, origin: sess.origin, createdAt: sess.createdAt}, true
}

// End ends sess when it is still the live session.
func (s *Service) End(ctx context.Context, sess Session) {
	s.mu.Lock()
	live := s.sess != nil && s.sess.cookie == sess.cookie
	if live {
		s.sess = nil
	}
	s.mu.Unlock()
	if live {
		s.log.InfoContext(ctx, "A repair session ended.", "event", "breakglass.session_ended", "reason", "operator")
	}
}

// AdminSignedIn is an administrator's normal sign-in: it ends the session
// and retires the outstanding code, since sign-in works again.
func (s *Service) AdminSignedIn(ctx context.Context) {
	s.mu.Lock()
	retired, ended := s.code != nil, s.sess != nil
	s.code, s.sess = nil, nil
	clear(s.wrong)
	s.mu.Unlock()
	if retired {
		s.log.InfoContext(ctx, "The outstanding repair code was retired.", "event", "breakglass.code_retired", "reason", "admin_signin")
	}
	if ended {
		s.log.InfoContext(ctx, "A repair session ended.", "event", "breakglass.session_ended", "reason", "admin_signin")
	}
}

// RecordJob records a job sess submitted, so the repair page lists it.
func (s *Service) RecordJob(sess Session, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil && s.sess.cookie == sess.cookie {
		s.sess.jobs = append(s.sess.jobs, id)
	}
}

// sessionJobs is the live session's job ids.
func (s *Service) sessionJobs(sess Session) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == nil || s.sess.cookie != sess.cookie {
		return nil
	}
	return append([]string(nil), s.sess.jobs...)
}

// Reset resets the sign-in of the account id names for sess, submitted as
// by, once per session (C1). In order: no reset wired is
// ErrResetUnavailable; a session that has reset one is ErrResetUsed; an
// account that is not a target is accounts.ErrNotRepairTarget; a request
// without the current token is *ResetConfirm, and a confirmed one without a
// password ErrNoPassword, neither claiming anything. Then the session's one
// reset is claimed, and Resets.Submit runs; any error it returns releases
// the claim. The job is recorded on the session, a WARN record written, and
// the critical alert raised; an alert that can't be raised is logged, and
// the job stands.
func (s *Service) Reset(ctx context.Context, sess Session, by authz.Submitter, id, token string, pw secret.Value) (*jobs.Job, error) {
	if s.d.Resets == nil {
		return nil, ErrResetUnavailable
	}
	if s.resetUsed(sess) {
		return nil, ErrResetUsed
	}
	t, want, err := s.d.Resets.Confirm(ctx, id)
	if err != nil {
		return nil, err
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		return nil, &ResetConfirm{Target: Target{ID: t.ID, Name: t.Username}, Token: want}
	}
	if pw.Len() == 0 {
		return nil, ErrNoPassword
	}
	if err := s.claimReset(sess); err != nil {
		return nil, err
	}
	j, err := s.d.Resets.Submit(ctx, by, id, pw)
	if err != nil {
		s.releaseReset(sess)
		return nil, err
	}
	s.RecordJob(sess, j.ID)
	s.log.WarnContext(ctx, "A repair session reset an account's sign-in.", "event", "breakglass.reset_submitted",
		"job_id", j.ID, "account_id", t.ID)
	s.raise(ctx, "reset", func(ctx context.Context, ev string) error { return s.d.Alerts.RaiseBreakGlassReset(ctx, ev, t.ID) })
	return j, nil
}

// live is the session record sess names, or nil. The caller holds mu.
func (s *Service) live(sess Session) *session {
	if s.sess == nil || s.sess.cookie != sess.cookie {
		return nil
	}
	return s.sess
}

// resetUsed reports whether sess has claimed its reset.
func (s *Service) resetUsed(sess Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.live(sess)
	return l != nil && l.reset
}

// claimReset claims sess's one reset: ErrResetUsed when it is claimed,
// ErrSessionEnded when sess is no longer the live session.
func (s *Service) claimReset(sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.live(sess)
	switch {
	case l == nil:
		return ErrSessionEnded
	case l.reset:
		return ErrResetUsed
	}
	l.reset = true
	return nil
}

// releaseReset frees sess's reset after a submit that made no job.
func (s *Service) releaseReset(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.live(sess); l != nil {
		l.reset = false
	}
}

// MoveState is C9's state, for the move's confirmation: how many accounts
// would come back and the current token. ErrMoveUnavailable with no state
// wired.
func (s *Service) MoveState(ctx context.Context) (MoveRepair, error) {
	if s.d.Move == nil {
		return MoveRepair{}, ErrMoveUnavailable
	}
	return s.d.Move.Repair(ctx)
}
