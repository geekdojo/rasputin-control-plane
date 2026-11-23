package auth

// The control lock (geekdojo/geekdojo-brain#987, Identity 4.5;
// identity-authz.md §5.1, IA-F11): while the identity service's sign-in
// rules differ from Rasputin's, every control capability is refused and
// view and self continue, until a re-read shows them restored.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// ControlGate answers whether control capabilities may run: nil allows
// them, an error locks them (*converge.Converger's ControlGate).
type ControlGate func(ctx context.Context) error

// controlLockedBody is the refusal's body while the sign-in rules differ:
// its code and its sentence.
const controlLockedBody = `{"code":"signin_rules_differ","error":"Administrator tools are locked because Rasputin's sign-in rules differ from its settings. They unlock when Rasputin restores them; see Alerts."}`

// controlApplyingBody is the refusal's body while Rasputin applies its
// sign-in rules, when no alert is raised (F-987-19).
const controlApplyingBody = `{"code":"signin_rules_applying","error":"Administrator tools are locked while Rasputin applies its sign-in rules. They unlock when it finishes."}`

// applyingLock is a gate error that locks control while Rasputin applies
// its own sign-in rules (converge.ErrSignInRulesApplying).
type applyingLock interface{ ControlApplying() bool }

// selfPrefix is the account's own routes (sign-in, sign-out, its passkeys),
// which the lock never refuses.
const selfPrefix = "/api/auth/"

// viewSockets are the WebSocket routes that only push to the client: the
// live views. Every other WebSocket upgrade is control, so the two-way
// serial console (GET /ws/bmc/{nodeId}/sol) and any socket added later are
// refused while locked until one is listed here as read-only.
var viewSockets = []string{
	"GET /ws/jobs", "GET /ws/inventory", "GET /ws/firewall", "GET /ws/apps", "GET /ws/updates",
	"GET /ws/updates/system", "GET /ws/mesh", "GET /ws/bmc", "GET /ws/alerts",
}

// controlGate is the installed gate and its logger.
type controlGate struct {
	mu   sync.RWMutex
	gate ControlGate
	log  *slog.Logger
}

// SetControlGate installs the control lock's gate and the logger its
// refusals are recorded on. Safe to call before or after Start. Nil
// uninstalls it.
func (s *Service) SetControlGate(g ControlGate, log *slog.Logger) {
	s.control.mu.Lock()
	defer s.control.mu.Unlock()
	s.control.gate, s.control.log = g, log
}

// HasControlGate reports whether a gate is installed.
func (s *Service) HasControlGate() bool {
	s.control.mu.RLock()
	defer s.control.mu.RUnlock()
	return s.control.gate != nil
}

// isControl reports whether r uses a control capability: any unsafe method
// outside the account's own routes, and any WebSocket upgrade that is not a
// listed view.
func isControl(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, selfPrefix) {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return !slices.Contains(viewSockets, r.Pattern)
	}
	return false
}

// controlLocked writes the lock's refusal and reports true when r is
// control and the gate refuses it.
func (s *Service) controlLocked(w http.ResponseWriter, r *http.Request) bool {
	s.control.mu.RLock()
	gate, log := s.control.gate, s.control.log
	s.control.mu.RUnlock()
	if gate == nil || !isControl(r) {
		return false
	}
	err := gate(r.Context())
	if err == nil {
		return false
	}
	body := controlLockedBody
	var a applyingLock
	if errors.As(err, &a) && a.ControlApplying() {
		body = controlApplyingBody
	}
	if log != nil {
		log.LogAttrs(r.Context(), slog.LevelInfo, "A control request was refused: the sign-in rules differ from Rasputin's.",
			slog.String("event", "auth.control_locked"), slog.String("method", r.Method), slog.String("route", r.Pattern))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusLocked)
	_, _ = w.Write([]byte(body))
	return true
}
