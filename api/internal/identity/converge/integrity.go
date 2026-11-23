package converge

// The integrity state (geekdojo/geekdojo-brain#987, Identity 4.5): whether
// the realm's sign-in rules match the definition, decided on every reading
// RunJob and Recheck make. While they do not, the control lock refuses
// control capabilities (ControlGate) and the door pauses clients bound to a
// variant stricter than the realm default (ClientPaused).

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// SignInRulesAlertID is the critical alert raised while the sign-in rules
// differ from Rasputin's by something Rasputin did not change.
const SignInRulesAlertID = "identity:signin-rules-differ"

// signInRulesTitle is the alert's sentence.
const signInRulesTitle = "Sign-in rules differ from Rasputin's settings. Administrator tools are locked until they are restored."

// ErrSignInRulesDiffer is ControlGate's answer while control is locked.
var ErrSignInRulesDiffer = errors.New("converge: the sign-in rules differ from Rasputin's")

// Integrity is the integrity state.
type Integrity int

// The states. Unknown holds from the api's start until the first reading.
const (
	Unknown Integrity = iota
	// Applying is an integrity difference while the desired state's hash
	// differs from the stored one: Rasputin's own change (an install, an
	// upgrade, the clock syncing, an app's binding) being applied.
	Applying
	// Drifted is an integrity difference while the hashes match: something
	// other than Rasputin changed the rules.
	Drifted
	// Failed is a run that saw an integrity difference and could not repair
	// it.
	Failed
	// Intact is a reading with no integrity difference.
	Intact
)

func (s Integrity) String() string {
	return [...]string{"unknown", "applying", "drifted", "failed", "intact"}[s]
}

// recheckTypes are the admin event resource types that can change a rule,
// so a pass holding one runs one Recheck.
var recheckTypes = []string{
	"AUTH_FLOW", "AUTH_EXECUTION", "AUTH_EXECUTION_FLOW", "AUTHENTICATOR_CONFIG", "REQUIRED_ACTION",
	"CLIENT", "CLIENT_SCOPE", "CLIENT_ROLE", "REALM", "REALM_ROLE", "USER_PROFILE",
}

// The sinks the drain delivers to.
var (
	_ events.AdminSink = (*Converger)(nil)
	_ events.PassSink  = (*Converger)(nil)
)

// State is the integrity state.
func (c *Converger) State() Integrity {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// decide sets the state from one reading: its integrity fields, and whether
// the stored hash equals the desired one. It logs and raises or clears the
// alert on each transition.
func (c *Converger) decide(ctx context.Context, integrity []string, sameHash bool) {
	c.mu.Lock()
	prev := c.state
	var next Integrity
	switch {
	case len(integrity) == 0:
		next = Intact
	case sameHash:
		next = Drifted
	default:
		next = Applying
	}
	c.state = next
	if next == Intact {
		c.rulesAlert = nil
	}
	if next == Drifted && prev != Drifted {
		c.rulesAlert = c.newRulesAlert()
	}
	c.mu.Unlock()
	attrs := []slog.Attr{slog.Any("fields", integrity)}
	switch {
	case next == Intact && prev != Intact && prev != Unknown:
		c.log.LogAttrs(ctx, slog.LevelInfo, "The sign-in rules match Rasputin's again; administrator tools are unlocked.",
			slog.String("event", "identity.integrity.restored"))
	case next == Applying:
		c.log.LogAttrs(ctx, slog.LevelInfo, "Rasputin is applying its sign-in rules; administrator tools stay locked until they are applied.",
			append([]slog.Attr{slog.String("event", "identity.integrity.applying")}, attrs...)...)
	case next == Drifted && prev != Drifted:
		c.log.LogAttrs(ctx, slog.LevelError, "The sign-in rules differ from Rasputin's; administrator tools are locked until they are restored.",
			append([]slog.Attr{slog.String("event", "identity.integrity.differs")}, attrs...)...)
	}
}

// fail is a run that saw an integrity difference and then failed: the state
// is Failed and the alert is raised. The run's own ERROR is the log.
func (c *Converger) fail() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = Failed
	if c.rulesAlert == nil {
		c.rulesAlert = c.newRulesAlert()
	}
}

// newRulesAlert builds the critical alert; c.mu is held.
func (c *Converger) newRulesAlert() *proto.Alert {
	return &proto.Alert{
		ID: SignInRulesAlertID, Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity,
		Title: signInRulesTitle, Detail: signInRulesTitle, Since: c.d.Now(), RelatedKind: "accounts",
	}
}

// ControlGate is the control lock's gate: ErrSignInRulesDiffer while the
// rules are being applied, have drifted or failed to apply, and while the
// state is still unknown with the identity service ready (ERR-CLOSED,
// F-987-09). Before the service is ready an unknown state locks nothing
// (identity-authz.md §10 row 1: console sessions continue).
func (c *Converger) ControlGate(ctx context.Context) error {
	switch c.State() {
	case Intact:
		return nil
	case Unknown:
		if c.d.Ready(ctx) != nil {
			return nil
		}
	}
	return ErrSignInRulesDiffer
}

// ClientPaused reports whether the door pauses client: the state is not
// intact and the client's desired variant is stricter than the realm
// default (row B90).
func (c *Converger) ClientPaused(client string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == Intact {
		return false
	}
	v, ok := c.bindings[client]
	return ok && v.Stricter()
}

// setBindings records the bindings the last reading wanted.
func (c *Converger) setBindings(app map[string]flows.Variant) {
	c.mu.Lock()
	c.bindings = flows.Bindings(app)
	c.mu.Unlock()
}

// AdminEvent marks the drain's pass when the event's resource type can
// change a rule.
func (c *Converger) AdminEvent(_ context.Context, e events.AdminEvent) {
	if slices.Contains(recheckTypes, e.ResourceType) {
		c.mu.Lock()
		c.recheckDue = true
		c.mu.Unlock()
	}
}

// PassStarted does nothing.
func (c *Converger) PassStarted(context.Context, uint64) {}

// PassEnded runs one Recheck when the pass delivered an admin event that
// can change a rule.
func (c *Converger) PassEnded(ctx context.Context, _ uint64) {
	c.mu.Lock()
	due := c.recheckDue
	c.recheckDue = false
	c.mu.Unlock()
	if due {
		c.Recheck(ctx)
	}
}

// Recheck reads the realm under the realm lock, writes nothing, and sets
// the state by the same rule RunJob does. A difference bumps the generation
// ConvergeCond folds into its rearm key, so identity.converge is due to
// repair it. A read that fails leaves the state as it was, with one WARN per
// outage.
func (c *Converger) Recheck(ctx context.Context) {
	c.d.Lock.Lock()
	defer c.d.Lock.Unlock()
	in, err := c.d.Inputs(ctx)
	var stored string
	var o observed
	if err == nil {
		stored, err = c.d.Settings.Get(ctx, HashKey)
	}
	if err == nil {
		o, err = c.observe(ctx)
	}
	c.mu.Lock()
	warn := err != nil && !c.recheckDown
	c.recheckDown = err != nil
	c.mu.Unlock()
	if err != nil {
		if warn {
			c.log.LogAttrs(ctx, slog.LevelWarn, "The sign-in rules could not be read to check them; their state is unchanged.",
				slog.String("event", "identity.integrity.recheck_failed"), slog.String("err", err.Error()))
		}
		return
	}
	desired := NewDesired(in)
	c.setBindings(in.AppBindings)
	w := diff(desired, o)
	c.decide(ctx, integrityFields(w.fields), stored == desired.Hash())
	if len(w.fields) > 0 || len(w.missingKeys) > 0 {
		c.mu.Lock()
		c.generation++
		c.mu.Unlock()
	}
}

// Generation counts the Rechecks that found a difference.
func (c *Converger) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}
