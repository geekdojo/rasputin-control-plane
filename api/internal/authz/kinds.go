package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The Job kind table (geekdojo/geekdojo-brain#1001; accounts-and-sign-in.md
// Appendix E): who may submit each kind, decided at jobs.Submit before a job
// id, a prepare call, a row or a step exists.

// submitterKind is who a Submitter is. The zero value is nobody.
type submitterKind int

const (
	kindNone submitterKind = iota
	kindSystem
	kindPerson
	kindRepair
	kindBridge
)

// Submitter is who asks for a job: the system, a signed-in person, a
// break-glass repair session or a bridge grant. Its fields are unexported, so
// only its constructors make one. The zero Submitter holds nothing, is not
// the system, and every rule refuses it.
type Submitter struct {
	kind      submitterKind
	caps      Set
	account   string
	createdBy string
}

// SystemSubmitter is the system starting a job, under the subsystem's name.
// Only package jobs calls it, from its system path (specargs_test.go pins
// this). It is not named System because System is the capability.
func SystemSubmitter(name string) Submitter {
	return Submitter{kind: kindSystem, createdBy: name}
}

// Person is a signed-in person. Their capabilities come from For, the one
// capability function, and the job records their account id. An empty Sub is
// the zero Submitter. Only package auth calls it (Principal.Submitter).
func Person(s Subject) Submitter {
	if s.Sub == "" {
		return Submitter{}
	}
	return Submitter{kind: kindPerson, caps: For(s), account: s.Sub, createdBy: s.Sub}
}

// RepairSession is a break-glass repair session (geekdojo/geekdojo-brain#321):
// it holds Repair only. Only package breakglass constructs it
// (breakglass.Session.Submitter; specargs_test.go pins this).
func RepairSession() Submitter {
	return Submitter{kind: kindRepair, caps: Set{}.with(Repair), createdBy: "break-glass"}
}

// BridgeGrant is a live bridge grant for accountID (Identity 5.2): it holds
// Self only, and passes only the bridge rule for its own account. Nothing
// constructs it yet. An empty accountID is the zero Submitter.
func BridgeGrant(accountID string) Submitter {
	if accountID == "" {
		return Submitter{}
	}
	return Submitter{kind: kindBridge, caps: Set{}.with(Self), account: accountID, createdBy: accountID}
}

// CreatedBy is what the job records as its submitter: the subsystem's name,
// the account id, or "break-glass".
func (s Submitter) CreatedBy() string { return s.createdBy }

// IsSystem reports whether s is the system.
func (s Submitter) IsSystem() bool { return s.kind == kindSystem }

// Capabilities is what s holds, for a router deciding a route's floor for a
// submitter that is not a person (a repair session's routes,
// geekdojo/geekdojo-brain#321). The zero Submitter holds nothing.
func (s Submitter) Capabilities() Set { return s.caps }

// KindRefusal is a submission the kind table refuses: a stable code and the
// sentence the person reads.
type KindRefusal struct {
	Code     string
	Sentence string
}

// Error names the code only. The sentence is for the response.
func (r *KindRefusal) Error() string { return "authz: job refused: " + r.Code }

// The refusal codes. The api answers each as "job_" + code.
const (
	CodeUnknownKind    = "unknown_kind"
	CodeSystemOnly     = "system_only"
	CodeNotSubmittable = "not_submittable"
	CodeNotPermitted   = "not_permitted"
	CodeNotYourAccount = "not_your_account"
	CodeOwnAccount     = "own_account"
	CodeNoTarget       = "no_target"
	CodeNoApp          = "no_app"
	CodeUnknownTier    = "unknown_tier"
	// CodeMoveState and CodeStateChanged are a repair session's re-run of
	// identity.move outside C9's state, or on a state that changed since it
	// was confirmed (geekdojo/geekdojo-brain#1004).
	CodeMoveState    = "move_state"
	CodeStateChanged = "state_changed"
)

// sentences is each code's own sentence (ERR-MESSAGE).
var sentences = map[string]string{
	CodeUnknownKind:    "This kind of job isn't recognised.",
	CodeSystemOnly:     "This job runs only when the system starts it.",
	CodeNotSubmittable: "This job is recorded from what the operating system reports, so it can't be submitted.",
	CodeNotPermitted:   "You don't have permission to run this job.",
	CodeNotYourAccount: "You can only do this for your own account.",
	CodeOwnAccount:     "This can't be done to your own account.",
	CodeNoTarget:       "This job doesn't say which account or app it acts on.",
	CodeNoApp:          "That app doesn't exist.",
	CodeUnknownTier:    "This app's privilege tier isn't one this control plane recognises, so the job wasn't started.",
	CodeMoveState:      "Bringing back the accounts from before the update is only possible while sign-in has lost its accounts and this cluster still has them.",
	CodeStateChanged:   "What this would bring back changed since you confirmed it. Review it and confirm again.",
}

func refuseKind(code string) *KindRefusal { return &KindRefusal{Code: code, Sentence: sentences[code]} }

// KindSentence is code's sentence, "" for a code the table does not have: a
// job that re-checks a rule at run time fails with the same words
// (identity.move's repair re-run).
func KindSentence(code string) string { return sentences[code] }

// ErrNoApp is what AppReader.AppFacts returns for an app that does not exist.
var ErrNoApp = errors.New("authz: no such app")

// ErrCheckFailed wraps a read the policy needed and could not make. The job
// is refused (ERR-CLOSED); the caller logs the cause.
var ErrCheckFailed = errors.New("authz: the job could not be checked")

// AppFacts are what the app rule reads about the app a job acts on: whether
// its compose is custom, and every privilege tier the job would run it at.
type AppFacts struct {
	Custom bool
	Tiers  []string
}

// AppReader reads an app's facts for kind, or ErrNoApp.
type AppReader interface {
	AppFacts(ctx context.Context, kind, appID string) (AppFacts, error)
}

// shape is one rule of the kind table.
type shape int

const (
	shapeNone shape = iota
	sysOnly
	control
	self
	selfOrOthers
	others
	appTier
	repairOnly
	repairOr
	move
	bridge
	never
)

// rule is one kind's entry: its shape and, for control and the shapes that
// fall back to control, its capability.
type rule struct {
	shape shape
	cap   Capability
}

// The targets the account and app rules read from a spec.
const (
	accountTarget = "accountId"
	appTarget     = "appId"
)

func ctl(c Capability) rule { return rule{shape: control, cap: c} }

// kindTable is every kind a runner may be asked for. A kind not here is
// refused to everyone, the system included.
var kindTable = func() map[string]rule {
	t := map[string]rule{}
	add := func(r rule, kinds ...string) {
		for _, k := range kinds {
			if _, dup := t[k]; dup {
				panic("authz: kind " + k + " is in the table twice")
			}
			t[k] = r
		}
	}
	// Appendix E: accounts.
	add(rule{shape: others, cap: IAM},
		"accounts.grant_access", "accounts.revoke_access", "accounts.set_roles", "accounts.set_network",
		"accounts.set_claims", "accounts.set_groups", "accounts.set_email", "accounts.confirm_email",
		"accounts.disable", "accounts.enable", "accounts.delete", "accounts.decline", "accounts.unlock",
		"accounts.reset_password", "accounts.remove_second_steps", "accounts.clear_network_password",
		"accounts.grant_waiting")
	add(rule{shape: selfOrOthers, cap: IAM},
		"accounts.sign_out", "accounts.set_display_name", "accounts.revoke_device_certificate", "accounts.remove_mesh_device")
	add(rule{shape: self},
		"accounts.remove_credential", "accounts.rename_credential", "accounts.set_network_password",
		"accounts.enrol_gear_code", "accounts.issue_device_certificate")
	add(ctl(IAM), "accounts.define_group", "accounts.delete_group", "accounts.define_claim", "accounts.delete_claim")
	add(rule{shape: sysOnly}, "accounts.grant_designated_role")
	add(rule{shape: bridge}, "accounts.set_first_password")
	add(rule{shape: repairOnly}, "accounts.repair_reset")
	// Appendix E: identity.
	add(rule{shape: sysOnly},
		"identity.revoke", "identity.arm", "identity.migrate", "identity.reference_check",
		"identity.recover", "identity.recover_admin")
	add(ctl(IAM), "identity.converge")
	add(rule{shape: move}, "identity.move")
	add(rule{shape: repairOr, cap: IAM}, "identity.restart")
	add(rule{shape: repairOnly}, "identity.restore_data")
	add(ctl(IAM), "identity.clients.add", "identity.clients.edit", "identity.clients.remove", "identity.rotate_signing_key")
	add(rule{shape: never}, "os.identity_db_init", "os.identity_rollback", "identity.service_exit")
	add(rule{shape: appTier}, "app.sso_reopen_window", "app.backchannel_logout")
	add(ctl(IAM),
		"radius.enable", "radius.disable", "radius.device_add", "radius.device_edit", "radius.device_remove",
		"radius.set_password_wifi", "radius.set_wifi_names")
	add(rule{shape: sysOnly}, "radius.converge", "radius.disconnect", "firewall.radius_forward")
	// Every kind registered today.
	add(ctl(Nodes), "diag.ping", "node.reboot", "console.root_push")
	add(ctl(BMC), "bmc.power", "bmc.configure")
	add(ctl(Firewall), "firewall.apply", "firewall.reconcile", "firewall.set_active", "firewall.dns_forward")
	add(ctl(Mesh), "mesh.apply", "mesh.reconcile", "mesh.enroll_node")
	add(ctl(Updates), "system.update", "node.update")
	add(ctl(System), "obs.enable", "obs.disable", "backup.run", "backup.target.claim")
	add(rule{shape: appTier},
		"app.deploy", "app.edit", "app.upgrade", "app.revert", "app.stop", "app.delete", "backup.restore_app")
	add(rule{shape: sysOnly},
		"apps.reconcile", "apps.leaf_rotate", "trust.converge", "mesh.leaf_sweep", "storage.reconcile",
		"secretstore.audit_rotate", "secretstore.seal_rotate", "secretstore.recover", "secretstore.migrate",
		"store.reference_check", "updates.security_check",
		"obs.collectors.reconcile", "obs.collectors.deploy_node", "obs.collectors.teardown_node")
	// The OS outcome kinds: recorded from what the OS reports.
	add(rule{shape: never}, "os.seal_key", "os.store_init", "os.store_provision", "os.store_rollback", "os.store_migrate")
	return t
}()

// Known reports whether kind is in the table.
func Known(kind string) bool {
	_, ok := kindTable[kind]
	return ok
}

// SystemOnly reports whether only the system may submit kind: a kind every
// non-system submitter is refused. identity.move is not: a repair session
// may re-run it in C9's state.
func SystemOnly(kind string) bool {
	r, ok := kindTable[kind]
	return ok && r.shape == sysOnly
}

// SystemOrRepair reports whether kind is the system's, and a repair
// session's only in C9's state: identity.move, the one System workflow a
// non-system submitter may start (geekdojo/geekdojo-brain#1004).
func SystemOrRepair(kind string) bool {
	r, ok := kindTable[kind]
	return ok && r.shape == move
}

// MoveState is C9's state as the move rule reads it
// (move.State.RepairToken): the current state token, and whether the state
// holds.
type MoveState interface {
	RepairToken(ctx context.Context) (token string, holds bool, err error)
}

// KindPolicy decides job submissions by kind.
type KindPolicy struct {
	apps AppReader
	move MoveState
}

// KindOption is an optional collaborator of NewKindPolicy.
type KindOption func(*KindPolicy)

// WithMoveState gives the move rule C9's state. Without it every repair
// submission of identity.move is refused.
func WithMoveState(m MoveState) KindOption {
	return func(p *KindPolicy) { p.move = m }
}

// NewKindPolicy returns the policy reading apps through apps. It refuses nil.
func NewKindPolicy(apps AppReader, opts ...KindOption) (*KindPolicy, error) {
	if apps == nil {
		return nil, errors.New("authz: NewKindPolicy: apps is nil")
	}
	p := &KindPolicy{apps: apps}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Authorize decides whether by may submit a job of kind with spec, the bytes
// the job will record. It returns nil, a *KindRefusal, or an error wrapping
// ErrCheckFailed when a read the decision needs fails. It never logs.
func (p *KindPolicy) Authorize(ctx context.Context, kind string, spec []byte, by Submitter) error {
	r, ok := kindTable[kind]
	if !ok {
		return refuseKind(CodeUnknownKind)
	}
	if r.shape == never {
		return refuseKind(CodeNotSubmittable)
	}
	if by.kind == kindNone {
		return refuseKind(CodeNotPermitted)
	}
	switch r.shape {
	case sysOnly:
		return allowIf(by.IsSystem(), CodeSystemOnly)
	case move:
		return p.moveRule(ctx, spec, by)
	case control:
		return allowIf(by.IsSystem() || by.caps.Permits(NeedControl(r.cap)), CodeNotPermitted)
	case repairOnly:
		return allowIf(by.caps.Permits(NeedControl(Repair)), CodeNotPermitted)
	case repairOr:
		return allowIf(by.IsSystem() || by.caps.Permits(NeedControl(Repair)) || by.caps.Permits(NeedControl(r.cap)), CodeNotPermitted)
	case self:
		return p.selfRule(spec, by)
	case selfOrOthers:
		if by.IsSystem() {
			return nil
		}
		target, ok := SpecTarget(spec, accountTarget)
		if !ok {
			return refuseKind(CodeNoTarget)
		}
		if target == by.account {
			return selfOn(target, by)
		}
		return allowIf(by.caps.Permits(NeedControl(r.cap)), CodeNotPermitted)
	case others:
		if by.IsSystem() {
			return nil
		}
		target, ok := SpecTarget(spec, accountTarget)
		if !ok {
			return refuseKind(CodeNoTarget)
		}
		if target == by.account {
			return refuseKind(CodeOwnAccount)
		}
		return allowIf(by.caps.Permits(NeedControl(r.cap)), CodeNotPermitted)
	case bridge:
		if by.kind != kindBridge {
			return refuseKind(CodeNotPermitted)
		}
		target, ok := SpecTarget(spec, accountTarget)
		if !ok {
			return refuseKind(CodeNoTarget)
		}
		return allowIf(target == by.account, CodeNotYourAccount)
	case appTier:
		return p.appRule(ctx, kind, spec, by)
	}
	// A shape this switch does not know is refused (ERR-CLOSED).
	return refuseKind(CodeNotPermitted)
}

// moveTarget is the spec field a repair re-run of identity.move carries:
// the state token the person confirmed.
const moveTarget = "stateToken"

// moveRule is identity.move's shape (geekdojo/geekdojo-brain#1004): the
// system; or a repair session while C9's state holds and the spec's state
// token is the current one. A state that can't be read, or no state wired,
// is an error wrapping ErrCheckFailed (ERR-CLOSED).
func (p *KindPolicy) moveRule(ctx context.Context, spec []byte, by Submitter) error {
	switch {
	case by.IsSystem():
		return nil
	case by.kind != kindRepair:
		return refuseKind(CodeSystemOnly)
	case p.move == nil:
		return fmt.Errorf("%w: identity.move: no move state is wired", ErrCheckFailed)
	}
	want, _ := SpecTarget(spec, moveTarget)
	token, holds, err := p.move.RepairToken(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("%w: read the move state: %w", ErrCheckFailed, err)
	case !holds:
		return refuseKind(CodeMoveState)
	case want == "" || want != token:
		return refuseKind(CodeStateChanged)
	}
	return nil
}

// selfRule is the self shape: Self, on the submitter's own account, and never
// a bridge grant.
func (p *KindPolicy) selfRule(spec []byte, by Submitter) error {
	target, ok := SpecTarget(spec, accountTarget)
	if !ok {
		return refuseKind(CodeNoTarget)
	}
	return selfOn(target, by)
}

// selfOn decides the self shape for target.
func selfOn(target string, by Submitter) error {
	if by.kind == kindBridge || !by.caps.Permits(NeedSelf()) {
		return refuseKind(CodeNotPermitted)
	}
	return allowIf(by.account != "" && target == by.account, CodeNotYourAccount)
}

// appRule is the app shape: the system, or control under the capability the
// app's compose and tiers need.
func (p *KindPolicy) appRule(ctx context.Context, kind string, spec []byte, by Submitter) error {
	if by.IsSystem() {
		return nil
	}
	target, ok := SpecTarget(spec, appTarget)
	if !ok {
		return refuseKind(CodeNoTarget)
	}
	facts, err := p.apps.AppFacts(ctx, kind, target)
	switch {
	case errors.Is(err, ErrNoApp):
		return refuseKind(CodeNoApp)
	case err != nil:
		return fmt.Errorf("%w: read the app for %s: %w", ErrCheckFailed, kind, err)
	}
	need, refusal := appNeed(facts)
	if refusal != nil {
		return refusal
	}
	return allowIf(by.caps.Permits(NeedControl(need)), CodeNotPermitted)
}

// appNeed is the capability an app job needs (E23): apps.host for a custom
// compose, or when any tier the job runs the app at ranks at or above
// host-trusting; apps otherwise. The empty tier is routine, as an install from
// before tiers were recorded carries it. A tier tileschema does not know is
// refused with unknown_tier.
func appNeed(f AppFacts) (Capability, *KindRefusal) {
	host := f.Custom
	for _, t := range f.Tiers {
		eff := tileschema.Privilege{Tier: t}.EffectiveTier()
		if !tileschema.KnownTier(eff) {
			return "", refuseKind(CodeUnknownTier)
		}
		if tileschema.TierRank[eff] >= tileschema.TierRank[tileschema.TierHostTrusting] {
			host = true
		}
	}
	if host {
		return AppsHost, nil
	}
	return Apps, nil
}

func allowIf(ok bool, code string) error {
	if ok {
		return nil
	}
	return refuseKind(code)
}

// SpecTarget reads the target name from spec the way a workflow's tagged
// struct decode reads it. spec must be a JSON object. Every top-level key
// that strings.EqualFold matches name is counted, a superset of
// encoding/json's case-insensitive field match; anything but exactly one such
// key, holding a non-empty JSON string, is no target. So a case-folded or
// exact duplicate, which a decode would resolve to one of the values, is
// refused rather than decided on a value the job may not act on.
func SpecTarget(spec []byte, name string) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(spec))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "", false
	}
	var value string
	found := 0
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return "", false
		}
		key, ok := kt.(string)
		if !ok {
			return "", false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", false
		}
		if !strings.EqualFold(key, name) {
			continue
		}
		found++
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		value = s
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return "", false
	}
	if found != 1 || value == "" {
		return "", false
	}
	return value, true
}
