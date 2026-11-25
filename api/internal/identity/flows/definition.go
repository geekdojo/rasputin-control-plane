package flows

import "github.com/geekdojo/rasputin-control-plane/api/internal/authz"

// Requirement is an execution's requirement, as Keycloak names it.
type Requirement string

// The requirements the definition uses.
const (
	Required    Requirement = "REQUIRED"
	Alternative Requirement = "ALTERNATIVE"
	Conditional Requirement = "CONDITIONAL"
	Disabled    Requirement = "DISABLED"
)

// The stock authenticators and conditions the flows are built from
// (Keycloak 26.8.2's provider ids; capability row K-FLOW).
const (
	ProviderCookie            = "auth-cookie"
	ProviderPasswordForm      = "auth-username-password-form"
	ProviderPasskey           = "webauthn-authenticator-passwordless"
	ProviderSecurityKey       = "webauthn-authenticator"
	ProviderOTP               = "auth-otp-form"
	ProviderRecoveryCode      = "auth-recovery-authn-code-form"
	ProviderDeny              = "deny-access-authenticator"
	ConditionUserAttribute    = "conditional-user-attribute"
	ConditionUserRole         = "conditional-user-role"
	ConditionCredential       = "conditional-credential"
	ConditionSubFlowExecuted  = "conditional-sub-flow-executed"
	ConditionUserConfigured   = "conditional-user-configured"
	credentialPasswordless    = "webauthn-passwordless"
	consoleClient             = "rasputin-console"
	subFlowType               = "basic-flow"
	attrAppRole               = "rasputin_app_role"
	attrNetwork               = "rasputin_network"
	denyMessageKey            = "denyErrorMessage"
	appAccessPattern          = "^(user|admin)$"
	appAdminPattern           = "^admin$"
	networkAccessPattern      = "^(gear-read|gear-admin)$"
	networkAdminPattern       = "^gear-admin$"
	consoleRoleAdmin          = string(authz.Admin)
	consoleRoleOperator       = string(authz.Operator)
	subFlowNotExecutedSetting = "not-executed"
)

// The five markers the api keeps on an account (admin-only attributes; the
// markers package writes them): whether it holds a passkey or security key
// made at each door, whether it holds a second step usable at each door, and
// whether it holds one at either door.
const (
	MarkerWebAuthnHome   = "rasputin_webauthn_home"
	MarkerWebAuthnApp    = "rasputin_webauthn_app"
	MarkerSecondStepHome = "rasputin_second_step_home"
	MarkerSecondStepApp  = "rasputin_second_step_app"
	MarkerSecondStepAny  = "rasputin_second_step_any"
)

// Markers are the five, in a fixed order.
var Markers = []string{MarkerWebAuthnHome, MarkerWebAuthnApp, MarkerSecondStepHome, MarkerSecondStepApp, MarkerSecondStepAny}

// WebAuthnMarker is door's webauthn marker.
func WebAuthnMarker(d Door) string {
	if d == DoorHome {
		return MarkerWebAuthnHome
	}
	return MarkerWebAuthnApp
}

// SecondStepMarker is door's second-step marker.
func SecondStepMarker(d Door) string {
	if d == DoorHome {
		return MarkerSecondStepHome
	}
	return MarkerSecondStepApp
}

// The sentences each Deny access step shows (ERR-MESSAGE; row B117). Each is
// the English sentence itself, never a theme key: another theme would print
// a bare key.
const (
	SentenceNoAppAccess     = "Your account doesn't have access to apps yet. Ask an administrator."
	SentencePrivileged      = "This account signs in with two steps, and none of its second steps works here. Ask another administrator to reset your sign-in."
	SentenceAdministering   = "Signing in to this app needs a second step. Add a passkey, security key or authenticator app in Your account, then try again."
	SentenceAdminsFirst     = "This app is waiting for an administrator to sign in to it first. Try again later."
	SentenceNoNetworkAccess = "Your account doesn't have access to network devices. Ask an administrator."
	// SentenceResetNoCodes is the reset flow's answer to an account with no
	// recovery codes, and to a name no account has, alike (Identity 4.10).
	SentenceResetNoCodes = "Recovery codes can't be used for this account. Sign in with a passkey, or ask an administrator to reset your password."
	// SentenceResetPrivileged is the reset flow's answer to a privileged
	// account that gave no second step besides its recovery code.
	SentenceResetPrivileged = "An administrator who has lost their password also needs their passkey, security key or authenticator app. Otherwise ask another administrator, or use the repair code on the control plane."
)

// Node is one execution: an authenticator or condition (Provider set), or a
// sub-flow (Alias set) with its children.
type Node struct {
	Provider    string            `json:"provider,omitempty"`
	Alias       string            `json:"alias,omitempty"`
	Requirement Requirement       `json:"requirement"`
	ConfigAlias string            `json:"configAlias,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	Children    []Node            `json:"children,omitempty"`
}

// IsFlow reports whether n is a sub-flow.
func (n Node) IsFlow() bool { return n.Alias != "" }

// Flow is variant v's top-level flow: the executions under its alias.
//
// The level rule (Keycloak 26.8.2, DefaultAuthenticationFlow's
// fillListsOfExecutions): a level that holds a REQUIRED or CONDITIONAL
// execution drops every ALTERNATIVE one beside it, conditions not counted.
// So each level here is either REQUIRED and CONDITIONAL executions only, or
// ALTERNATIVE ones only, each with its conditions.
func Flow(v Variant) []Node {
	b := builder{alias: v.Alias()}
	top := []Node{{Alias: b.name("authenticate"), Requirement: Required, Children: b.authenticate(v)}}
	if gate, ok := b.gate(v); ok {
		top = append(top, gate)
	}
	return top
}

// builder names a variant's sub-flows and configs, each prefixed with its
// top-level alias so they are unique in the realm.
type builder struct{ alias string }

func (b builder) name(part string) string { return b.alias + "-" + part }

func (b builder) cond(provider, part string, config map[string]string) Node {
	n := Node{Provider: provider, Requirement: Required}
	if config != nil {
		n.ConfigAlias, n.Config = b.name(part), config
	}
	return n
}

func (b builder) attribute(part, name, value string, not, regex bool) Node {
	return b.cond(ConditionUserAttribute, part, map[string]string{
		"attribute_name": name, "attribute_expected_value": value,
		"not": boolString(not), "regex": boolString(regex), "include_group_attributes": "false",
	})
}

func (b builder) noPasskeyUsed(part string) Node {
	return b.cond(ConditionCredential, part, map[string]string{"credentials": credentialPasswordless, "included": "false"})
}

func (b builder) notExecuted(part, flow string) Node {
	return b.cond(ConditionSubFlowExecuted, part, map[string]string{"flow_to_check": flow, "check_result": subFlowNotExecutedSetting})
}

func (b builder) deny(part, sentence string) Node {
	n := Node{Provider: ProviderDeny, Requirement: Required}
	n.ConfigAlias, n.Config = b.name(part), map[string]string{denyMessageKey: sentence}
	return n
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// authenticate holds the cookie and the sign-in sub-flow as alternatives,
// except at Administering, where every sign-in is fresh.
func (b builder) authenticate(v Variant) []Node {
	signIn := Node{Alias: b.name("sign-in"), Requirement: Alternative, Children: b.signIn(v)}
	if v == Administering {
		signIn.Requirement = Required
		return []Node{signIn}
	}
	return []Node{{Provider: ProviderCookie, Requirement: Alternative}, signIn}
}

// secondStepMarker is the marker that says the account holds a second step
// this variant's sign-in can ask for.
func secondStepMarker(v Variant) string {
	if v == Administering {
		return MarkerSecondStepAny
	}
	return SecondStepMarker(v.Door())
}

// signIn is the password form, then the two second-step sub-flows (at most
// one of which runs), then the privileged deny branches.
func (b builder) signIn(v Variant) []Node {
	door := v.Door()
	webauthnFlow, codesFlow := b.name("second-step-webauthn"), b.name("second-step-codes")
	nodes := []Node{
		{Provider: ProviderPasswordForm, Requirement: Required},
		{Alias: webauthnFlow, Requirement: Conditional, Children: []Node{
			b.noPasskeyUsed("second-step-webauthn-no-passkey"),
			b.attribute("second-step-webauthn-marker", secondStepMarker(v), "true", false, false),
			b.attribute("second-step-webauthn-door", WebAuthnMarker(door), "true", false, false),
			{Provider: ProviderPasskey, Requirement: Alternative},
			{Provider: ProviderSecurityKey, Requirement: Alternative},
			{Provider: ProviderOTP, Requirement: Alternative},
			{Provider: ProviderRecoveryCode, Requirement: Alternative},
		}},
		{Alias: codesFlow, Requirement: Conditional, Children: []Node{
			b.noPasskeyUsed("second-step-codes-no-passkey"),
			b.attribute("second-step-codes-marker", secondStepMarker(v), "true", false, false),
			b.attribute("second-step-codes-door", WebAuthnMarker(door), "true", true, false),
			{Provider: ConditionUserConfigured, Requirement: Required},
			{Provider: ProviderOTP, Requirement: Alternative},
			{Provider: ProviderRecoveryCode, Requirement: Alternative},
		}},
	}
	for _, br := range branches(v) {
		children := []Node{}
		if br.condition != nil {
			children = append(children, br.condition(b))
		}
		children = append(children,
			b.noPasskeyUsed(br.part+"-no-passkey"),
			b.notExecuted(br.part+"-no-webauthn-step", webauthnFlow),
			b.notExecuted(br.part+"-no-codes-step", codesFlow),
			b.deny(br.part+"-deny", br.sentence),
		)
		nodes = append(nodes, Node{Alias: b.name(br.part), Requirement: Conditional, Children: children})
	}
	return nodes
}

// branch is one privileged deny branch: its name, its account condition
// (nil for every account) and its sentence.
type branch struct {
	part      string
	condition func(builder) Node
	sentence  string
}

// branches are v's privileged deny branches (C3): console admin and
// operator, the app administrator at the app door, and gear-admin; or, at
// Administering, one branch over every account (C22).
func branches(v Variant) []branch {
	if v == Administering {
		return []branch{{part: "every-account", sentence: SentenceAdministering}}
	}
	return privilegedBranches(v.Door() == DoorApp)
}

// privilegedBranches are the privileged accounts' conditions (C3), each with
// SentencePrivileged: console admin and operator, the app administrator when
// appAdmin, and gear-admin. The sign-in flows and the reset flow
// (ResetFlow) both build from them.
func privilegedBranches(appAdmin bool) []branch {
	role := func(name string) func(builder) Node {
		return func(b builder) Node {
			return b.cond(ConditionUserRole, "privileged-"+name+"-role", map[string]string{
				"condUserRole": consoleClient + "." + name, "negate": "false",
			})
		}
	}
	out := []branch{
		{part: "privileged-admin", condition: role(consoleRoleAdmin), sentence: SentencePrivileged},
		{part: "privileged-operator", condition: role(consoleRoleOperator), sentence: SentencePrivileged},
	}
	if appAdmin {
		out = append(out, branch{part: "privileged-app-admin", sentence: SentencePrivileged, condition: func(b builder) Node {
			return b.attribute("privileged-app-admin-role", attrAppRole, appAdminPattern, false, true)
		}})
	}
	return append(out, branch{part: "privileged-gear-admin", sentence: SentencePrivileged, condition: func(b builder) Node {
		return b.attribute("privileged-gear-admin-grant", attrNetwork, networkAdminPattern, false, true)
	}})
}

// gate is the access gate (Identity 7.4) on the gated variants: it denies
// an account whose attribute does not match the variant's pattern.
func (b builder) gate(v Variant) (Node, bool) {
	var attr, pattern, sentence string
	switch v {
	case HomeMesh, AppClients, Administering:
		attr, pattern, sentence = attrAppRole, appAccessPattern, SentenceNoAppAccess
	case AdminsFirst:
		attr, pattern, sentence = attrAppRole, appAdminPattern, SentenceAdminsFirst
	case NetworkDevices:
		attr, pattern, sentence = attrNetwork, networkAccessPattern, SentenceNoNetworkAccess
	default:
		return Node{}, false
	}
	return Node{Alias: b.name("access-gate"), Requirement: Conditional, Children: []Node{
		b.attribute("access-gate-attribute", attr, pattern, true, true),
		b.deny("access-gate-deny", sentence),
	}}, true
}

// Step is one execution of a flattened flow, as Keycloak lists a flow's
// executions: its parent's alias, its depth and its index among its
// siblings.
type Step struct {
	Parent      string            `json:"parent"`
	Level       int               `json:"level"`
	Index       int               `json:"index"`
	Provider    string            `json:"provider,omitempty"`
	Alias       string            `json:"alias,omitempty"`
	Requirement Requirement       `json:"requirement"`
	ConfigAlias string            `json:"configAlias,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
}

// Flatten lists nodes depth first under parent, the order Keycloak's
// executions listing uses.
func Flatten(parent string, nodes []Node) []Step {
	var out []Step
	var walk func(parent string, level int, nodes []Node)
	walk = func(parent string, level int, nodes []Node) {
		for i, n := range nodes {
			out = append(out, Step{Parent: parent, Level: level, Index: i, Provider: n.Provider, Alias: n.Alias,
				Requirement: n.Requirement, ConfigAlias: n.ConfigAlias, Config: n.Config})
			if n.IsFlow() {
				walk(n.Alias, level+1, n.Children)
			}
		}
	}
	walk(parent, 0, nodes)
	return out
}
