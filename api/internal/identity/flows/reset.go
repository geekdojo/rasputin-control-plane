package flows

// The password reset (geekdojo/geekdojo-brain#992, Identity 4.10;
// identity-authz.md §5.4): the realm's reset-credentials flow, which both
// reset clients run through the login-actions/reset-credentials entry. It
// sends no email: a person gives one recovery code, and a privileged account
// also gives a second step that is not on its code sheet, before choosing a
// new password.

// ResetAlias is the reset flow's alias, as the baseline froze it.
const ResetAlias = "rasputin-reset"

// The reset flow's own stock authenticators (Keycloak 26.8.2's provider
// ids; capability row K-FLOW).
const (
	ProviderChooseUser    = "reset-credentials-choose-user"
	ProviderResetPassword = "reset-password"
)

// ResetFlow is the reset flow's top level: choose the account, one recovery
// code or the codeless sentence, a privileged account's second step or the
// privileged sentence, then the new password. It holds only REQUIRED and
// CONDITIONAL executions, so the level rule (Flow) drops nothing.
//
// A reset at either door changes the password both doors use, so the app
// administrator counts as privileged at both (privilegedBranches(true)).
// A name no account has meets the codeless sentence too: Choose User clears
// the user, and a recovery code is configured for nobody.
func ResetFlow() []Node {
	b := builder{alias: ResetAlias}
	codes := b.name("codes")
	top := []Node{
		{Provider: ProviderChooseUser, Requirement: Required},
		{Alias: codes, Requirement: Conditional, Children: []Node{
			{Provider: ConditionUserConfigured, Requirement: Required},
			{Provider: ProviderRecoveryCode, Requirement: Required},
		}},
		{Alias: b.name("no-codes"), Requirement: Conditional, Children: []Node{
			b.notExecuted("no-codes-not-executed", codes),
			b.deny("no-codes-deny", SentenceResetNoCodes),
		}},
	}
	// Each branch's condition appears twice, so each use names its config
	// under a builder of its own.
	steps := builder{alias: ResetAlias + "-second-step"}
	denies := builder{alias: ResetAlias + "-deny"}
	brs := privilegedBranches(true)
	stepFlows := make([]string, 0, len(brs))
	for _, br := range brs {
		alias := b.name(br.part + "-second-step")
		children := []Node{br.condition(steps)}
		for _, earlier := range stepFlows {
			children = append(children, steps.notExecuted(br.part+"-after-"+earlier, earlier))
		}
		children = append(children,
			Node{Provider: ConditionUserConfigured, Requirement: Required},
			Node{Provider: ProviderPasskey, Requirement: Alternative},
			Node{Provider: ProviderSecurityKey, Requirement: Alternative},
			Node{Provider: ProviderOTP, Requirement: Alternative},
		)
		top = append(top, Node{Alias: alias, Requirement: Conditional, Children: children})
		stepFlows = append(stepFlows, alias)
	}
	for _, br := range brs {
		children := []Node{br.condition(denies)}
		for _, step := range stepFlows {
			children = append(children, denies.notExecuted(br.part+"-not-"+step, step))
		}
		children = append(children, denies.deny(br.part, SentenceResetPrivileged))
		top = append(top, Node{Alias: b.name(br.part + "-deny"), Requirement: Conditional, Children: children})
	}
	return append(top, Node{Provider: ProviderResetPassword, Requirement: Required})
}

// Aliases are every flow the rules own: the seven sign-in variants', in
// order, then the reset flow's.
func Aliases() []string {
	out := make([]string, 0, len(Variants)+1)
	for _, v := range Variants {
		out = append(out, v.Alias())
	}
	return append(out, ResetAlias)
}
