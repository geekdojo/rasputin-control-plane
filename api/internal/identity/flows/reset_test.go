package flows

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// flowAliases are the sub-flow aliases among nodes, at one level.
func flowAliases(nodes []Node) []string {
	var out []string
	for _, n := range nodes {
		if n.IsFlow() {
			out = append(out, n.Alias)
		}
	}
	return out
}

// TC-992-01: the reset flow's shape. Its top level is choose-user, codes,
// no-codes, the second-step flows, the deny flows, then reset-password, each
// REQUIRED or CONDITIONAL; no second step holds a recovery code; each deny
// flow checks not-executed against every second step; Render, Aliases and
// RealmRules name it. The seven sign-in flows' golden files are unchanged
// by the privilegedBranches factoring (F-992-04): TestFlow_VariantsAndStructure
// compares each with its golden file byte for byte.
func TestResetFlow_TC992_01_Shape(t *testing.T) {
	f := ResetFlow()
	golden(t, ResetAlias, f)
	checkLevels(t, ResetAlias, f)
	for _, n := range f {
		if n.Requirement != Required && n.Requirement != Conditional {
			t.Errorf("top level %s%s is %s", n.Provider, n.Alias, n.Requirement)
		}
	}
	if f[0].Provider != ProviderChooseUser || f[len(f)-1].Provider != ProviderResetPassword {
		t.Fatalf("top level starts %q and ends %q", f[0].Provider, f[len(f)-1].Provider)
	}
	parts := []string{"privileged-admin", "privileged-operator", "privileged-app-admin", "privileged-gear-admin"}
	want := []string{ResetAlias + "-codes", ResetAlias + "-no-codes"}
	var steps, denyFlows []string
	for _, p := range parts {
		steps = append(steps, ResetAlias+"-"+p+"-second-step")
		denyFlows = append(denyFlows, ResetAlias+"-"+p+"-deny")
	}
	want = append(append(want, steps...), denyFlows...)
	if got := flowAliases(f); !slices.Equal(got, want) {
		t.Fatalf("sub-flows %v, want %v", got, want)
	}
	codes := f[1]
	if codes.Children[0].Provider != ConditionUserConfigured || codes.Children[1].Provider != ProviderRecoveryCode ||
		codes.Children[1].Requirement != Required {
		t.Errorf("codes is %+v", codes.Children)
	}
	noCodes := f[2]
	if noCodes.Children[0].Config["flow_to_check"] != codes.Alias || noCodes.Children[0].Config["check_result"] != "not-executed" {
		t.Errorf("no-codes checks %v", noCodes.Children[0].Config)
	}
	for i, alias := range steps {
		n, _ := find(f, alias)
		var checked []string
		for _, c := range n.Children {
			if c.Provider == ProviderRecoveryCode {
				t.Errorf("%s offers a recovery code", alias)
			}
			if c.Provider == ConditionSubFlowExecuted {
				checked = append(checked, c.Config["flow_to_check"])
			}
		}
		if !slices.Equal(checked, steps[:i]) && !(i == 0 && len(checked) == 0) {
			t.Errorf("%s checks %v, want the earlier second steps %v", alias, checked, steps[:i])
		}
		var alts []string
		for _, c := range n.Children {
			if c.Requirement == Alternative {
				alts = append(alts, c.Provider)
			}
		}
		if !slices.Equal(alts, []string{ProviderPasskey, ProviderSecurityKey, ProviderOTP}) {
			t.Errorf("%s offers %v", alias, alts)
		}
	}
	for _, alias := range denyFlows {
		n, _ := find(f, alias)
		var checked []string
		for _, c := range n.Children {
			if c.Provider == ConditionSubFlowExecuted {
				checked = append(checked, c.Config["flow_to_check"])
			}
		}
		if !slices.Equal(checked, steps) {
			t.Errorf("%s checks %v, want every second step", alias, checked)
		}
	}
	if _, ok := Render(Inputs{}).Flows[ResetAlias]; !ok {
		t.Error("Render has no reset flow")
	}
	if a := Aliases(); len(a) != len(Variants)+1 || a[len(a)-1] != ResetAlias {
		t.Errorf("Aliases = %v", a)
	}
	r := RealmRules(Inputs{})
	if r["resetCredentialsFlow"] != ResetAlias || r["resetPasswordAllowed"] != true {
		t.Errorf("realm rules reset fields %v %v", r["resetCredentialsFlow"], r["resetPasswordAllowed"])
	}
	// Every config alias is unique across the reset flow and the variants.
	seen := map[string]bool{}
	for _, alias := range Aliases() {
		for _, s := range Flatten(alias, Render(Inputs{}).Flows[alias]) {
			for _, a := range []string{s.ConfigAlias, s.Alias} {
				if a != "" && seen[a] {
					t.Errorf("%s is used twice", a)
				}
				seen[a] = true
			}
		}
	}
}

// TC-992-02: the two deny sentences, byte for byte, and each deny holds its
// own.
func TestResetFlow_TC992_02_Sentences(t *testing.T) {
	const noCodes = "Recovery codes can't be used for this account. Sign in with a passkey, or ask an administrator to reset your password."
	const privileged = "An administrator who has lost their password also needs their passkey, security key or authenticator app. Otherwise ask another administrator, or use the repair code on the control plane."
	if SentenceResetNoCodes != noCodes || SentenceResetPrivileged != privileged {
		t.Fatal("a reset sentence differs from the issue's")
	}
	f := ResetFlow()
	if got := denies(f[2].Children); !slices.Equal(got, []string{noCodes}) {
		t.Errorf("no-codes denies with %q", got)
	}
	for _, n := range f {
		if strings.HasSuffix(n.Alias, "-deny") {
			if got := denies(n.Children); !slices.Equal(got, []string{privileged}) {
				t.Errorf("%s denies with %q", n.Alias, got)
			}
		}
	}
}

// TC-992-24: the theme's password hint names the length(N) the realm's
// policy starts with, which is 15.
func TestPasswordHint_TC992_24_MatchesPolicy(t *testing.T) {
	m := regexp.MustCompile(`^length\((\d+)\)`).FindStringSubmatch(PasswordPolicy)
	if m == nil || m[1] != "15" {
		t.Fatalf("PasswordPolicy starts %q, want length(15)", PasswordPolicy)
	}
	path := filepath.Join("..", "..", "..", "..", "ui", "identity-theme", "src", "login", "messages", "messages_en.properties")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	found := false
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "rasputinPasswordRule=")
		if !ok {
			continue
		}
		found = true
		if !strings.HasPrefix(line, "Use at least "+m[1]+" characters.") {
			t.Errorf("rasputinPasswordRule is %q, want it to name %s characters", line, m[1])
		}
	}
	if err := sc.Err(); err != nil || !found {
		t.Fatalf("no rasputinPasswordRule line (%v)", err)
	}
}
