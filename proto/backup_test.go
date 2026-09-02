package proto

import (
	"strings"
	"testing"
	"time"
)

// TestBackupValidStagingNameRefusesAnythingButAPlainName.
//
// The write verb joins this name onto the agent's staging root. Refusing by
// SHAPE rather than sanitising is the whole guard: it means the verb can never
// be talked into reading a file somewhere else on the node, however the name
// was constructed.
func TestBackupValidStagingNameRefusesAnythingButAPlainName(t *testing.T) {
	valid := []string{
		"20260902T031500Z-01J8ZQ4K-identity-only.sealed",
		"a",
		"gen_1.tar",
		strings.Repeat("a", 128),
	}
	for _, s := range valid {
		if !BackupValidStagingName(s) {
			t.Errorf("BackupValidStagingName(%q) = false, want true", s)
		}
	}

	invalid := map[string]string{
		"empty":                 "",
		"a parent traversal":    "..",
		"a relative traversal":  "../../etc/shadow",
		"a current dir":         ".",
		"an absolute path":      "/etc/shadow",
		"a nested path":         "sub/dir/file",
		"a windows path":        `sub\dir`,
		"a dotfile":             ".ssh",
		"a hidden traversal":    ".../x",
		"a space":               "gen 1.sealed",
		"a shell metacharacter": "gen;rm -rf /",
		"a null byte":           "gen\x00.sealed",
		"a newline":             "gen\n.sealed",
		"too long":              strings.Repeat("a", 129),
	}
	for name, s := range invalid {
		if BackupValidStagingName(s) {
			t.Errorf("BackupValidStagingName(%q) = true (%s), want false", s, name)
		}
	}
}

// TestBackupGenerationIDCarriesTheScope is the property an operator relies on
// with no Rasputin installed and no manifest parsed: `ls generations/` says what
// each archive is.
func TestBackupGenerationIDCarriesTheScope(t *testing.T) {
	at := time.Date(2026, 9, 2, 3, 15, 0, 0, time.UTC)
	id := BackupGenerationID(at, "01J8ZQ4KABCDEFGH", BackupScopeIdentityOnly)

	if !strings.Contains(id, BackupScopeIdentityOnly) {
		t.Errorf("generation id %q does not carry its scope", id)
	}
	if !strings.HasPrefix(id, "20260902T031500Z") {
		t.Errorf("generation id %q does not start with a sortable UTC timestamp", id)
	}
	if !BackupValidGenerationID(id) {
		t.Errorf("generation id %q is not a usable file name", id)
	}
	// It has to survive being suffixed for a staging name, which is what the
	// api does with it.
	for _, kind := range []string{"db", "tar", "sealed"} {
		if !BackupValidStagingName(id + "." + kind) {
			t.Errorf("%s is not a usable staging name", id+"."+kind)
		}
	}

	// An empty scope defaults rather than producing a nameless archive: a
	// generation whose name makes no claim is worse than one that says
	// identity-only.
	if got := BackupGenerationID(at, "job", ""); !strings.Contains(got, BackupScopeIdentityOnly) {
		t.Errorf("an empty scope produced %q", got)
	}

	// A job id with characters a file name cannot take is mapped, not passed
	// through.
	if got := BackupGenerationID(at, "a/b:c d", BackupScopeIdentityOnly); !BackupValidGenerationID(got) {
		t.Errorf("a hostile job id produced an unusable generation id: %q", got)
	}
	// And no job id at all still yields a usable name.
	if got := BackupGenerationID(at, "", BackupScopeIdentityOnly); !BackupValidGenerationID(got) {
		t.Errorf("an empty job id produced %q", got)
	}

	// Two runs in the same second are distinguishable — the discriminator is
	// the ULID's random tail.
	a := BackupGenerationID(at, "01J8ZQ4KAAAAAAAA", BackupScopeIdentityOnly)
	b := BackupGenerationID(at, "01J8ZQ4KBBBBBBBB", BackupScopeIdentityOnly)
	if a == b {
		t.Error("two runs in the same second minted the same generation id")
	}
}

// TestBackupBudgetsAreInTheReplyGrant is the busreply.go contract, applied to
// the verbs added for #290: EVERY agent-side budget belongs in
// AgentWorkBudgetMax. One left out is a handler that finishes with a real
// answer and is denied the publish that carries it.
func TestBackupBudgetsAreInTheReplyGrant(t *testing.T) {
	for name, budget := range map[string]time.Duration{
		"BackupPreflightWork": BackupPreflightWork,
		"BackupWriteWork":     BackupWriteWork,
		"BackupPruneWork":     BackupPruneWork,
	} {
		if budget > AgentWorkBudgetMax {
			t.Errorf("%s (%s) exceeds AgentWorkBudgetMax (%s): the reply grant would expire before the handler answers",
				name, budget, AgentWorkBudgetMax)
		}
		if BusReplyGrantTTL <= budget {
			t.Errorf("%s (%s) is not strictly outlived by the reply grant (%s)", name, budget, BusReplyGrantTTL)
		}
	}
}

// TestBackupSubjectsAreUnderTheNodeCommandFilter: an agent subscribes with
// NodeCmdFilter, so a verb outside that prefix would be a subject nothing
// listens on and no bus credential permits.
func TestBackupSubjectsAreUnderTheNodeCommandFilter(t *testing.T) {
	const node = "n-1"
	prefix := strings.TrimSuffix(NodeCmdFilter(node), ">")
	for name, subj := range map[string]string{
		"preflight": BackupPreflightSubject(node),
		"write":     BackupWriteSubject(node),
		"prune":     BackupPruneSubject(node),
	} {
		if !strings.HasPrefix(subj, prefix) {
			t.Errorf("%s subject %q is not under %q", name, subj, prefix)
		}
	}
	// And they are distinct from each other and from the §4.8 verbs.
	seen := map[string]bool{}
	for _, s := range []string{
		BackupPreflightSubject(node), BackupWriteSubject(node), BackupPruneSubject(node),
		StorageEnumerateSubject(node), StorageClaimSubject(node),
		StorageMountSubject(node), StorageInspectSubject(node),
	} {
		if seen[s] {
			t.Errorf("subject collision on %q", s)
		}
		seen[s] = true
	}
}

// TestBackupRetentionMatchesTheDesign pins §4.4's four generations to a
// constant rather than to a literal somebody can quietly change in one of the
// three places that read it.
func TestBackupRetentionMatchesTheDesign(t *testing.T) {
	if BackupRetainGenerations != 4 {
		t.Errorf("BackupRetainGenerations = %d; design/storage.md §4.4 says four full generations, oldest pruned first", BackupRetainGenerations)
	}
	if BackupScopeIdentityOnly == BackupScopeFull {
		t.Fatal("the two scopes are the same string")
	}
	if !BackupValidStagingName("x-" + BackupScopeIdentityOnly) {
		t.Errorf("the scope %q cannot appear in a file name, so it cannot appear in a generation id", BackupScopeIdentityOnly)
	}
}
