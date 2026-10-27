package proto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// newCanary is a fresh random value per run, so a test that finds it
// anywhere found this run's value and nothing else.
func newCanary(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "S776-" + hex.EncodeToString(b)
}

// TC-776-01: SecretEnvName is the prefix and the name upper-cased with '-'
// as '_', and no two distinct valid names map to the same key.
func TestSecretEnvName(t *testing.T) {
	long := strings.Repeat("a", 62) + "b"
	for name, want := range map[string]string{
		"db-password": "RASPUTIN_SECRET_DB_PASSWORD",
		"a":           "RASPUTIN_SECRET_A",
		"x1-y2-z3":    "RASPUTIN_SECRET_X1_Y2_Z3",
		long:          "RASPUTIN_SECRET_" + strings.ToUpper(long),
	} {
		if got := SecretEnvName(name); got != want {
			t.Errorf("SecretEnvName(%q) = %q, want %q", name, got, want)
		}
		if !ValidSecretEnvKey(SecretEnvName(name)) {
			t.Errorf("SecretEnvName(%q) = %q is not a valid key", name, SecretEnvName(name))
		}
	}
	// Injectivity over a generated set of valid DNS labels: every name of up
	// to three characters over [a-z0-9-] with no leading or trailing hyphen.
	alphabet := "abz09-"
	seen := map[string]string{}
	var gen func(prefix string, n int)
	gen = func(prefix string, n int) {
		if prefix != "" && prefix[0] != '-' && prefix[len(prefix)-1] != '-' {
			key := SecretEnvName(prefix)
			if other, ok := seen[key]; ok {
				t.Fatalf("%q and %q both map to %q", other, prefix, key)
			}
			seen[key] = prefix
		}
		if n == 0 {
			return
		}
		for _, c := range alphabet {
			gen(prefix+string(c), n-1)
		}
	}
	gen("", 3)
	if len(seen) < 100 {
		t.Fatalf("generated only %d names", len(seen))
	}
}

// TC-776-02: only a key SecretEnvName can produce is valid.
func TestValidSecretEnvKey(t *testing.T) {
	overBound := SecretEnvPrefix + strings.Repeat("A", maxSecretEnvKeyLen-len(SecretEnvPrefix)+1)
	atBound := overBound[:len(overBound)-1]
	if !ValidSecretEnvKey(atBound) {
		t.Errorf("a key at the bound (%d bytes) was refused", len(atBound))
	}
	for k, want := range map[string]bool{
		"RASPUTIN_SECRET_DB_PASSWORD": true,
		"PATH":                        false,
		"DOCKER_HOST":                 false,
		"LD_PRELOAD":                  false,
		"rasputin_secret_x":           false,
		"RASPUTIN_SECRET_":            false,
		"RASPUTIN_SECRET_A-B":         false,
		overBound:                     false,
	} {
		if got := ValidSecretEnvKey(k); got != want {
			t.Errorf("ValidSecretEnvKey(%q) = %v, want %v", k, got, want)
		}
	}
}

// TC-776-03: the map renders redacted — bare and inside an AppDeployCmd,
// through every fmt verb and slog's text and JSON handlers.
func TestAppSecretEnvRendersRedacted(t *testing.T) {
	canary := newCanary(t)
	env := AppSecretEnv{"RASPUTIN_SECRET_DB_PASSWORD": canary}
	cmd := AppDeployCmd{AppID: "a", Name: "n", ComposeYAML: "c", SecretEnv: env}
	for _, x := range []any{env, cmd, &cmd} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			out := fmt.Sprintf(verb, x)
			if strings.Contains(out, canary) {
				t.Errorf("%s of %T renders the value: %s", verb, x, out)
			}
			if !strings.Contains(out, "[redacted]") {
				t.Errorf("%s of %T does not show [redacted]: %s", verb, x, out)
			}
		}
		if s, ok := x.(fmt.Stringer); ok && s.String() != "[redacted]" {
			t.Errorf("String() = %q", s.String())
		}
		for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
			"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		} {
			var b bytes.Buffer
			slog.New(h(&b)).Info("deploy", "x", x)
			if strings.Contains(b.String(), canary) {
				t.Errorf("slog %s handler logs the value of %T: %s", name, x, b.String())
			}
			if !strings.Contains(b.String(), "[redacted]") {
				t.Errorf("slog %s handler does not show [redacted] for %T: %s", name, x, b.String())
			}
		}
	}
}

// TC-776-04: the wire carries the value; a command without secrets has no
// secretEnv key and is byte-identical to the encoding before the field.
func TestAppDeployCmdWire(t *testing.T) {
	canary := newCanary(t)
	b, err := json.Marshal(AppDeployCmd{AppID: "a", SecretEnv: AppSecretEnv{"RASPUTIN_SECRET_X": canary}})
	if err != nil {
		t.Fatal(err)
	}
	var back AppDeployCmd
	if err := json.Unmarshal(b, &back); err != nil || back.SecretEnv["RASPUTIN_SECRET_X"] != canary {
		t.Fatalf("the wire does not carry the value: %s (%v)", b, err)
	}

	b, err = json.Marshal(AppDeployCmd{AppID: "01APP", Name: "kuma", ComposeYAML: "services: {}\n", WorkBudgetSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	const golden = `{"appId":"01APP","name":"kuma","composeYaml":"services: {}\n","workBudgetSeconds":300}`
	if string(b) != golden {
		t.Fatalf("a command without secrets encodes as\n%s\nwant the previous encoding\n%s", b, golden)
	}
}

// TC-776-05: Validate names the bad key and never the value; a map of valid
// keys is accepted.
func TestAppSecretEnvValidate(t *testing.T) {
	canary := newCanary(t)
	err := AppSecretEnv{"RASPUTIN_SECRET_OK": "fine", "LD_PRELOAD": canary}.Validate()
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") || strings.Contains(err.Error(), canary) {
		t.Fatalf("Validate = %v, want one naming LD_PRELOAD without the value", err)
	}
	if err := (AppSecretEnv{"RASPUTIN_SECRET_A": canary, "RASPUTIN_SECRET_B_C": "x"}).Validate(); err != nil {
		t.Fatalf("valid keys refused: %v", err)
	}
	if err := AppSecretEnv(nil).Validate(); err != nil {
		t.Fatalf("a nil map refused: %v", err)
	}
}

// TC-776-06 (proto half): the verb has a floor, in bare CalVer, and its
// subject round-trips. The comparison against v2026.10.3 needs the api's
// releases package and is in api/internal/inventory.
func TestAppDeploySecretsVerbFloorAndSubject(t *testing.T) {
	floor, ok := VerbMinAgentVersion(AppDeploySecretsVerb)
	if !ok || floor == "" || strings.HasPrefix(floor, "v") {
		t.Fatalf("floor = %q, %v; want a bare CalVer entry", floor, ok)
	}
	node, verb, ok := CmdSubjectVerb(AppDeploySecretsSubject("n1"))
	if !ok || node != "n1" || verb != "docker.deploy_secrets" {
		t.Fatalf("CmdSubjectVerb = (%q, %q, %v)", node, verb, ok)
	}
}
