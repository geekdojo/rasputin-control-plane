package docker

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-604-17 (agent half): a deploy command carrying an unset optional secret
// as "" decodes with the key present, the guard accepts a compose that
// references it (it checks presence, not emptiness), and the value renders
// as KEY= for Compose's environment. The api half is api/internal/apps's
// TestDeployCommand_DeliversAnEmptyValue.
func TestOptionalEmptyValueIsDelivered(t *testing.T) {
	const wire = `{"appId":"` + envAppID + `","name":"feeds","composeYaml":"x","secretEnv":{"RASPUTIN_SECRET_OPT_KEY":""}}`
	var cmd proto.AppDeployCmd
	if err := json.Unmarshal([]byte(wire), &cmd); err != nil {
		t.Fatal(err)
	}
	if v, ok := cmd.SecretEnv["RASPUTIN_SECRET_OPT_KEY"]; !ok || v != "" {
		t.Fatalf("decoded SecretEnv = %v, want the key present and empty", cmd.SecretEnv)
	}

	f := newFakeCompose(t)
	f.guard = `{"services":{"web":{"environment":{"OPT":"${RASPUTIN_SECRET_OPT_KEY}"}}}}`
	const compose = "services:\n  web:\n    environment:\n      OPT: ${RASPUTIN_SECRET_OPT_KEY}\n"
	if err := f.c.guardSecretRefs(context.Background(), envAppID, compose, cmd.SecretEnv); err != nil {
		t.Fatalf("the guard refused an empty value: %v", err)
	}
	if got := envEntries(cmd.SecretEnv); !slices.Equal(got, []string{"RASPUTIN_SECRET_OPT_KEY="}) {
		t.Fatalf("envEntries = %q, want [RASPUTIN_SECRET_OPT_KEY=]", got)
	}
}
