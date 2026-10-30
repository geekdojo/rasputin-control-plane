package apps

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-604-17 (api half): an unset optional secret, resolved to "", is
// delivered in the deploy command as a present key with an empty value, not
// dropped. The agent half is agent/internal/docker's
// TestOptionalEmptyValueIsDelivered.
func TestDeployCommand_DeliversAnEmptyValue(t *testing.T) {
	env := map[string]secret.Value{
		"RASPUTIN_SECRET_OPT_KEY":  secret.New(nil),
		"RASPUTIN_SECRET_FEED_KEY": secret.New([]byte("v")),
	}
	b, err := deployCommand(&App{ID: "01J9ZK3Q0M8X7Y6W5V4T3S2R3A", Name: "feeds"},
		secret.New([]byte("services: {}\n")), env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"RASPUTIN_SECRET_OPT_KEY":""`) {
		t.Fatalf("the command does not carry the empty value: %s", b)
	}
	var cmd proto.AppDeployCmd
	if err := json.Unmarshal(b, &cmd); err != nil {
		t.Fatal(err)
	}
	if v, ok := cmd.SecretEnv["RASPUTIN_SECRET_OPT_KEY"]; !ok || v != "" {
		t.Fatalf("decoded SecretEnv[OPT_KEY] = %q (present %v), want present and empty", v, ok)
	}
}
