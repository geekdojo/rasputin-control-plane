package apps

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// TC-692-01 and TC-692-02: each deploy-family constructor refuses a nil secret
// source with an error naming its kind and a zero Workflow, and builds its
// workflow, push step included, when given one.
func TestDeployFamilyConstructorsRequireASecretSource(t *testing.T) {
	for _, tc := range []struct {
		kind  string
		build func(SecretSource) (jobs.Workflow, error)
	}{
		{"app.deploy", func(s SecretSource) (jobs.Workflow, error) { return DeployWorkflow(nil, nil, nil, nil, s) }},
		{"app.revert", func(s SecretSource) (jobs.Workflow, error) { return RevertWorkflow(nil, nil, nil, nil, s) }},
		{"app.edit", func(s SecretSource) (jobs.Workflow, error) {
			return EditWorkflow(nil, nil, nil, nil, NewComposeStash(), s)
		}},
		{"app.upgrade", func(s SecretSource) (jobs.Workflow, error) { return UpgradeWorkflow(nil, nil, nil, nil, nil, s) }},
	} {
		t.Run(tc.kind+"/nil source", func(t *testing.T) {
			w, err := tc.build(nil)
			if err == nil {
				t.Fatal("the constructor accepted a nil secret source")
			}
			if !strings.Contains(err.Error(), tc.kind) || !strings.Contains(err.Error(), "a secret source is required") {
				t.Fatalf("error %q does not name the kind and the missing source", err)
			}
			if w.Kind != "" || len(w.Steps) != 0 || w.OnTerminal != nil {
				t.Fatalf("a refused constructor returned a non-zero workflow: %+v", w)
			}
		})
		t.Run(tc.kind+"/with source", func(t *testing.T) {
			w, err := tc.build(testSource(t))
			if err != nil {
				t.Fatalf("the constructor refused a source: %v", err)
			}
			if w.Kind != tc.kind {
				t.Fatalf("Kind = %q, want %q", w.Kind, tc.kind)
			}
			push := false
			for _, s := range w.Steps {
				if s.Name == "push" {
					push = s.Do != nil
				}
			}
			if !push {
				t.Fatalf("the %s workflow has no push step", tc.kind)
			}
		})
	}
}
