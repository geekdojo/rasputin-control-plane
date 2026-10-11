package obs

import (
	"reflect"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/execrun"
)

// TC-758-36: a supervisor built without a Runner runs compose through the one
// shared runner, not a private copy.
func TestNewDockerComposeSupervisor_DefaultRunnerIsExecrun(t *testing.T) {
	s, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if reflect.ValueOf(s.runner).Pointer() != reflect.ValueOf(execrun.CombinedOutput).Pointer() {
		t.Error("the default runner is not execrun.CombinedOutput")
	}
}
