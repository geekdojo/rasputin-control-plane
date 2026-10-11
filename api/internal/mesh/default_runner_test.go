package mesh

import (
	"reflect"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/execrun"
)

// TC-758-36: a supervisor built without a Runner runs docker through the one
// shared runner, not a private copy.
func TestNewDockerSupervisor_DefaultRunnerIsExecrun(t *testing.T) {
	s, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	if reflect.ValueOf(s.runner).Pointer() != reflect.ValueOf(execrun.CombinedOutput).Pointer() {
		t.Error("the default runner is not execrun.CombinedOutput")
	}
}
