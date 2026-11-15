package execrun

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// helperEnv marks the test binary run as TestHelperProcess's child.
const helperEnv = "EXECRUN_HELPER_PROCESS=1"

// TestHelperProcess is not a test: run by CombinedOutputEnv below, it prints
// its own environment and the arguments after "--", one per line, and exits
// 0, or 7 when the first argument is "fail".
func TestHelperProcess(t *testing.T) {
	if !slices.Contains(os.Environ(), helperEnv) {
		return
	}
	i := slices.Index(os.Args, "--")
	args := os.Args[i+1:]
	for _, e := range os.Environ() {
		fmt.Println("env:" + e)
	}
	for _, a := range args {
		fmt.Println("arg:" + a)
	}
	if len(args) > 0 && args[0] == "fail" {
		os.Exit(7)
	}
	os.Exit(0)
}

// TC-978-19: the child's environment is exactly the given list, with nothing
// inherited (a sentinel in this process's environment is absent), argv is
// unchanged, and a failing run's error names the command, its arguments and
// the output, and no environment value the caller gave.
func TestCombinedOutputEnv_TheEnvironmentIsExactlyTheGivenList(t *testing.T) {
	const parentSentinel = "EXECRUN_PARENT_SENTINEL=parent-value-0451"
	t.Setenv("EXECRUN_PARENT_SENTINEL", "parent-value-0451")
	const childSecret = "CHILD_SECRET=child-secret-value-9a7c"
	env := []string{helperEnv, childSecret, "PATH=/usr/bin:/bin"}

	out, err := CombinedOutputEnv(t.Context(), env, os.Args[0], "-test.run=^TestHelperProcess$", "--", "a b", "c")
	if err != nil {
		t.Fatalf("CombinedOutputEnv: %v", err)
	}
	var gotEnv, gotArgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case strings.HasPrefix(line, "env:"):
			gotEnv = append(gotEnv, strings.TrimPrefix(line, "env:"))
		case strings.HasPrefix(line, "arg:"):
			gotArgs = append(gotArgs, strings.TrimPrefix(line, "arg:"))
		}
	}
	slices.Sort(gotEnv)
	want := slices.Clone(env)
	slices.Sort(want)
	if !slices.Equal(gotEnv, want) {
		t.Errorf("child environment = %q, want exactly %q", gotEnv, want)
	}
	if slices.Contains(gotEnv, parentSentinel) {
		t.Error("the child inherited the parent's sentinel variable")
	}
	if !slices.Equal(gotArgs, []string{"a b", "c"}) {
		t.Errorf("child argv after -- = %q, want [a b c]", gotArgs)
	}

	_, err = CombinedOutputEnv(t.Context(), env, os.Args[0], "-test.run=^TestHelperProcess$", "--", "fail", "x")
	if err == nil {
		t.Fatal("a failing run returned no error")
	}
	msg := err.Error()
	for _, want := range []string{os.Args[0], "-- fail x", "arg:fail"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %q", msg, want)
		}
	}
	// The output carries the env lines the helper printed, so the error's
	// output part is checked only for what the caller controls: the error's
	// own text before the output never prints the environment.
	head, _, _ := strings.Cut(msg, "(output:")
	for _, v := range []string{"child-secret-value-9a7c", "parent-value-0451"} {
		if strings.Contains(head, v) {
			t.Errorf("the error's command part carries an environment value: %q", head)
		}
	}
}
