package execrun

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// helperEnv marks the test binary run as TestHelperProcess's child.
const helperEnv = "EXECRUN_HELPER_PROCESS=1"

// TestHelperProcess is not a test: run by CombinedOutputInput below, it reads
// its whole stdin and prints it quoted, then its own environment and the
// arguments after "--", one per line, and exits 0. When the first argument is
// "fail" it prints only how many bytes it read, never the bytes, and exits 7.
func TestHelperProcess(t *testing.T) {
	if !slices.Contains(os.Environ(), helperEnv) {
		return
	}
	i := slices.Index(os.Args, "--")
	args := os.Args[i+1:]
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("stdin-error:" + err.Error())
		os.Exit(9)
	}
	if len(args) > 0 && args[0] == "fail" {
		fmt.Printf("read %d bytes\n", len(in))
		for _, a := range args {
			fmt.Println("arg:" + a)
		}
		os.Exit(7)
	}
	fmt.Println("stdin:" + strconv.Quote(string(in)))
	for _, e := range os.Environ() {
		fmt.Println("env:" + e)
	}
	for _, a := range args {
		fmt.Println("arg:" + a)
	}
	os.Exit(0)
}

// helperOutput splits the helper's output into what it read on stdin, its
// environment and its argv after "--".
func helperOutput(t *testing.T, out []byte) (stdin string, env, args []string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case strings.HasPrefix(line, "stdin:"):
			s, err := strconv.Unquote(strings.TrimPrefix(line, "stdin:"))
			if err != nil {
				t.Fatalf("helper stdin line %q: %v", line, err)
			}
			stdin = s
		case strings.HasPrefix(line, "env:"):
			env = append(env, strings.TrimPrefix(line, "env:"))
		case strings.HasPrefix(line, "arg:"):
			args = append(args, strings.TrimPrefix(line, "arg:"))
		}
	}
	return stdin, env, args
}

// TC-1131-01 (and TC-978-19's exact environment, carried over): the child
// reads exactly the given stdin, its environment is exactly the given list
// with nothing inherited (a sentinel in this process's environment is
// absent), and argv is unchanged. A nil stdin reads as EOF at once.
func TestCombinedOutputInput_DeliversStdinAndAnExactEnvironment(t *testing.T) {
	const parentSentinel = "EXECRUN_PARENT_SENTINEL=parent-value-0451"
	t.Setenv("EXECRUN_PARENT_SENTINEL", "parent-value-0451")
	env := []string{helperEnv, "CHILD_VAR=child-value-9a7c", "PATH=/usr/bin:/bin"}

	out, err := CombinedOutputInput(t.Context(), env, []byte("abc\n"), os.Args[0], "-test.run=^TestHelperProcess$", "--", "a b", "c")
	if err != nil {
		t.Fatalf("CombinedOutputInput: %v", err)
	}
	gotIn, gotEnv, gotArgs := helperOutput(t, out)
	if gotIn != "abc\n" {
		t.Errorf("child read %q on stdin, want %q", gotIn, "abc\n")
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

	out, err = CombinedOutputInput(t.Context(), env, nil, os.Args[0], "-test.run=^TestHelperProcess$", "--", "x")
	if err != nil {
		t.Fatalf("CombinedOutputInput with nil stdin: %v", err)
	}
	if gotIn, _, _ := helperOutput(t, out); gotIn != "" {
		t.Errorf("with nil stdin the child read %q, want EOF at once", gotIn)
	}
}

// TC-1131-02: a failing run's error names the command, its arguments and the
// child's output, and carries the stdin nowhere; a cancelled context returns
// an error.
func TestCombinedOutputInput_ErrorNeverCarriesStdin(t *testing.T) {
	const sentinel = "STDIN-SECRET-5c1e0b7d"
	env := []string{helperEnv, "PATH=/usr/bin:/bin"}

	_, err := CombinedOutputInput(t.Context(), env, []byte(sentinel+"\n"), os.Args[0], "-test.run=^TestHelperProcess$", "--", "fail", "x")
	if err == nil {
		t.Fatal("a failing run returned no error")
	}
	msg := err.Error()
	for _, want := range []string{os.Args[0], "-- fail x", "arg:fail", "read 22 bytes"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %q", msg, want)
		}
	}
	if strings.Contains(msg, sentinel) {
		t.Errorf("the error carries the stdin: %q", msg)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := CombinedOutputInput(ctx, env, []byte(sentinel), os.Args[0], "-test.run=^TestHelperProcess$", "--", "x"); err == nil {
		t.Error("a cancelled context returned no error")
	}
}
