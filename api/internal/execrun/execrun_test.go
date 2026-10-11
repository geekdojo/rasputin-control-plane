package execrun

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TC-758-36: the one shared runner returns the output on success, the output
// and a descriptive error on a non-zero exit, and a ctx error when cancelled.
func TestCombinedOutput(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("sh: %v", err)
	}

	t.Run("success returns the output", func(t *testing.T) {
		out, err := CombinedOutput(t.Context(), sh, "-c", "printf ok; printf ' err' >&2")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if string(out) != "ok err" {
			t.Errorf("out = %q, want both streams %q", out, "ok err")
		}
	})

	t.Run("non-zero exit carries the output", func(t *testing.T) {
		out, err := CombinedOutput(t.Context(), sh, "-c", "printf '  refused  '; exit 3")
		if err == nil {
			t.Fatal("err = nil, want the exit status")
		}
		if string(out) != "  refused  " {
			t.Errorf("out = %q, want the untrimmed output", out)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
			t.Errorf("err = %v, want an *exec.ExitError with code 3", err)
		}
		for _, want := range []string{sh + " -c printf '  refused  '; exit 3", "(output: refused)"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, want it to contain %q", err, want)
			}
		}
	})

	t.Run("a cancelled ctx stops the command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := CombinedOutput(ctx, sh, "-c", "sleep 30")
		if err == nil {
			t.Fatal("err = nil, want the cancel")
		}
		if !errors.Is(err, context.Canceled) {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || !strings.Contains(err.Error(), "killed") {
				t.Errorf("err = %v, want context.Canceled or a killed process", err)
			}
		}
	})
}
