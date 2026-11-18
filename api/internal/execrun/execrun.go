// Package execrun is the one default way the api runs an external command and
// keeps what it printed. mesh and obs supervise their containers through it,
// and the composition root restarts the secret store's unit through it
// (geekdojo/geekdojo-brain#758). Before it, each supervisor carried its own
// byte-identical copy.
package execrun

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CombinedOutput runs name with args under ctx and returns its combined
// stdout and stderr. A failure returns the output too, and an error naming the
// command, its arguments and the trimmed output, so a log line says why the
// command refused. ctx ending kills the process.
func CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return combined(exec.CommandContext(ctx, name, args...), name, args)
}

// CombinedOutputInput is CombinedOutput with env as the command's whole
// environment, nothing inherited from this process's, and stdin as its
// standard input; a nil stdin reads as empty. It is how a value that must not
// appear on a command line or in a file (geekdojo/geekdojo-brain#1131's
// temporary identity client secret) reaches a child. The error names the
// command, its arguments and the output, as CombinedOutput's does, and never
// an environment value or the input.
func CombinedOutputInput(ctx context.Context, env []string, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// A nil Env would inherit everything; an empty, non-nil one gives none.
	cmd.Env = append(make([]string, 0, len(env)), env...)
	cmd.Stdin = bytes.NewReader(stdin)
	return combined(cmd, name, args)
}

// combined runs cmd and wraps a failure with the command, its arguments and
// the trimmed output.
func combined(cmd *exec.Cmd, name string, args []string) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
