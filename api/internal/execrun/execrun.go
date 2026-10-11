// Package execrun is the one default way the api runs an external command and
// keeps what it printed. mesh and obs supervise their containers through it,
// and the composition root restarts the secret store's unit through it
// (geekdojo/geekdojo-brain#758). Before it, each supervisor carried its own
// byte-identical copy.
package execrun

import (
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
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
