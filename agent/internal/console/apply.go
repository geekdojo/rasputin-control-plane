package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// How a delivered hash reaches root's shadow entry.
//
// The IMAGE owns that write where it ships a helper for it. The firewall
// image already does: /usr/lib/rasputin/set-root-hash
// (geekdojo/rasputin-openwrt-firewall#64) takes a crypt hash on argv or
// stdin, rewrites only root's field atomically at 0600, refuses a plaintext
// or anything that would corrupt the row, and never logs the value. That is
// the contract this agent targets rather than a second one of its own: the
// image knows things the agent does not — where the overlay is, what else
// must be re-asserted alongside the password, what its own boot-time harden
// script expects to find.
//
// The agent keeps its own writer for an image that has not shipped the
// helper yet. That is not a rollback shim; it is the tolerance #64's PR body
// hands to this story in as many words — "a newer control plane that pushes
// a root hash must tolerate a firewall image without set-root-hash (the
// agent pin lags); that tolerance belongs to the control-plane story". The
// two paths produce the same file. When both images ship the helper, the
// fallback can go, and the fact that retires it is every node reporting it
// applied through the helper.

// HelperPath is where an image that owns the write puts its helper.
const HelperPath = "/usr/lib/rasputin/set-root-hash"

// helperTimeout bounds the one exec. A single I/O call may carry a timeout;
// nothing else here is clock-driven.
const helperTimeout = 20 * time.Second

// applyVia names which path applied the hash, for the ack and the log.
type applyVia string

const (
	viaHelper applyVia = "the image's " + HelperPath
	viaAgent  applyVia = "the agent's own shadow writer (this image ships no " + HelperPath + ")"
)

// errHelperMissing is returned by runHelper when the image has no helper, so
// the caller falls back rather than failing the node.
var errHelperMissing = errors.New("console: the image ships no set-root-hash helper")

// apply installs hash through the image's helper when there is one, and
// through the agent's own writer otherwise. changed is false only when the
// node already held exactly this hash.
//
// The helper has no "was it already this?" answer, so the comparison is made
// here, before the call: reading the current field is what makes a re-run of
// the push job a no-op on a converged node.
func apply(ctx context.Context, shadowPath, helperPath, hash string) (changed bool, via applyVia, err error) {
	same, err := rootHoldsHash(shadowPath, hash)
	if err != nil {
		return false, "", err
	}
	if same {
		return false, viaHelper, nil
	}
	switch err := runHelper(ctx, helperPath, shadowPath, hash); {
	case err == nil:
		return true, viaHelper, nil
	case errors.Is(err, errHelperMissing):
		// Fall through to the agent's own writer.
	default:
		return false, viaHelper, err
	}
	if _, err := ApplyRootHash(shadowPath, hash); err != nil {
		return false, viaAgent, err
	}
	return true, viaAgent, nil
}

// runHelper execs the image's helper with the hash on STDIN.
//
// Stdin, not argv: an argument is visible in /proc/<pid>/cmdline to every
// process on the box for as long as the helper runs, and the hash is secret
// material. The helper accepts either form.
func runHelper(ctx context.Context, helperPath, shadowPath, hash string) error {
	info, err := os.Stat(helperPath)
	if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return errHelperMissing
	}
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, helperPath)
	cmd.Stdin = strings.NewReader(hash)
	// The helper reads RASPUTIN_SHADOW_FILE for its own tests; passing the
	// agent's resolved path keeps the two ends pointed at one file.
	cmd.Env = append(os.Environ(), "RASPUTIN_SHADOW_FILE="+shadowPath)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		// The helper's contract is that its messages describe the SHAPE of a
		// value and never the value, so its output is safe to relay.
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s refused the delivered password: %s", helperPath, msg)
	}
	return nil
}

// rootHoldsHash reports whether root's shadow field already equals hash.
func rootHoldsHash(shadowPath, hash string) (bool, error) {
	raw, err := os.ReadFile(shadowPath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", shadowPath, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, rootUser+":") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			return false, fmt.Errorf("%s: root entry has %d field(s), want at least 2", shadowPath, len(fields))
		}
		return fields[1] == hash, nil
	}
	return false, fmt.Errorf("%s: %w", shadowPath, ErrNoRootEntry)
}

// HelperPathFromEnv resolves the helper the agent should call.
// RASPUTIN_SET_ROOT_HASH overrides it, for tests.
func HelperPathFromEnv() string {
	if v := os.Getenv("RASPUTIN_SET_ROOT_HASH"); v != "" {
		return v
	}
	return HelperPath
}
