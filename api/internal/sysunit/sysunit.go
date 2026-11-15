// Package sysunit holds the one way the api restarts a systemd unit that may
// be sitting in failed or was skipped: the secret store's and the identity
// service's leaf reloads, and the full-disk recoveries
// (geekdojo/geekdojo-brain#979 moved it here from the composition root so the
// identity recovery reuses it rather than copying it).
package sysunit

import "context"

// RestartUnits runs systemctl reset-failed on reset, so a unit skipped on
// first boot or sitting in failed after a crash loop can start, then
// systemctl restart unit. The first error is returned and the restart is then
// not attempted.
func RestartUnits(ctx context.Context, run func(ctx context.Context, name string, args ...string) ([]byte, error),
	reset []string, unit string) error {
	if _, err := run(ctx, "systemctl", append([]string{"reset-failed"}, reset...)...); err != nil {
		return err
	}
	_, err := run(ctx, "systemctl", "restart", unit)
	return err
}
