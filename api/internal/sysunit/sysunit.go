// Package sysunit holds the one way the api restarts a systemd unit that may
// be sitting in failed or was skipped: the secret store's and the identity
// service's leaf reloads, and the full-disk recoveries
// (geekdojo/geekdojo-brain#979 moved it here from the composition root so the
// identity recovery reuses it rather than copying it). It also holds the one
// way the api reads a unit's state (Show), and the one way it lists the
// units of a pattern that run now (ActiveUnits).
package sysunit

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
)

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

// Unit is one unit's systemd properties, as Show reads them.
type Unit struct {
	ActiveState  string
	SubState     string
	InvocationID string
}

// unitProps are the properties Show asks for, in one call.
var unitProps = []string{"ActiveState", "SubState", "InvocationID"}

// Show reads units' properties with one
// `systemctl show --property=ActiveState,SubState,InvocationID <units...>`,
// in the order the units are named. It moved here from identitystate
// (geekdojo/geekdojo-brain#1132), so the store migration reads the store
// unit's InvocationID through the same code as the identity monitor.
func Show(ctx context.Context, run func(ctx context.Context, name string, args ...string) ([]byte, error),
	units ...string) ([]Unit, error) {
	if len(units) == 0 {
		return nil, errors.New("sysunit: no unit named")
	}
	out, err := run(ctx, "systemctl", append([]string{"show", "--property=" + strings.Join(unitProps, ",")}, units...)...)
	if err != nil {
		return nil, fmt.Errorf("reading the state of %s: %w", strings.Join(units, " and "), err)
	}
	return ParseUnits(out, len(units))
}

// ParseUnits parses `systemctl show` output for n units: n blocks of
// KEY=VALUE lines, separated by a blank line, in the order the units were
// named. Each block must carry ActiveState, SubState and InvocationID (which
// is empty for a unit that never ran), and a non-empty ActiveState; anything
// else is an error.
func ParseUnits(out []byte, n int) ([]Unit, error) {
	var blocks []map[string]string
	cur := map[string]string{}
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("systemctl show line %d is not KEY=VALUE", i+1)
		}
		cur[k] = v
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	if len(blocks) != n {
		return nil, fmt.Errorf("systemctl show printed %d units, want %d", len(blocks), n)
	}
	units := make([]Unit, n)
	for i, b := range blocks {
		for _, p := range unitProps {
			if _, ok := b[p]; !ok {
				return nil, fmt.Errorf("systemctl show printed no %s for unit %d", p, i+1)
			}
		}
		if b["ActiveState"] == "" {
			return nil, fmt.Errorf("systemctl show printed an empty ActiveState for unit %d", i+1)
		}
		units[i] = Unit{ActiveState: b["ActiveState"], SubState: b["SubState"], InvocationID: b["InvocationID"]}
	}
	return units, nil
}

// ActiveUnits lists the service units matching pattern that are active now,
// with one `systemctl list-units --type=service --state=active --plain
// --no-legend <pattern>` (geekdojo/geekdojo-brain#321: the repair page lists
// the serial way only while a serial login runs). No match is an empty
// result and a nil error.
func ActiveUnits(ctx context.Context, run func(ctx context.Context, name string, args ...string) ([]byte, error),
	pattern string) ([]string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, fmt.Errorf("sysunit: unit pattern %q: %w", pattern, err)
	}
	out, err := run(ctx, "systemctl", "list-units", "--type=service", "--state=active", "--plain", "--no-legend", pattern)
	if err != nil {
		return nil, fmt.Errorf("listing the active units of %s: %w", pattern, err)
	}
	return parseActive(out, pattern)
}

// parseActive parses list-units output strictly (F-321-45): blank lines are
// skipped, and every other line must be `<unit matching pattern> loaded
// active <sub> [description]`. Anything else, a stray warning included,
// is an error and no unit, so a caller never counts a line it can't read as
// a running unit.
func parseActive(out []byte, pattern string) ([]string, error) {
	units := []string{}
	for i, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 4 || f[1] != "loaded" || f[2] != "active" {
			return nil, fmt.Errorf("systemctl list-units line %d is not an active loaded unit", i+1)
		}
		if ok, _ := path.Match(pattern, f[0]); !ok { // the pattern was checked by ActiveUnits
			return nil, fmt.Errorf("systemctl list-units line %d names a unit outside %s", i+1, pattern)
		}
		units = append(units, f[0])
	}
	return units, nil
}
