package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/storage"
)

// Backend selection — the one decision in this command that can make every
// other line of its output a fiction.

// backendChoice is what a run resolved to.
type backendChoice struct {
	// Name is "blockdev" or "mock", matching storage.Backend.Name().
	Name string
	// Fixture is true for the mock and false for the real backend. It is not
	// derivable from Name by anything downstream without re-spelling the
	// comparison, and it is what every renderer keys its banner off, so it is
	// carried rather than re-derived.
	Fixture bool
}

// errNoTooling is the refusal a bench node with an incomplete util-linux gets.
// A sentinel so dispatch can map it to its own exit code — a script that sees
// "could not run" must be able to tell "this image is missing wipefs" from
// "the disk refused the claim", because the first is fixed by rebuilding the
// image and the second is not fixed at all.
var errNoTooling = errors.New("the real storage backend is unavailable on this machine")

// errBadBackend is an unusable --backend value. Usage, not a storage failure.
var errBadBackend = errors.New("unknown backend")

// selectBackend decides which backend a run gets. It is the entire safety
// rule, in one pure function, so it can be tested rather than inspected.
//
// choice is the --backend flag; "" means "the real one". missing is
// storage.MissingTools() — the required util-linux tools NOT on PATH, already
// named rather than reduced to a bool.
//
// ⚠️ THERE IS NO PATH FROM AN EMPTY choice TO THE MOCK, and there must never
// be one. Falling back would reproduce the 2026-09-01 incident inside a tool
// whose entire job is to tell an operator the truth about their disks: fixture
// disks printed with a real device path beside a fingerprint the operator is
// about to paste into a destructive claim. An explicit `--backend blockdev` on
// a machine without the tooling is refused for the same reason and by the same
// branch — asking for the real backend by name does not conjure `wipefs`.
//
// Note also what is NOT read here: RASPUTIN_STORAGE_BACKEND. The agent honours
// that variable, and this command deliberately does not, because a bench run
// inherits the environment of whatever shell started it and a probe whose
// backend can be flipped by a leftover export is the silent-mock hazard with
// an extra hop. The mock is a flag you type, on the command line, in front of
// you.
func selectBackend(choice string, missing []string) (backendChoice, error) {
	switch strings.TrimSpace(choice) {
	case "", "blockdev":
		if len(missing) > 0 {
			return backendChoice{}, fmt.Errorf(
				"%w: not on PATH: %s — this is not a machine storageprobe can read disks on, "+
					"and it will NOT substitute the mock (see storage.MissingTools). "+
					"Add the missing tool to the image, or pass --backend mock to exercise fixtures knowingly",
				errNoTooling, strings.Join(missing, ", "))
		}
		return backendChoice{Name: "blockdev"}, nil
	case "mock":
		return backendChoice{Name: "mock", Fixture: true}, nil
	default:
		return backendChoice{}, fmt.Errorf("%w: %q (want %q or %q)", errBadBackend, choice, "blockdev", "mock")
	}
}

// openBackend resolves the choice and constructs the backend behind it.
//
// stateDir is the agent's state directory. The real backend keeps nothing
// there for the verbs this command drives — its answers come off the platter —
// but the mock keeps its whole simulated machine under <stateDir>/storage, so
// a mock run needs one it may write to and a bench run of the mock must not be
// pointed at the live agent's.
func openBackend(choice, stateDir string) (storage.Backend, backendChoice, error) {
	sel, err := selectBackend(choice, storage.MissingTools())
	if err != nil {
		return nil, backendChoice{}, err
	}
	switch sel.Name {
	case "blockdev":
		b, err := storage.NewBlockDevBackend(stateDir)
		if err != nil {
			// Unreachable while selectBackend and NewBlockDevBackend agree on
			// requiredTools — they read the same list — but a constructor
			// failure is still a refusal and never a fall-through.
			return nil, backendChoice{}, fmt.Errorf("%w: %v", errNoTooling, err)
		}
		return b, sel, nil
	case "mock":
		b, err := storage.NewMockBackend(stateDir)
		if err != nil {
			return nil, backendChoice{}, fmt.Errorf("open mock backend under %s: %w", stateDir, err)
		}
		return b, sel, nil
	default:
		return nil, backendChoice{}, fmt.Errorf("%w: %q", errBadBackend, sel.Name)
	}
}
