package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/clusterdns"
)

// devImage is a pre-release image version, on which the Rebooter may simulate.
const devImage = "2026.09.4-dev.7"

// unsetEnv makes key absent for the rest of the test, and restores it after.
// t.Setenv registers the restore; os.Unsetenv then removes the variable.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
}

// selectorUnderTest is one of the five backend selector resolvers, with the
// variable it reads and the names its autodetect may answer.
type selectorUnderTest struct {
	name    string
	env     string
	real    []string
	resolve func(detect func() string) string
}

var backendSelectors = []selectorUnderTest{
	{"docker", "RASPUTIN_DOCKER_BACKEND", []string{"docker"}, dockerBackendFromEnv},
	{"uci", "RASPUTIN_UCI_BACKEND", []string{"uci"}, uciBackendFromEnv},
	{"update", "RASPUTIN_UPDATE_BACKEND", []string{"rauc", "openwrt-ab"}, updateBackendFromEnv},
	{"storage", "RASPUTIN_STORAGE_BACKEND", []string{"blockdev"}, storageBackendFromEnv},
	{"tailscale", "RASPUTIN_TAILSCALE_BACKEND", []string{"tailscale"}, tailscaleBackendFromEnv},
}

// probe is an autodetect stand-in that answers a fixed value and counts how
// often it was asked.
type probe struct {
	answer string
	calls  int
}

func (p *probe) detect() string {
	p.calls++
	return p.answer
}

// malformedSelectorValues are the TC-591-05 values. other is a real name that
// belongs to a different selector.
func malformedSelectorValues(other string) []string {
	return []string{"Mock", " mock", "mock ", "MOCK", "docker,mock", "none", "auto", "1", other}
}

// otherSelectorsName returns a real backend name of a different selector.
func otherSelectorsName(sel selectorUnderTest) string {
	for _, o := range backendSelectors {
		if o.name != sel.name {
			return o.real[0]
		}
	}
	panic("no other selector")
}

// Fail-closed table test for the five backend selector resolvers
// (security-resolvers R29-R33).
func TestBackendFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	for _, sel := range backendSelectors {
		t.Run(sel.name, func(t *testing.T) {
			// TC-591-01: absent, and the probe answers a real name.
			t.Run("TC-591-01 absent, probe answers a real name", func(t *testing.T) {
				for _, name := range sel.real {
					unsetEnv(t, sel.env)
					p := &probe{answer: name}
					if got := sel.resolve(p.detect); got != name {
						t.Errorf("%s absent, probe %q: got %q, want %q", sel.env, name, got, name)
					}
					if p.calls != 1 {
						t.Errorf("%s absent: probe called %d times, want 1", sel.env, p.calls)
					}
				}
			})

			// TC-591-02: absent or empty, and the probe finds nothing.
			t.Run("TC-591-02 absent or empty, probe unavailable", func(t *testing.T) {
				for _, shape := range []string{"absent", "empty"} {
					if shape == "absent" {
						unsetEnv(t, sel.env)
					} else {
						t.Setenv(sel.env, "")
					}
					p := &probe{answer: backendUnavailable}
					if got := sel.resolve(p.detect); got != backendUnavailable {
						t.Errorf("%s %s, probe unavailable: got %q, want backendUnavailable", sel.env, shape, got)
					}
				}
			})

			// TC-591-03: a probe answer outside real is never honoured, and
			// mock is never inferred.
			t.Run("TC-591-03 mock and junk probe answers are unavailable", func(t *testing.T) {
				for _, answer := range []string{"mock", "junk"} {
					unsetEnv(t, sel.env)
					p := &probe{answer: answer}
					if got := sel.resolve(p.detect); got != backendUnavailable {
						t.Errorf("%s absent, probe %q: got %q, want backendUnavailable", sel.env, answer, got)
					}
				}
			})

			// TC-591-04: an explicit selection is honoured, without probing.
			t.Run("TC-591-04 explicit selection honoured without probing", func(t *testing.T) {
				for _, set := range append([]string{"mock"}, sel.real...) {
					t.Setenv(sel.env, set)
					p := &probe{answer: backendUnavailable}
					if got := sel.resolve(p.detect); got != set {
						t.Errorf("%s=%q: got %q, want %q", sel.env, set, got, set)
					}
					if p.calls != 0 {
						t.Errorf("%s=%q: probe called %d times, want 0", sel.env, set, p.calls)
					}
				}
			})

			// TC-591-05: a malformed value comes back verbatim and never
			// selects a backend.
			t.Run("TC-591-05 malformed values are returned verbatim", func(t *testing.T) {
				selectable := append([]string{"mock"}, sel.real...)
				for _, set := range malformedSelectorValues(otherSelectorsName(sel)) {
					t.Setenv(sel.env, set)
					p := &probe{answer: sel.real[0]}
					got := sel.resolve(p.detect)
					if got != set {
						t.Errorf("%s=%q: got %q, want the value verbatim", sel.env, set, got)
					}
					if slices.Contains(selectable, got) {
						t.Errorf("%s=%q resolved to selectable backend %q", sel.env, set, got)
					}
					if p.calls != 0 {
						t.Errorf("%s=%q: probe called %d times, want 0", sel.env, set, p.calls)
					}
				}
			})
		})
	}

	// TC-591-06: the update selector's result never makes the Rebooter
	// simulate, except for an explicit mock on a dev image.
	t.Run("TC-591-06 update result never simulates a reboot unless mock", func(t *testing.T) {
		const env = "RASPUTIN_UPDATE_BACKEND"
		for _, set := range malformedSelectorValues("docker") {
			t.Setenv(env, set)
			choice := updateBackendFromEnv((&probe{answer: backendUnavailable}).detect)
			if newRebooter("n", nil, choice, devImage, nil).Simulated() {
				t.Errorf("%s=%q (resolved %q) on a dev image: Rebooter simulates", env, set, choice)
			}
		}
		unsetEnv(t, env)
		choice := updateBackendFromEnv((&probe{answer: backendUnavailable}).detect)
		if newRebooter("n", nil, choice, devImage, nil).Simulated() {
			t.Errorf("%s absent, probe unavailable (resolved %q): Rebooter simulates", env, choice)
		}
		t.Setenv(env, "mock")
		choice = updateBackendFromEnv((&probe{answer: backendUnavailable}).detect)
		if !newRebooter("n", nil, choice, devImage, nil).Simulated() {
			t.Errorf("%s=mock on a dev image: Rebooter does not simulate", env)
		}
	})
}

// Fail-closed table test for bmcBackendFromEnv (security-resolvers R28), held
// against the real bmc.NewHost, which is where an unknown name is refused.
func TestBMCBackendFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	const env = "RASPUTIN_BMC_BACKEND"
	newHost := func(t *testing.T) (*bmc.Host, error) {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "bmc")
		return bmc.NewHost("n1", dir, bmcBackendFromEnv(), bmcConfigFromEnv(dir))
	}

	// TC-591-07: absent, empty or none is off, with a fresh state dir.
	for _, shape := range []string{"absent", "", bmc.BackendNone} {
		t.Run("TC-591-07 off: "+shape, func(t *testing.T) {
			if shape == "absent" {
				unsetEnv(t, env)
			} else {
				t.Setenv(env, shape)
			}
			host, err := newHost(t)
			if err != nil {
				t.Fatalf("%s=%q: NewHost error %v, want nil", env, shape, err)
			}
			if host.Active() {
				t.Errorf("%s=%q: host is active, want off", env, shape)
			}
		})
	}

	// TC-591-08: a malformed name is refused as unknown.
	for _, set := range []string{"Mock", " mock", "bitscope2", "docker"} {
		t.Run("TC-591-08 refused: "+set, func(t *testing.T) {
			t.Setenv(env, set)
			host, err := newHost(t)
			if !errors.Is(err, bmc.ErrUnknownBackend) {
				t.Errorf("%s=%q: err %v, want ErrUnknownBackend", env, set, err)
			}
			if host != nil {
				t.Errorf("%s=%q: got a host, want nil", env, set)
			}
		})
	}

	// TC-591-09: an explicit mock is honoured.
	t.Run("TC-591-09 explicit mock", func(t *testing.T) {
		t.Setenv(env, "mock")
		host, err := newHost(t)
		if err != nil {
			t.Fatalf("%s=mock: NewHost error %v", env, err)
		}
		if !host.Active() {
			t.Errorf("%s=mock: host is not active", env)
		}
	})
}

// TC-591-10: fail-closed table test for resolvedDropinDirFromEnv
// (security-resolvers R34). The result is never empty.
func TestResolvedDropinDirFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	const env = "RASPUTIN_RESOLVED_DROPIN_DIR"
	for _, tc := range []struct {
		name   string
		absent bool
		set    string
		want   string
	}{
		{"absent", true, "", clusterdns.DefaultDir},
		{"empty", false, "", clusterdns.DefaultDir},
		{"blank", false, "   ", clusterdns.DefaultDir},
		{"padded", false, "  /tmp/x  ", "/tmp/x"},
		{"set", false, "/tmp/x", "/tmp/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.absent {
				unsetEnv(t, env)
			} else {
				t.Setenv(env, tc.set)
			}
			got := resolvedDropinDirFromEnv()
			if got != tc.want {
				t.Errorf("%s=%q: got %q, want %q", env, tc.set, got, tc.want)
			}
			if got == "" {
				t.Errorf("%s=%q: resolved to an empty directory", env, tc.set)
			}
		})
	}
}
