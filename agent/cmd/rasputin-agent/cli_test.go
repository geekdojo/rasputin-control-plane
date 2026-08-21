package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures live with the package that owns the verification logic; there is
// one signed payload in this repo and both test suites point at it, so a change
// to how the pipeline signs cannot leave one of them passing against a stale
// copy.
func fixture(name string) string {
	return filepath.Join("..", "..", "..", "artifactsig", "testdata", name)
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code, handled := dispatchCLI(args, &out, &errBuf)
	if !handled {
		t.Fatalf("dispatchCLI(%q) reported unhandled; only the empty argument list is the daemon path", args)
	}
	return code, out.String(), errBuf.String()
}

// The daemon path. Both shipping unit files start the agent with no arguments,
// so this must stay true or every node stops booting its agent.
func TestDispatchCLI_NoArgsRunsTheDaemon(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code, handled := dispatchCLI(nil, &out, &errBuf); handled || code != 0 {
		t.Fatalf("dispatchCLI(nil) = (%d, %v), want (0, false)", code, handled)
	}
	if out.Len() != 0 || errBuf.Len() != 0 {
		t.Errorf("dispatchCLI(nil) wrote output; the daemon path must be silent")
	}
}

func TestDispatchCLI_HelpListsTheCommandsAndOptions(t *testing.T) {
	for _, flag := range []string{"-h", "--help", "help"} {
		code, stdout, _ := run(t, flag)
		if code != 0 {
			t.Errorf("%s: exit = %d, want 0", flag, code)
		}
		for _, want := range []string{
			"verify-artifact", "version", "--sig", "--trust-root",
			"RASPUTIN_TRUST_ROOT", "/etc/rasputin/trust/root-ca.pem",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%s: help does not mention %q", flag, want)
			}
		}
	}
}

func TestDispatchCLI_UnknownCommand(t *testing.T) {
	code, _, stderr := run(t, "frobnicate")
	// 2, not 1: a script must not be able to read a typo as "signature bad".
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestVerifyArtifact_GoodSignature(t *testing.T) {
	code, stdout, stderr := run(t, "verify-artifact", fixture("payload.bin"), "--trust-root", fixture("root-ca.pem"))
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"signature OK", "Rasputin Test Release Leaf", "sha256"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not mention %q:\n%s", want, stdout)
		}
	}
}

// Flags on either side of the artifact. Go's flag package stops at the first
// positional, so the natural `verify-artifact <file> --trust-root <pem>` form
// would otherwise silently ignore the flag and verify against the baked default
// — passing or failing for a reason the operator did not ask about.
func TestVerifyArtifact_FlagsOnEitherSideOfTheArtifact(t *testing.T) {
	for _, args := range [][]string{
		{"verify-artifact", fixture("payload.bin"), "--trust-root", fixture("root-ca.pem")},
		{"verify-artifact", "--trust-root", fixture("root-ca.pem"), fixture("payload.bin")},
	} {
		if code, _, stderr := run(t, args...); code != 0 {
			t.Errorf("%v: exit = %d, stderr = %s", args, code, stderr)
		}
	}
}

func TestVerifyArtifact_Rejections(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{
			name:     "chains to a foreign root",
			args:     []string{"verify-artifact", fixture("payload.bin"), "--sig", fixture("payload.bin.other.sig"), "--trust-root", fixture("root-ca.pem")},
			wantCode: 1, wantErr: "SIGNATURE INVALID",
		},
		{
			name:     "no signature beside the artifact",
			args:     []string{"verify-artifact", fixture("root-ca.pem"), "--trust-root", fixture("root-ca.pem")},
			wantCode: 1, wantErr: "signature file is missing",
		},
		{
			name:     "trust root absent",
			args:     []string{"verify-artifact", fixture("payload.bin"), "--trust-root", fixture("no-such-root.pem")},
			wantCode: 1, wantErr: "trust root is missing",
		},
		{
			name:     "no artifact named",
			args:     []string{"verify-artifact"},
			wantCode: 2, wantErr: "expected exactly one artifact path",
		},
		{
			name:     "two artifacts named",
			args:     []string{"verify-artifact", "a", "b"},
			wantCode: 2, wantErr: "expected exactly one artifact path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tc.args...)
			if code != tc.wantCode {
				t.Errorf("exit = %d, want %d (stderr: %s)", code, tc.wantCode, stderr)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, tc.wantErr)
			}
			if strings.Contains(stdout, "signature OK") {
				t.Errorf("a rejection printed the success line")
			}
		})
	}
}
