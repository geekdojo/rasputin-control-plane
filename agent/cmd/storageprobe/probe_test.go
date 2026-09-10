package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// These drive the REAL dispatcher — the same flag sets, the same refusals, the
// same renderers a bench run gets — against storage.MockBackend rather than an
// invented fake. The mock is behaviourally mirrored to the real backend (its
// refusal order matches blockdev.Claim line for line, and it derives Protected
// from a simulated mount table rather than from a flag), so what these prove
// about the command's handling of a refusal is a thing that also holds on a
// disk.

// probe runs the command with the mock backend rooted at a per-test temp dir.
func probe(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return probeIn(t, t.TempDir(), args...)
}

// probeIn is probe with an explicit state dir, for the sequences that need one
// invocation to see what the last one did.
func probeIn(t *testing.T, stateDir string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	full := append([]string{}, args...)
	full = append(full, "--backend", "mock", "--state-dir", stateDir)
	code = dispatch(context.Background(), full, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// The default is the READ-ONLY verb, and that is a safety property rather than
// a convenience: there must be no arrangement of this command line, the empty
// one included, that formats a disk without the word "claim" in it.
func TestDispatch_NoArgumentsEnumerates(t *testing.T) {
	var out, errBuf bytes.Buffer
	// No --backend, so this takes the autodetect path. On a machine with
	// util-linux that enumerates; on one without it refuses. Both are fine —
	// what must never happen is a destructive verb or a fixture list.
	code := dispatch(context.Background(), nil, &out, &errBuf)
	if code != exitOK && code != exitNoBackend && code != exitFailed {
		t.Fatalf("bare invocation exited %d", code)
	}
	if strings.Contains(out.String(), "CLAIMED") {
		t.Fatal("a bare invocation claimed a disk")
	}
	if code == exitNoBackend && !strings.Contains(errBuf.String(), "NOT substitute the mock") {
		t.Errorf("the no-tooling refusal does not say it declined to use fixtures: %s", errBuf.String())
	}
}

func TestDispatch_Help(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		var out, errBuf bytes.Buffer
		if code := dispatch(context.Background(), []string{arg}, &out, &errBuf); code != exitOK {
			t.Errorf("%s: exit = %d, want %d", arg, code, exitOK)
		}
		for _, want := range []string{
			"enumerate", "claim", "mount-data", "inspect",
			// The fingerprint rationale is the load-bearing paragraph: an
			// operator who does not understand why it is required will look
			// for a way around it.
			"--fingerprint is REQUIRED and is the guardrail",
			"fail closed",
			// The two operational facts that cost a round trip on the bench.
			"scp -O", "GOOS=linux",
			// The mock rule.
			"NEVER autodetected",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: help does not mention %q", arg, want)
			}
		}
	}
}

func TestDispatch_UnknownCommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := dispatch(context.Background(), []string{"frobnicate"}, &out, &errBuf)
	// 2, not 1: a script must not be able to read a typo as "the disk refused".
	if code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "frobnicate") {
		t.Errorf("the error does not name the command typed: %s", errBuf.String())
	}
}

// A leading flag with no verb still runs enumerate, so `storageprobe --json`
// works the way it reads.
func TestDispatch_LeadingFlagRunsEnumerate(t *testing.T) {
	code, stdout, stderr := probe(t, "--json")
	if code != exitOK {
		t.Fatalf("exit = %d (%s)", code, stderr)
	}
	var rep enumerateReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout is not the enumerate report as JSON: %v\n%s", err, stdout)
	}
	if rep.Backend != "mock" {
		t.Errorf("backend = %q, want mock", rep.Backend)
	}
}

// The headline output. The mock's seeded machine is a controlplane whose boot
// NVMe and spare NVMe are the same vendor family and differ only by the mount
// table, which is precisely the case the protected block exists for.
func TestEnumerate_ProtectedSetIsTheHeadline(t *testing.T) {
	code, stdout, stderr := probe(t)
	if code != exitOK {
		t.Fatalf("exit = %d (%s)", code, stderr)
	}
	protectedIdx := strings.Index(stdout, "PROTECTED (1)")
	claimableIdx := strings.Index(stdout, "CLAIMABLE (")
	if protectedIdx < 0 || claimableIdx < 0 {
		t.Fatalf("output has no protected/claimable blocks:\n%s", stdout)
	}
	if protectedIdx > claimableIdx {
		t.Error("the claimable disks are printed before the protected ones")
	}
	// The reason, verbatim, not a boolean.
	if !strings.Contains(stdout, "holds the mounted persistent partition (/var/lib/rasputin)") {
		t.Errorf("the protection reason is not printed verbatim:\n%s", stdout)
	}
	// The fingerprint is on the listing because claim requires it and this is
	// where an operator copies it from.
	if !strings.Contains(stdout, "fingerprint: ") {
		t.Errorf("no fingerprint in the listing:\n%s", stdout)
	}
	// A fixture run says so, first.
	if !strings.HasPrefix(stdout, "!! "+fixtureBanner) {
		t.Errorf("a mock run does not open with the fixture banner:\n%s", stdout)
	}
}

// The whole destructive path, end to end: enumerate, claim with the fingerprint
// it printed, and then the two refusals that make the guardrail real.
func TestClaim_EndToEndAndTheRefusalsThatFollow(t *testing.T) {
	stateDir := t.TempDir()

	code, stdout, stderr := probeIn(t, stateDir, "enumerate", "--json")
	if code != exitOK {
		t.Fatalf("enumerate exit = %d (%s)", code, stderr)
	}
	var listing enumerateReport
	if err := json.Unmarshal([]byte(stdout), &listing); err != nil {
		t.Fatalf("enumerate --json: %v", err)
	}
	if len(listing.Protected) != 1 || len(listing.Claimable) < 1 {
		t.Fatalf("unexpected seeded machine: %d protected, %d claimable", len(listing.Protected), len(listing.Claimable))
	}
	spare := listing.Claimable[0]
	boot := listing.Protected[0]

	// (1) The claim itself.
	code, stdout, stderr = probeIn(t, stateDir, "claim", "--json",
		"--device", spare.DevicePath, "--purpose", "data",
		"--fingerprint", spare.Fingerprint, "--label", "bench media", "--cluster-id", "e3bench")
	if code != exitOK {
		t.Fatalf("claim exit = %d (%s)", code, stderr)
	}
	var claimed claimReport
	if err := json.Unmarshal([]byte(stdout), &claimed); err != nil {
		t.Fatalf("claim --json: %v\n%s", err, stdout)
	}
	// The ground truth, all of it. A claim that cannot report these is not
	// reported as a claim at all — see newClaimReport.
	if claimed.PartUUID == "" {
		t.Error("no partUuid on a successful claim")
	}
	if claimed.GPTName != proto.StorageDataPartName {
		t.Errorf("gptName = %q, want %q", claimed.GPTName, proto.StorageDataPartName)
	}
	if claimed.FSLabel != proto.StorageDataLabel {
		t.Errorf("fsLabel = %q, want %q", claimed.FSLabel, proto.StorageDataLabel)
	}
	if claimed.MountOptions != proto.StorageDataMountOptions {
		t.Errorf("mountOptions = %q, want %q", claimed.MountOptions, proto.StorageDataMountOptions)
	}
	if !strings.HasSuffix(claimed.MarkerPath, proto.StorageDataMarkerFile) {
		t.Errorf("markerPath = %q, want it to end in %q", claimed.MarkerPath, proto.StorageDataMarkerFile)
	}
	if claimed.MountPath == "" {
		t.Error("no mountPath on a successful claim")
	}
	// §6.3's check, applied to this command's own work: the marker was read
	// back off the filesystem that was mounted, not merely named.
	if !strings.HasPrefix(claimed.MarkerVerified, "yes") {
		t.Errorf("markerVerified = %q, want the marker read back", claimed.MarkerVerified)
	}
	if claimed.Fingerprint == spare.Fingerprint {
		t.Error("the post-format fingerprint equals the pre-format one; the replay guard rests on it changing")
	}

	// (2) Replay with the same fingerprint. The format rewrote the partition
	// table the hash covers, so the identical command fails closed on its own
	// with no dedup state anywhere.
	code, _, stderr = probeIn(t, stateDir, "claim",
		"--device", spare.DevicePath, "--purpose", "data", "--fingerprint", spare.Fingerprint)
	if code != exitFailed {
		t.Errorf("a replayed claim exited %d, want %d", code, exitFailed)
	}
	if !strings.Contains(stderr, "fingerprint") {
		t.Errorf("the replay refusal does not mention the fingerprint: %s", stderr)
	}

	// (3) The boot medium, with its own current fingerprint, so the ONLY thing
	// that can refuse it is the protected set.
	code, _, stderr = probeIn(t, stateDir, "claim",
		"--device", boot.DevicePath, "--purpose", "data", "--fingerprint", boot.Fingerprint)
	if code != exitFailed {
		t.Errorf("claiming the boot medium exited %d, want %d", code, exitFailed)
	}
	if !strings.Contains(stderr, "refusing to touch the device holding the mounted boot/persistent partitions") {
		t.Errorf("the refusal does not name the protection: %s", stderr)
	}
}

// The fingerprint requirement, refused before the backend is even opened, so
// the operator is told what to do rather than handed a wire refusal.
func TestClaim_UsageRefusals(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no device",
			args:    []string{"claim", "--purpose", "data", "--fingerprint", "fp"},
			wantErr: "--device is required",
		},
		{
			name: "no fingerprint",
			args: []string{"claim", "--device", "/dev/nvme1n1", "--purpose", "data"},
			// Empty is not a wildcard, and the message says where to get one.
			wantErr: "Empty is not a wildcard",
		},
		{
			name:    "an empty purpose is not defaulted to backup here",
			args:    []string{"claim", "--device", "/dev/nvme1n1", "--fingerprint", "fp"},
			wantErr: "--purpose",
		},
		{
			name:    "a purpose this build does not know",
			args:    []string{"claim", "--device", "/dev/nvme1n1", "--purpose", "scratch", "--fingerprint", "fp"},
			wantErr: "unrecognised storage purpose",
		},
		{
			// A stray positional is usually a flag whose value drifted off it,
			// and on this path that is a device path the parser ignored.
			name:    "a stray positional argument",
			args:    []string{"claim", "--device", "/dev/nvme1n1", "--purpose", "data", "--fingerprint", "fp", "oops"},
			wantErr: "unexpected argument",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := probe(t, tc.args...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitUsage, stderr)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr does not mention %q: %s", tc.wantErr, stderr)
			}
			if stdout != "" {
				t.Errorf("a usage refusal wrote to stdout: %s", stdout)
			}
		})
	}
}

// An empty purpose is a usage error rather than the wire default. The
// empty-means-backup rule on StorageClaimCmd.Purpose is compatibility for an
// api that predates §6; a human typing a claim on a bench node has no such
// history, and silently formatting a disk as a backup target because they
// forgot a flag is the outcome §4.8 exists to prevent.
func TestClaim_EmptyPurposeIsNotSilentlyBackup(t *testing.T) {
	_, _, stderr := probe(t, "claim", "--device", "/dev/nvme1n1", "--fingerprint", "fp")
	if strings.Contains(strings.ToLower(stderr), "defaulting") {
		t.Errorf("an empty purpose was defaulted: %s", stderr)
	}
}

func TestMountData(t *testing.T) {
	stateDir := t.TempDir()

	// An unclaimed machine: the sweep looks, finds nothing, and says so. That
	// is not a failure — §6.3's first bullet — so it is exit 0.
	code, stdout, stderr := probeIn(t, stateDir, "mount-data")
	if code != exitOK {
		t.Fatalf("mount-data on an unclaimed machine exited %d (%s)", code, stderr)
	}
	if !strings.Contains(stdout, "found no claimed data disk") {
		t.Errorf("an empty sweep said nothing:\n%s", stdout)
	}

	// Claim one, then sweep again.
	spare := firstClaimable(t, stateDir)
	if code, _, stderr = probeIn(t, stateDir, "claim",
		"--device", spare.DevicePath, "--purpose", "data", "--fingerprint", spare.Fingerprint); code != exitOK {
		t.Fatalf("claim exited %d (%s)", code, stderr)
	}
	code, stdout, stderr = probeIn(t, stateDir, "mount-data", "--json")
	if code != exitOK {
		t.Fatalf("mount-data exited %d (%s)", code, stderr)
	}
	var rep dataMountReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("mount-data --json: %v\n%s", err, stdout)
	}
	if len(rep.Mounted) != 1 || len(rep.Skipped) != 0 {
		t.Fatalf("mounted=%d skipped=%d, want 1 and 0", len(rep.Mounted), len(rep.Skipped))
	}
	if !strings.HasSuffix(rep.Mounted[0].MarkerPath, proto.StorageDataMarkerFile) {
		t.Errorf("markerPath = %q", rep.Mounted[0].MarkerPath)
	}
}

// A skipped disk is never fatal to a node — that is the contract — but this is
// a bench probe, and a script asking "did the disk come up" needs an answer it
// can branch on. So a skip is reported, loudly, and exits exitNegative.
func TestMountData_ASkipIsReportedAndExitsNegative(t *testing.T) {
	stateDir := t.TempDir()
	spare := firstClaimable(t, stateDir)

	// Claim first, with no fail mode set, so there is a data disk to sweep.
	if code, _, stderr := probeIn(t, stateDir, "claim",
		"--device", spare.DevicePath, "--purpose", "data", "--fingerprint", spare.Fingerprint); code != exitOK {
		t.Fatalf("claim exited %d (%s)", code, stderr)
	}
	// The mock's own failure injection, mirroring the updater's. The sweep
	// will now fail to mount the disk it just found.
	t.Setenv("RASPUTIN_STORAGE_FAIL_MODE", "mount")

	code, stdout, _ := probeIn(t, stateDir, "mount-data")
	if code != exitNegative {
		t.Fatalf("a sweep with a skipped disk exited %d, want %d", code, exitNegative)
	}
	skippedIdx := strings.Index(stdout, "SKIPPED")
	mountedIdx := strings.Index(stdout, "MOUNTED:")
	if skippedIdx < 0 || mountedIdx < 0 || skippedIdx > mountedIdx {
		t.Errorf("the skipped disk is not printed above the mounted ones:\n%s", stdout)
	}
	if !strings.Contains(stdout, "will not find their data") {
		t.Errorf("a skip does not say what it costs:\n%s", stdout)
	}
}

func TestInspect(t *testing.T) {
	stateDir := t.TempDir()
	spare := firstClaimable(t, stateDir)

	code, stdout, stderr := probeIn(t, stateDir, "claim", "--json",
		"--device", spare.DevicePath, "--purpose", "data", "--fingerprint", spare.Fingerprint, "--cluster-id", "e3bench")
	if code != exitOK {
		t.Fatalf("claim exited %d (%s)", code, stderr)
	}
	var claimed claimReport
	if err := json.Unmarshal([]byte(stdout), &claimed); err != nil {
		t.Fatalf("claim --json: %v", err)
	}

	t.Run("a claimed target", func(t *testing.T) {
		code, stdout, stderr := probeIn(t, stateDir, "inspect", "--json", "--part-uuid", claimed.PartUUID)
		if code != exitOK {
			t.Fatalf("inspect exited %d (%s)", code, stderr)
		}
		var rep inspectReport
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
			t.Fatalf("inspect --json: %v", err)
		}
		if !rep.Present || !rep.OK {
			t.Fatalf("present=%t ok=%t", rep.Present, rep.OK)
		}
		if rep.Purpose != proto.StoragePurposeData {
			t.Errorf("purpose = %q, want data", rep.Purpose)
		}
		if rep.DataSet == nil || rep.DataSet.ClusterID != "e3bench" {
			t.Errorf("the marker did not come back with the cluster that wrote it: %+v", rep.DataSet)
		}
	})

	t.Run("an unplugged target is an answer, not a failure, and still exits negative", func(t *testing.T) {
		code, stdout, _ := probeIn(t, stateDir, "inspect", "--part-uuid", "00000000-0000-0000-0000-000000000000")
		// exitNegative, not exitFailed: nothing went wrong, and a script that
		// deploys onto a data disk still must not read it as yes.
		if code != exitNegative {
			t.Fatalf("exit = %d, want %d", code, exitNegative)
		}
		if !strings.Contains(stdout, "NOT PRESENT") {
			t.Errorf("output does not say the target is absent:\n%s", stdout)
		}
	})

	t.Run("no part-uuid is a usage error", func(t *testing.T) {
		code, _, stderr := probeIn(t, stateDir, "inspect")
		if code != exitUsage {
			t.Errorf("exit = %d, want %d", code, exitUsage)
		}
		if !strings.Contains(stderr, "--part-uuid is required") {
			t.Errorf("stderr: %s", stderr)
		}
	})
}

// The behaviour that cannot be reproduced on a laptop with util-linux
// installed, and the most important one in this command: a machine whose block
// tooling is incomplete gets a refusal that names the tool, and no fixtures.
func TestDispatch_RefusesWhenTheRealBackendIsUnavailable(t *testing.T) {
	env := probeEnv{
		open: func(choice, stateDir string) (storage.Backend, backendChoice, error) {
			// What openBackend would do on an OS image that shipped without
			// wipefs — the 2026-09-01 e3bench incident.
			return nil, backendChoice{}, fmt.Errorf("%w: not on PATH: wipefs", errNoTooling)
		},
	}
	for _, verb := range []string{"enumerate", "mount-data"} {
		t.Run(verb, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			env.stdout, env.stderr = &out, &errBuf
			code := dispatchWith(context.Background(), []string{verb}, env)
			if code != exitNoBackend {
				t.Fatalf("exit = %d, want %d", code, exitNoBackend)
			}
			if !strings.Contains(errBuf.String(), "wipefs") {
				t.Errorf("the refusal does not name the missing tool: %s", errBuf.String())
			}
			if out.Len() != 0 {
				t.Errorf("a refused run wrote a report to stdout: %s", out.String())
			}
		})
	}
	t.Run("claim gets there too, after its own argument checks", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		env.stdout, env.stderr = &out, &errBuf
		code := dispatchWith(context.Background(), []string{
			"claim", "--device", "/dev/nvme1n1", "--purpose", "data", "--fingerprint", "fp"}, env)
		if code != exitNoBackend {
			t.Fatalf("exit = %d, want %d", code, exitNoBackend)
		}
	})
}

// An unusable --backend value is usage (2), not a backend failure (3): the
// machine may be perfectly capable and the operator merely mistyped.
func TestDispatch_UnknownBackendIsUsage(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := dispatch(context.Background(), []string{"enumerate", "--backend", "moc"}, &out, &errBuf)
	if code != exitUsage {
		t.Errorf("exit = %d, want %d (stderr: %s)", code, exitUsage, errBuf.String())
	}
}

// Every verb defaults its deadline to that verb's proto work budget, so a
// bench result transfers to the agent's own behaviour over the bus. Claim's
// fifteen minutes in particular is not a placeholder: wipefs + sfdisk + mkfs +
// a udev settle on a spinning 8 TB archive drive really does take that long.
func TestCommonFlags_DeadlineDefaultsToTheProtoBudget(t *testing.T) {
	tests := []struct {
		verb string
		want interface{ String() string }
	}{
		{"enumerate", proto.StorageEnumerateWork},
		{"claim", proto.StorageClaimWork},
		{"inspect", proto.StorageInspectWork},
	}
	for _, tc := range tests {
		if !strings.Contains(usageText(), tc.want.String()) {
			t.Errorf("%s: the help does not state its %s budget", tc.verb, tc.want)
		}
	}
	// And the deadline actually attaches.
	var c commonFlags
	c.timeout = proto.StorageClaimWork
	ctx, cancel := c.deadline(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("no deadline on the context")
	}

	// A zero timeout means "no deadline" rather than "expire immediately",
	// which is what an operator passing --timeout 0 to watch a slow disk
	// means.
	var unbounded commonFlags
	ctx2, cancel2 := unbounded.deadline(context.Background())
	defer cancel2()
	if _, ok := ctx2.Deadline(); ok {
		t.Error("--timeout 0 attached a deadline")
	}
}

func usageText() string {
	var b bytes.Buffer
	printUsage(&b)
	return b.String()
}

// firstClaimable enumerates the mock machine and returns a disk that is not in
// the protected set.
func firstClaimable(t *testing.T, stateDir string) proto.StorageCandidate {
	t.Helper()
	code, stdout, stderr := probeIn(t, stateDir, "enumerate", "--json")
	if code != exitOK {
		t.Fatalf("enumerate exited %d (%s)", code, stderr)
	}
	var rep enumerateReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("enumerate --json: %v", err)
	}
	if len(rep.Claimable) == 0 {
		t.Fatal("the seeded mock machine offers no claimable disk")
	}
	return rep.Claimable[0]
}
