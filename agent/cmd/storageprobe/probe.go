package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Exit codes. A bench script branches on these, so they distinguish the four
// outcomes that need different responses from an operator.
//
// exitUsage is 2 and not 1 for the reason rasputin-agent's dispatcher gives:
// a mistyped flag is not a storage failure, and a script that treats every
// non-zero exit as "the disk refused" must not be able to reach that
// conclusion from a typo.
const (
	// exitOK — the verb did what was asked.
	exitOK = 0
	// exitFailed — the backend refused, or the work failed.
	exitFailed = 1
	// exitUsage — the command line was wrong. Nothing was attempted.
	exitUsage = 2
	// exitNoBackend — the real backend is unavailable on this machine and no
	// fixture was substituted. Fixed by changing the image, not the command.
	exitNoBackend = 3
	// exitNegative — the verb ran and the answer is no: inspect found nothing
	// present, or the data sweep skipped a disk. Distinct from exitFailed,
	// because "the target is unplugged" is an answer and not a failure — but a
	// script that deploys onto a data disk still must not read it as yes.
	exitNegative = 4
)

// probeEnv is the outside world, as a value, so a test drives the real
// dispatcher with a backend of its choosing rather than reaching for a
// package-level variable it then has to put back.
type probeEnv struct {
	stdout io.Writer
	stderr io.Writer
	// open resolves and constructs the backend. The seam exists for one test
	// that cannot otherwise be written: "this machine is missing wipefs, so
	// refuse" is not reproducible on a laptop that has wipefs, and it is the
	// single most important behaviour in this command.
	open func(choice, stateDir string) (storage.Backend, backendChoice, error)
}

// dispatch is the whole command line. Returns a process exit code and writes
// nothing to os.Stdout/os.Stderr directly.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return dispatchWith(ctx, args, probeEnv{stdout: stdout, stderr: stderr, open: openBackend})
}

func dispatchWith(ctx context.Context, args []string, env probeEnv) int {
	// No arguments runs `enumerate`, which is read-only and mutates nothing.
	// The default being the SAFE verb is not a convenience — it is so that
	// there is no arrangement of this command line, including the empty one,
	// that formats a disk without the word "claim" in it.
	if len(args) == 0 {
		args = []string{"enumerate"}
	}
	switch args[0] {
	case "-h", "--help", "help":
		printUsage(env.stdout)
		return exitOK
	}
	verb, rest := "enumerate", args
	if !strings.HasPrefix(args[0], "-") {
		verb, rest = args[0], args[1:]
	}
	switch verb {
	case "enumerate":
		return runEnumerate(ctx, env, rest)
	case "claim":
		return runClaim(ctx, env, rest)
	case "mount-data":
		return runMountData(ctx, env, rest)
	case "inspect":
		return runInspect(ctx, env, rest)
	default:
		fmt.Fprintf(env.stderr, "storageprobe: unknown command %q\n\n", verb)
		printUsage(env.stderr)
		return exitUsage
	}
}

// commonFlags are the four every verb takes. Bound per-verb rather than parsed
// globally, so `storageprobe claim --help` prints the flags that apply to a
// claim and not a union of everything.
type commonFlags struct {
	json     bool
	backend  string
	stateDir string
	timeout  time.Duration
}

// bind attaches the common flags to fs. budget is the verb's own work budget
// from proto — the SAME number the agent gets over the bus, so a claim that
// runs long here runs long there too and a bench result transfers.
func (c *commonFlags) bind(fs *flag.FlagSet, budget time.Duration) {
	fs.BoolVar(&c.json, "json", false, "emit the report as JSON instead of text")
	fs.StringVar(&c.backend, "backend", "", "backend: blockdev (default, and the only one autodetected) or mock (fixtures, must be asked for by name)")
	fs.StringVar(&c.stateDir, "state-dir", "storageprobe-state", "state directory; only the mock writes here (its simulated machine), the real backend's answers come off the platter")
	fs.DurationVar(&c.timeout, "timeout", budget, "hard deadline for the work")
}

// deadline bounds the verb. Every verb gets one, defaulted from proto's budget
// for that verb, because the failure being bounded is a mount(8) or an mkfs
// against a disk that has begun to fail and answers slowly or not at all.
//
// The deadline bounds I/O and drives no state: when it fires, the verb gives
// up and says which one it was, and nothing about the disk is inferred from
// the fact that it ran out. Note that a claim's default is fifteen minutes for
// a real reason — wipefs + sfdisk + mkfs + a udev settle on a spinning 8 TB
// archive drive — so a claim that appears to hang has probably not.
func (c commonFlags) deadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.timeout)
}

// parse runs the flag set and maps its outcome onto our exit codes. flag's own
// ErrHelp is a successful help request, not a usage error.
func parse(fs *flag.FlagSet, args []string) (int, bool) {
	switch err := fs.Parse(args); {
	case err == nil:
		if fs.NArg() > 0 {
			// Every verb here takes flags only. A stray positional is almost
			// always a flag whose value drifted off it, and on the claim path
			// that is a device path the parser silently ignored.
			fmt.Fprintf(fs.Output(), "storageprobe %s: unexpected argument %q — every option on this command is a named flag\n", fs.Name(), fs.Arg(0))
			return exitUsage, false
		}
		return exitOK, true
	case errors.Is(err, flag.ErrHelp):
		return exitOK, false
	default:
		return exitUsage, false
	}
}

// openFor resolves the backend and reports the refusal itself, so each verb's
// body is the verb and not four lines of the same error handling.
func openFor(env probeEnv, c commonFlags) (storage.Backend, backendChoice, int, bool) {
	backend, sel, err := env.open(c.backend, c.stateDir)
	if err != nil {
		fmt.Fprintf(env.stderr, "storageprobe: %v\n", err)
		switch {
		case errors.Is(err, errNoTooling):
			return nil, sel, exitNoBackend, false
		case errors.Is(err, errBadBackend):
			return nil, sel, exitUsage, false
		default:
			return nil, sel, exitFailed, false
		}
	}
	return backend, sel, exitOK, true
}

// ---------------------------------------------------------------------------

func runEnumerate(ctx context.Context, env probeEnv, args []string) int {
	fs := flag.NewFlagSet("enumerate", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var c commonFlags
	c.bind(fs, proto.StorageEnumerateWork)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	backend, sel, code, ok := openFor(env, c)
	if !ok {
		return code
	}
	ctx, cancel := c.deadline(ctx)
	defer cancel()

	ack, err := backend.Enumerate(ctx)
	if err != nil {
		fmt.Fprintf(env.stderr, "storageprobe enumerate: %v\n", err)
		return exitFailed
	}
	rep := newEnumerateReport(ack, sel)
	if err := emit(env.stdout, c.json, rep, func(w io.Writer) error { return renderEnumerateText(w, rep) }); err != nil {
		fmt.Fprintf(env.stderr, "storageprobe enumerate: write report: %v\n", err)
		return exitFailed
	}
	return exitOK
}

func runClaim(ctx context.Context, env probeEnv, args []string) int {
	fs := flag.NewFlagSet("claim", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var c commonFlags
	c.bind(fs, proto.StorageClaimWork)
	device := fs.String("device", "", "whole disk to FORMAT, exactly as `enumerate` reported it")
	purpose := fs.String("purpose", "", "what the disk is for: "+strings.Join(purposeNames(), " | "))
	fingerprint := fs.String("fingerprint", "", "the fingerprint `enumerate` printed for that disk (required; see the help)")
	label := fs.String("label", "", "operator-facing name written into the marker (not the filesystem label, which the purpose decides)")
	clusterID := fs.String("cluster-id", "", "cluster id stamped into the marker, so the disk records which cluster wrote it")
	if code, ok := parse(fs, args); !ok {
		return code
	}

	// These three are checked here so a mistyped command line is a usage error
	// rather than a trip to the backend. They are NOT the guard: the guard is
	// the agent's, runs inside Claim against live hardware immediately before
	// anything is written, and is unaffected by anything decided out here.
	if strings.TrimSpace(*device) == "" {
		fmt.Fprintln(env.stderr, "storageprobe claim: --device is required")
		return exitUsage
	}
	if strings.TrimSpace(*fingerprint) == "" {
		fmt.Fprintln(env.stderr, "storageprobe claim: --fingerprint is required. Empty is not a wildcard and never will be —")
		fmt.Fprintln(env.stderr, "  run `storageprobe enumerate`, read the protected set, and copy the fingerprint of the disk you meant.")
		return exitUsage
	}
	if _, err := proto.StoragePurposeSpecFor(proto.StoragePurpose(strings.TrimSpace(*purpose))); err != nil {
		fmt.Fprintf(env.stderr, "storageprobe claim: --purpose: %v\n", err)
		return exitUsage
	}

	backend, sel, code, ok := openFor(env, c)
	if !ok {
		return code
	}
	ctx, cancel := c.deadline(ctx)
	defer cancel()

	// The §4.6 custody fields (keyId, keyAlg, publicKey and the two wrappings)
	// are deliberately absent from this command line and from the struct
	// below. They are produced in the operator's BROWSER during backup setup
	// and there is nothing on a bench node that can mint them, so a flag for
	// them would only let an operator type a plausible-looking string onto a
	// platter. The consequence is stated in the help: a backup target claimed
	// by this tool exercises the format path and is not a production backup
	// disk. A data claim is unaffected — those fields are refused on it.
	ack, err := backend.Claim(ctx, proto.StorageClaimCmd{
		DevicePath:  strings.TrimSpace(*device),
		Fingerprint: strings.TrimSpace(*fingerprint),
		Purpose:     proto.StoragePurpose(strings.TrimSpace(*purpose)),
		Label:       *label,
		ClusterID:   *clusterID,
	})
	if err != nil {
		fmt.Fprintf(env.stderr, "storageprobe claim: REFUSED: %v\n", err)
		return exitFailed
	}
	rep, err := newClaimReport(ack, sel)
	if err != nil {
		// The disk may well have been formatted — Claim returned no error. But
		// this command cannot describe what happened, and saying "claim OK"
		// with fields it does not have would be the lie a bench tool exists
		// not to tell. Re-enumerate: a claimed disk is self-describing.
		fmt.Fprintf(env.stderr, "storageprobe claim: the claim returned no error but %v\n", err)
		fmt.Fprintln(env.stderr, "  The disk may have been formatted. Run `storageprobe enumerate` — a claimed disk carries its own marker.")
		return exitFailed
	}
	verifyClaimedMarker(&rep)
	if err := emit(env.stdout, c.json, rep, func(w io.Writer) error { return renderClaimText(w, rep) }); err != nil {
		fmt.Fprintf(env.stderr, "storageprobe claim: write report: %v\n", err)
		return exitFailed
	}
	if rep.MarkerVerified == "NO" {
		return exitNegative
	}
	return exitOK
}

func runMountData(ctx context.Context, env probeEnv, args []string) int {
	fs := flag.NewFlagSet("mount-data", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var c commonFlags
	// The sweep enumerates and then mounts, so its budget is both — the same
	// sum the agent gives it at startup in cmd/rasputin-agent/main.go.
	c.bind(fs, proto.StorageEnumerateWork+proto.StorageMountWork)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	backend, sel, code, ok := openFor(env, c)
	if !ok {
		return code
	}
	ctx, cancel := c.deadline(ctx)
	defer cancel()

	mounts, err := backend.MountClaimedData(ctx)
	if err != nil {
		// The error return means the sweep could not LOOK. Per-disk outcomes
		// are never errors — §6.3's first bullet — and ride in the mounts.
		fmt.Fprintf(env.stderr, "storageprobe mount-data: could not look for claimed data disks (none were mounted): %v\n", err)
		return exitFailed
	}
	rep := newDataMountReport(mounts, sel)
	if err := emit(env.stdout, c.json, rep, func(w io.Writer) error { return renderDataMountText(w, rep) }); err != nil {
		fmt.Fprintf(env.stderr, "storageprobe mount-data: write report: %v\n", err)
		return exitFailed
	}
	if len(rep.Skipped) > 0 {
		// A skip is not fatal to the AGENT and must never be — that is the
		// contract. It is not fatal here either; it is reported, and the exit
		// code says so, because the question a bench run is asking is "did the
		// disk come up" and a script needs to be able to branch on the answer.
		return exitNegative
	}
	return exitOK
}

func runInspect(ctx context.Context, env probeEnv, args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var c commonFlags
	c.bind(fs, proto.StorageInspectWork)
	partUUID := fs.String("part-uuid", "", "the partition UUID a claim minted — the only identifier a claimed target has")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if strings.TrimSpace(*partUUID) == "" {
		fmt.Fprintln(env.stderr, "storageprobe inspect: --part-uuid is required. A claimed target is addressed by partition UUID and never by device path or label.")
		return exitUsage
	}
	backend, sel, code, ok := openFor(env, c)
	if !ok {
		return code
	}
	ctx, cancel := c.deadline(ctx)
	defer cancel()

	ack, err := backend.Inspect(ctx, strings.TrimSpace(*partUUID))
	if err != nil {
		fmt.Fprintf(env.stderr, "storageprobe inspect: %v\n", err)
		return exitFailed
	}
	rep := newInspectReport(ack, sel)
	if err := emit(env.stdout, c.json, rep, func(w io.Writer) error { return renderInspectText(w, rep) }); err != nil {
		fmt.Fprintf(env.stderr, "storageprobe inspect: write report: %v\n", err)
		return exitFailed
	}
	if !rep.Present || !rep.OK {
		return exitNegative
	}
	return exitOK
}

// emit picks the renderer. One place, so a verb cannot grow a JSON path that
// its text path does not have.
func emit(w io.Writer, asJSON bool, report any, text func(io.Writer) error) error {
	if asJSON {
		return renderJSON(w, report)
	}
	return text(w)
}

// purposeNames is proto's purpose list as strings, read from
// AllStoragePurposes so a purpose added there shows up in this help without
// anyone remembering to add it.
func purposeNames() []string {
	out := make([]string, 0, len(proto.AllStoragePurposes))
	for _, p := range proto.AllStoragePurposes {
		out = append(out, string(p))
	}
	return out
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `storageprobe — drive the agent's storage backend directly against this machine's disks.

A BENCH TOOL. It is not installed in the OS image: cross-compile it and copy it
to a node for a run (note the -O, busybox has no sftp-server):

  cd agent
  GOOS=linux GOARCH=arm64 go build -o /tmp/storageprobe ./cmd/storageprobe   # Pi 5
  GOOS=linux GOARCH=amd64 go build -o /tmp/storageprobe ./cmd/storageprobe   # n100, CWWK
  scp -O /tmp/storageprobe root@<node>.local:/tmp/

Usage:
  storageprobe [command] [options]      (no command runs 'enumerate')

Commands:
  enumerate
        List every candidate whole disk, PROTECTED ONES FIRST, each with the
        reason it is protected and the fingerprint 'claim' requires. Read-only.
        On a machine with two identical NVMes the protected block is the ONLY
        thing that distinguishes the boot medium from the spare.
  claim --device <path> --purpose <%s> --fingerprint <fp> [--label ..] [--cluster-id ..]
        ⚠️ DESTRUCTIVE. Wipes, repartitions and formats the disk.
        --fingerprint is REQUIRED and is the guardrail. It is a hash over the
        disk's stable identity and its CURRENT partition table, re-computed by
        the agent against live hardware immediately before anything is written,
        so it does two jobs: it forces you to run 'enumerate' and look at the
        protected set first, and it makes a stale or replayed invocation
        fail closed on its own — the format rewrites the partition table the
        hash covers, so the same command run twice is refused the second time.
        An empty fingerprint is a refusal and never a wildcard.
        This tool cannot mint §4.6 backup-key custody (that happens in the
        operator's browser), so a 'backup' target claimed here exercises the
        format path and is NOT a production backup disk.
  mount-data
        Run the §6.5 startup sweep (MountClaimedData) and report every claimed
        data disk it mounted and every one it skipped, with the reason. Skips
        are never fatal to a node — a missing data disk must not make one
        unbootable — but this command exits %d when there is one.
  inspect --part-uuid <uuid>
        Read a claimed target's marker and free space. Addressed by partition
        UUID because that is the only identifier a claimed target has.

Options (all commands):
  --json                emit the report as JSON instead of text
  --backend <name>      blockdev (default) or mock
  --state-dir <path>    where the mock keeps its simulated machine
  --timeout <duration>  hard deadline for the work; defaults to that verb's
                        proto budget (enumerate %s, claim %s, mount-data %s,
                        inspect %s). A claim's fifteen minutes is real: wipefs +
                        sfdisk + mkfs + a udev settle on a spinning 8 TB drive
                        takes that long, so a claim that looks hung usually is
                        not. Do not interrupt one.

The mock is NEVER autodetected and RASPUTIN_STORAGE_BACKEND is deliberately not
read here. When the real backend's util-linux tooling is incomplete this command
REFUSES and names the missing tool (exit %d) rather than substituting fixtures:
on 2026-09-01 a missing 'wipefs' made a real controlplane offer three disks that
did not exist for a destructive format. Ask for '--backend mock' by name and
every line of output is stamped as a fixture.

Exit codes:
  %d  the verb did what was asked
  %d  the backend refused, or the work failed
  %d  the command line was wrong; nothing was attempted
  %d  the real backend is unavailable here and no fixture was substituted
  %d  the verb ran and the answer is no (inspect: not present; mount-data: a disk was skipped)

Contract: projects/rasputin/design/storage.md §4.8 and §6 in the geekdojo-brain
(geekdojo/geekdojo-brain#302). Backend: agent/internal/storage.
`,
		strings.Join(purposeNames(), "|"), exitNegative,
		proto.StorageEnumerateWork, proto.StorageClaimWork,
		proto.StorageEnumerateWork+proto.StorageMountWork, proto.StorageInspectWork,
		exitNoBackend,
		exitOK, exitFailed, exitUsage, exitNoBackend, exitNegative)
}
