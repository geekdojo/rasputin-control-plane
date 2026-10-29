package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/artifactsig"
	"github.com/geekdojo/rasputin-control-plane/logkit"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The agent is a daemon that both shipping units start with no arguments
// (rasputin-os: rasputin-agent.service; the firewall: /etc/init.d/rasputin-agent),
// and it is configured entirely through the environment. So until now it
// accepted no arguments at all — `rasputin-agent -h` printed nothing and
// started a daemon.
//
// This dispatcher exists for one operational reason: the MANUAL update path.
// The OTA path verifies the publisher signature itself, but an operator doing a
// hands-on sysupgrade over SSH — the documented recovery route on the firewall
// — had nothing on the box that could check one. The obvious answer,
// `openssl cms -verify`, is not available: OpenWrt's base image ships
// libopenssl but not the openssl CLI, and adding openssl-util spends rootfs
// bytes on the one image whose size is itself an open issue. The agent binary
// is already there, already carries the verification code, and already knows
// where the trust root is baked. See geekdojo/geekdojo-brain#154.
//
// It works identically on both surfaces: the trust root defaults to the path
// each image bakes it to, so nothing here is firewall-specific.

// dispatchCLI handles a one-shot command line. It returns handled=false when
// there are no arguments, which is the daemon path both units take.
func dispatchCLI(args []string, stdout, stderr io.Writer) (exitCode int, handled bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0, true
	case "-v", "--version", "version":
		fmt.Fprintln(stdout, AgentVersion)
		return 0, true
	case "verify-artifact":
		return runVerifyArtifact(args[1:], stdout, stderr), true
	case "seed":
		return runSeed(args[1:], stdout, stderr), true
	case "install-rootfs":
		return runInstallRootfs(args[1:], stdout, stderr, logkit.New(stderr, logkit.RedactSecrets()), newRootfsInstaller), true
	case "repair-slot-boot":
		return runRepairSlotBoot(args[1:], stdout, stderr, logkit.New(stderr, logkit.RedactSecrets()), newSlotRepairer), true
	default:
		fmt.Fprintf(stderr, "rasputin-agent: unknown command %q\n\n", args[0])
		printUsage(stderr)
		// 2, not 1: a usage error is not a verification failure, and a script
		// that treats every non-zero exit as "signature bad" should not be able
		// to reach that conclusion from a typo.
		return 2, true
	}
}

// printShortUsage is what an argument mistake gets. The full help is four
// screens; burying "expected exactly one artifact path" under it is how a
// terminal loses the actual error.
func printShortUsage(w io.Writer) {
	fmt.Fprint(w, `usage: rasputin-agent verify-artifact <artifact> [--sig <path>] [--trust-root <path>]
       rasputin-agent seed check <path> [--role <role>]
       rasputin-agent install-rootfs [--state-dir <dir>] <bundle-id>
       rasputin-agent repair-slot-boot
       rasputin-agent help
`)
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `rasputin-agent — the Rasputin node agent.

Usage:
  rasputin-agent                       run the agent daemon (how both images start it)
  rasputin-agent <command> [options]

Commands:
  verify-artifact <artifact> [options]
        Verify an update artifact's detached CMS signature against the
        publisher root CA baked into this image. Exits 0 only if the
        signature verifies and its chain is valid right now.
  seed check <path> [--role <role>]
        Read the enrollment seed at <path>, refuse it if it is unusable, and
        print a normalized, fully quoted copy on stdout for an image to
        source instead of sourcing the operator's file directly. Nothing is
        printed unless the seed is usable. Exits 1 on an unusable seed,
        naming the field and what to do about it.
  install-rootfs [--state-dir <dir>] <bundle-id>
        Firewall only. Verify and install <dir>/bundles/<bundle-id>.rootfs
        into the inactive slot and arm a trial boot of it. Writes nothing on
        the ESP but grubenv. Does not reboot. --state-dir defaults to the agent's
        updater state directory. Exits 1 if the install fails.
  repair-slot-boot
        Firewall only, run by the kernel-match guard at boot. Copy the running
        rootfs's bootx64.efi and grub.cfg onto the ESP where they differ, so
        GRUB boots the slot's own kernel, and re-arm its trial, or mark the
        slot bad if that cannot be done. Does not reboot. Exits 0
        when the caller should reboot, 3 when the ESP cannot be mounted.
  version
        Print the agent version and exit.
  help
        Print this message.

Options for seed check:
  --role <role>         Refuse the seed unless it names this role. An image
                        that can only be one thing passes its own.

Options for verify-artifact:
  --sig <path>          Detached signature to check.
                        Default: <artifact>.sig
  --trust-root <path>   Publisher root CA to verify the chain against.
                        Default: $RASPUTIN_TRUST_ROOT, or `+artifactsig.DefaultTrustRoot+`

The daemon itself takes no flags — it is configured through the environment,
which both shipping unit files set:

  RASPUTIN_NODE_ID          this node's id
  RASPUTIN_NODE_ROLE        controlplane | compute | firewall
  RASPUTIN_NATS_URL         control-plane bus URL
  RASPUTIN_CP_JOIN_TOKEN_FILE  file holding the bus join token, read on every
                            connect. The only token source on every role
                            (controlplane default:
                            /var/lib/rasputin/bus/agent.token)
  RASPUTIN_CLUSTER_ID       cluster name, used for <cluster-id>.local
  RASPUTIN_AGENT_STATE_DIR  agent state (updater bookkeeping)
  RASPUTIN_TRUST_ROOT       publisher root CA (see verify-artifact above)
  RASPUTIN_MESH_CA_BUNDLE   per-installation controlplane CA for tailscaled
  RASPUTIN_UPDATE_BACKEND   force an updater backend: rauc | openwrt-ab | mock
  RASPUTIN_STORAGE_BACKEND  force a backup-target backend: blockdev | mock

Every RASPUTIN_*_BACKEND autodetects a REAL backend from what this machine has.
"mock" is never autodetected — it is a development fixture and must be asked for
by name. A node whose real backend is unavailable disables that subsystem, names
the missing prerequisite in the log and reports it to the control plane; it does
not substitute fixture hardware. (A mock storage backend on real hardware once
offered three disks that did not exist for a destructive format — see
agent/internal/configfault.)

Further backend and bench overrides exist for development; they are read at the
point they are used rather than declared here, so the source is the only honest
list. Start with agent/cmd/rasputin-agent/main.go.
`)
}

func runVerifyArtifact(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-artifact", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sigPath := fs.String("sig", "", "detached signature path (default <artifact>.sig)")
	trustRoot := fs.String("trust-root", "", "publisher root CA (default $RASPUTIN_TRUST_ROOT)")
	fs.Usage = func() { printShortUsage(stderr) }

	// Go's flag package stops parsing at the first non-flag argument, so the
	// plain `verify-artifact <file> --trust-root <pem>` an operator types off a
	// runbook would silently leave --trust-root unparsed and fall back to the
	// baked default. Parse-take-a-positional-reparse accepts flags on either
	// side of the artifact, which is what every other tool on the box does.
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "rasputin-agent verify-artifact: expected exactly one artifact path")
		printShortUsage(stderr)
		return 2
	}
	artifact := positional[0]
	if *sigPath == "" {
		*sigPath = artifactsig.SigPathFor(artifact)
	}
	if *trustRoot == "" {
		*trustRoot = artifactsig.TrustRootPath()
	}

	res, err := artifactsig.Verify(artifact, *sigPath, *trustRoot)
	if err != nil {
		// One line, on stderr, naming what failed — this is read off an SSH
		// session in the middle of a recovery, not out of a log aggregator.
		fmt.Fprintf(stderr, "SIGNATURE INVALID: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "signature OK: %s\n", filepath.Base(artifact))
	fmt.Fprintf(stdout, "  signer:     %s\n", res.Signer)
	fmt.Fprintf(stdout, "  issued by:  %s\n", res.Issuer)
	fmt.Fprintf(stdout, "  expires:    %s\n", res.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(stdout, "  %s:     %s\n", res.DigestAlg, res.DigestHex)
	fmt.Fprintf(stdout, "  trust root: %s\n", *trustRoot)
	return 0
}

// exitCLI is separated so main() reads as one line and tests can drive
// dispatchCLI directly without a process exit.
func exitCLI() {
	if code, handled := dispatchCLI(os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
}

// ---- firewall slot verbs (geekdojo/geekdojo-brain#888) ------------------------

// rootfsInstaller is the backend as install-rootfs uses it.
type rootfsInstaller interface {
	Precheck(ctx context.Context) (*proto.UpdatePrecheckAck, error)
	ArtifactPath(bundleID string) (string, error)
	Install(ctx context.Context, bundleID, localPath string, slot proto.UpdateSlot, progress func(string, int)) (string, error)
}

// slotRepairer is the backend as repair-slot-boot uses it.
type slotRepairer interface {
	RepairRunningSlot() (updater.RepairOutcome, error)
}

// errNoDownload is the trust source of a verb that never downloads: a backend
// that tried would be refused rather than handed a default TLS config.
func errNoDownload() (*tls.Config, error) {
	return nil, errors.New("this command does not download, so it has no download trust")
}

// newRootfsInstaller is install-rootfs's composition root.
func newRootfsInstaller(stateDir string, logger *slog.Logger) (rootfsInstaller, error) {
	media, err := updater.NewOpenWrtBootMedia(logger)
	if err != nil {
		return nil, err
	}
	return updater.NewOpenWrtABBackend(stateDir, errNoDownload, media, updater.UnixModuleLoader{},
		updater.ProcFilesystems{}, logger)
}

// newSlotRepairer is repair-slot-boot's composition root. It takes no state
// directory: the repair runs on a boot whose /overlay may be RAM-only or
// read-only, and needs no bundle store (F-888-07).
func newSlotRepairer(logger *slog.Logger) (slotRepairer, error) {
	media, err := updater.NewOpenWrtBootMedia(logger)
	if err != nil {
		return nil, err
	}
	return updater.NewOpenWrtSlotRepairer(media, updater.UnixModuleLoader{}, updater.ProcFilesystems{}, logger)
}

// runInstallRootfs installs a bundle already in the bundle store into the
// inactive slot, exactly as the OTA's install step does, without the bus and
// without a reboot. It is the seam the firewall's update smoke test drives.
func runInstallRootfs(args []string, stdout, stderr io.Writer, logger *slog.Logger,
	build func(stateDir string, logger *slog.Logger) (rootfsInstaller, error)) int {
	fs := flag.NewFlagSet("install-rootfs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "updater state directory (default: the agent's)")
	fs.Usage = func() { printShortUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "Name exactly one bundle id: the file name, without .rootfs, of an artifact in the bundle store.")
		printShortUsage(stderr)
		return 2
	}
	bundleID := fs.Arg(0)
	if *stateDir == "" {
		*stateDir = updaterStateDir(agentStateDir(envOr("RASPUTIN_NODE_ID", "node-dev")))
	}

	b, err := build(*stateDir, logger)
	if err != nil {
		fmt.Fprintf(stderr, "Could not set up the installer: %v.\n", err)
		return 1
	}
	artifact, err := b.ArtifactPath(bundleID)
	if err != nil {
		fmt.Fprintf(stderr, "The bundle id %q cannot name an artifact: %v.\n", bundleID, err)
		return 1
	}
	for _, f := range []struct{ path, what string }{
		{artifact, "artifact"},
		{artifactsig.SigPathFor(artifact), "signature"},
	} {
		if _, err := os.Stat(f.path); err != nil {
			fmt.Fprintf(stderr, "The %s %s cannot be read: %v.\n", f.what, f.path, err)
			return 1
		}
	}
	ctx := context.Background()
	ack, err := b.Precheck(ctx)
	if err == nil && !ack.OK {
		err = errors.New(ack.Detail)
	}
	if err != nil {
		fmt.Fprintf(stderr, "Could not find the inactive slot: %v.\n", err)
		return 1
	}
	version, err := b.Install(ctx, bundleID, "", ack.InactiveSlot, nil)
	slot := strings.ToUpper(string(ack.InactiveSlot))
	if err != nil {
		fmt.Fprintf(stderr, "The install into slot %s failed: %v.\n", slot, err)
		return 1
	}
	if version == "" {
		version = "unknown"
	}
	fmt.Fprintf(stdout, "Installed %s (version %s) into slot %s. It boots on the next reboot; this command does not reboot.\n",
		bundleID, version, slot)
	return 0
}

// exitESPUnavailable tells the kernel-match guard the repair changed nothing
// because the ESP could not be mounted, so only the boot counter can roll the
// slot back.
const exitESPUnavailable = 3

// runRepairSlotBoot repairs the running slot's boot files. It never reboots:
// the guard that calls it does, on exit 0.
func runRepairSlotBoot(args []string, stdout, stderr io.Writer, logger *slog.Logger,
	build func(logger *slog.Logger) (slotRepairer, error)) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "The repair-slot-boot command takes no arguments.")
		printShortUsage(stderr)
		return 2
	}
	r, err := build(logger)
	if err != nil {
		fmt.Fprintf(stderr, "Could not set up the slot repair: %v.\n", err)
		return 1
	}
	outcome, err := r.RepairRunningSlot()
	switch {
	case outcome == updater.RepairRepaired:
		fmt.Fprintln(stdout, "Repaired the running slot's bootloader. Reboot to run the slot's own kernel.")
		return 0
	case outcome == updater.RepairFallback:
		fmt.Fprintln(stdout, "Marked the running slot bad. Reboot to fall back to the other slot.")
		return 0
	case errors.Is(err, updater.ErrESPUnavailable):
		fmt.Fprintf(stderr, "The ESP could not be mounted, so nothing was changed: %v.\n", err)
		return exitESPUnavailable
	default:
		fmt.Fprintf(stderr, "The slot repair did not run: %v.\n", err)
		return 1
	}
}
