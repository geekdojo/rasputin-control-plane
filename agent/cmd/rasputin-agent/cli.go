package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/artifactsig"
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
  version
        Print the agent version and exit.
  help
        Print this message.

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
  RASPUTIN_CP_JOIN_TOKEN    bus join token
  RASPUTIN_CLUSTER_ID       cluster name, used for <cluster-id>.local
  RASPUTIN_AGENT_STATE_DIR  agent state (updater bookkeeping)
  RASPUTIN_TRUST_ROOT       publisher root CA (see verify-artifact above)
  RASPUTIN_MESH_CA_BUNDLE   per-installation mesh CA for tailscaled
  RASPUTIN_UPDATE_BACKEND   force an updater backend: rauc | openwrt-ab | mock

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
