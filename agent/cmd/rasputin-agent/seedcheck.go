package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// `rasputin-agent seed check <path>` — read a seed, check it, and print a
// normalized one (methodology §5.6, §7 4.2, geekdojo/geekdojo-brain#540).
//
// WHY IT EXISTS
//
// Both images provision by SOURCING the seed as a root shell script:
// rasputin-firstboot does `. "$SEED_FILE"` and the firewall's apply-seed does
// `. "$SEED"`. The seed is a file an operator carried on a USB stick, and a
// shell reading it will run whatever it says. That is F18.
//
// This command is the replacement: it PARSES the file (proto.ParseSeed, which
// reads KEY=VALUE lines and strips one layer of quoting — it is not an
// interpreter), checks the values an image is about to act on, and prints a
// seed the image can source safely, because this binary wrote it and every
// value in it is single-quoted (proto.RenderSeed).
//
//	rasputin-agent seed check /run/rasputin-seed/rasputin-seed.env > /run/rasputin-seed.checked
//	. /run/rasputin-seed.checked
//
// An image that has not moved to this command is unaffected: the seed the
// control plane mints is still an ordinary env file that sourcing reads
// correctly. This is the reader changing, not the format.
//
// WHAT IT CHECKS, AND WHAT IT DOES NOT
//
// It checks what makes a seed USABLE, and refuses the whole file rather than a
// field, because a partially-applied seed is the half-joined node both images
// already fail loudly to avoid: a role that is one of the known roles; a node
// id that is a DNS label, since the join token is bound to it and the bus
// refuses it under any other; a bus pin that parses; and a join token on every
// role that needs one.
//
// It does NOT authenticate the seed. Nothing here proves the file came from
// the control plane — the seed is authorized by physical possession (E35,
// geekdojo/geekdojo-brain#127), and that is unchanged. What changes is that a
// seed can no longer make the image RUN something.
//
// Exit codes: 0 checked, output on stdout; 1 the seed is unusable, with the
// reason on stderr and NOTHING on stdout; 2 a usage error.

func runSeed(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "rasputin-agent seed: expected a subcommand (check)")
		printSeedUsage(stderr)
		return 2
	}
	switch args[0] {
	case "check":
		return runSeedCheck(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "rasputin-agent seed: unknown subcommand %q\n", args[0])
		printSeedUsage(stderr)
		return 2
	}
}

func printSeedUsage(w io.Writer) {
	fmt.Fprint(w, `usage: rasputin-agent seed check <path> [--role <role>]

Reads the enrollment seed at <path>, refuses it if it is unusable, and prints a
normalized, fully quoted copy on stdout for an image to source. Nothing is
printed unless the seed is usable.
`)
}

func runSeedCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("seed check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	// --role is what an image knows about ITSELF: the firewall image can only
	// ever be a firewall. A seed naming another role on that image is an
	// operator putting the wrong file on the wrong box, and saying so here is
	// better than a node that enrols as something it cannot be.
	wantRole := fs.String("role", "", "refuse the seed unless it names this role")
	fs.Usage = func() { printSeedUsage(stderr) }
	// Go's flag package stops parsing at the first non-flag argument, so
	// `seed check <path> --role firewall` — which is how an operator types it
	// off a runbook, and how verify-artifact was already bitten — would leave
	// --role unparsed and silently skip the check it asks for. Same
	// parse-take-a-positional-reparse loop as runVerifyArtifact, so flags work
	// on either side of the path.
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
		fmt.Fprintln(stderr, "rasputin-agent seed check: expected exactly one seed path")
		printSeedUsage(stderr)
		return 2
	}
	path := positional[0]

	f, err := os.Open(path) // #nosec G304 -- the path is an argument from the image's own init, not a value from a seed or a bus message
	if err != nil {
		fmt.Fprintf(stderr, "SEED UNUSABLE: cannot read %s: %v\n", path, err)
		return 1
	}
	defer func() { _ = f.Close() }()

	seed, err := proto.ParseSeed(f)
	if err != nil {
		fmt.Fprintf(stderr, "SEED UNUSABLE: %s is not a seed this agent can read: %v\n", path, err)
		return 1
	}
	if err := checkSeed(seed, proto.NodeRole(*wantRole)); err != nil {
		fmt.Fprintf(stderr, "SEED UNUSABLE: %s: %v\n", path, err)
		return 1
	}
	// Re-render rather than echo: the output is this binary's, quoted by the
	// one renderer, so an image sourcing it is sourcing something we wrote.
	seed.Origin = "rasputin-agent seed check"
	out, err := proto.RenderSeed(seed)
	if err != nil {
		fmt.Fprintf(stderr, "SEED UNUSABLE: %s: %v\n", path, err)
		return 1
	}
	fmt.Fprint(stdout, out)
	return 0
}

// checkSeed is the usability check. Every failure names the field and what to
// do, because it is read off a console on a box with no other way in.
func checkSeed(s proto.Seed, wantRole proto.NodeRole) error {
	if s.Role == "" {
		return fmt.Errorf("it names no %s — a node with no role is un-provisioned; re-generate the seed from the control plane (Add node)", proto.SeedKeyRole)
	}
	if !proto.ValidRole(s.Role) {
		return fmt.Errorf("%s is %q, which is not a role this build knows", proto.SeedKeyRole, s.Role)
	}
	if wantRole != "" && s.Role != wantRole {
		return fmt.Errorf("%s is %q but this image can only be a %q — this seed belongs to another node", proto.SeedKeyRole, s.Role, wantRole)
	}
	if s.NodeID == "" {
		return fmt.Errorf("it names no %s — the join token is bound to a node id, and the bus refuses it under any other", proto.SeedKeyNodeID)
	}
	if !proto.ValidSeedNodeID(s.NodeID) {
		return fmt.Errorf("%s is %q, which is not a usable node id: %s", proto.SeedKeyNodeID, s.NodeID, proto.SeedNodeIDRule)
	}
	// Every role but the controlplane enrols with a token bound to its id; the
	// controlplane's api mints its own agent's at start.
	if s.Role != proto.RoleControlPlane && s.JoinToken == "" && s.Extra[bus.EnvJoinTokenFile] == "" {
		return fmt.Errorf("a %s seed carries no %s — it cannot enrol; re-generate it from the control plane (Add node)", s.Role, proto.SeedKeyJoinToken)
	}
	if s.BusPin != "" {
		if _, err := proto.ParseBusPin(s.BusPin); err != nil {
			return fmt.Errorf("%s is not a usable bus pin: %w", proto.SeedKeyBusPin, err)
		}
	}
	return nil
}
