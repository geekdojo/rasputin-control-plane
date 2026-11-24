package main

import (
	"context"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass/repaircode"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// `rasputin-api repair-code` (geekdojo/geekdojo-brain#321): root on the
// control plane makes a one-time repair code. main runs it before anything
// else: no env beyond the data dir, no logger, no listener.

// repairCodeCommand is the subcommand's name.
const repairCodeCommand = "repair-code"

// repairSocketDir is the repair-code socket's 0700 root directory.
const repairSocketDir = "/run/rasputin-repair"

// isRepairCode reports whether args (os.Args) name the subcommand.
func isRepairCode(args []string) bool { return len(args) > 1 && args[1] == repairCodeCommand }

// runRepairCode is the subcommand: the identity CA from the api's trust
// dir, read as the api does (RASPUTIN_DATA_DIR, else the appliance's), and
// the socket in repairSocketDir. It returns the exit code.
func runRepairCode() int {
	// A CA that can't be read is passed as none, and the command refuses
	// to make a code it can't verify the api for.
	ca, _ := os.ReadFile(filepath.Join(trustDirFromEnv(envOr("RASPUTIN_DATA_DIR", "/var/lib/rasputin")), tlsca.IdentityCertFile))
	path := filepath.Join(repairSocketDir, breakglass.SocketName)
	return repaircode.Run(context.Background(), repaircode.Deps{
		Stdout: os.Stdout, Stderr: os.Stderr, IsTerminal: repaircode.IsTerminal, Rand: rand.Reader,
		Dial:  func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "unix", path) },
		CAPEM: ca,
	})
}
