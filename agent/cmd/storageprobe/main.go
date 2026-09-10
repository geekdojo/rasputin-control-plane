// Command storageprobe drives the agent's own storage backend directly against
// the disks in a bench node — enumerate, claim, mount-data, inspect — with no
// NATS broker, no api and no browser in the way.
//
// # Why it exists
//
// design/storage.md §6's data-disk contract (geekdojo/geekdojo-brain#302) is
// safety-critical block-device code. What it promises is about what happens to
// a real partition table on real hardware — which disk the protected set
// resolves to on a machine with two identical NVMes, what a fingerprint does
// when the disk underneath it changes, whether a claimed filesystem actually
// carries its marker after mkfs — and none of that can be witnessed by a unit
// test. It has to be run on a disk.
//
// The product path to those same verbs runs through the api, and the api is
// passkey-only: a WebAuthn session behind a Touch ID prompt in a browser. A
// headless run on the bench cannot get one and must not be given a way around
// one, so this binary skips the transport entirely and calls
// agent/internal/storage.Backend — the same interface, the same two backends,
// the same refusals — in-process.
//
// It was written as a throwaway for the 2026-09-10 bench session and used
// successfully there. This is that tool kept.
//
// # It is not part of the product
//
// storageprobe is NOT installed into the OS image and is deliberately absent
// from scripts/build-release.sh's component list. It is cross-compiled on a
// laptop and copied to a node for one run:
//
//	cd agent
//	GOOS=linux GOARCH=arm64 go build -o /tmp/storageprobe ./cmd/storageprobe   # Pi 5
//	GOOS=linux GOARCH=amd64 go build -o /tmp/storageprobe ./cmd/storageprobe   # n100, CWWK
//	scp -O /tmp/storageprobe root@<node>.local:/tmp/
//
// ⚠️ The -O on that scp is not optional. A Rasputin node's busybox ships no
// sftp-server, and every OpenSSH client since 9.0 speaks SFTP by default, so a
// plain `scp` fails with "subsystem request failed on channel 0". -O forces the
// legacy SCP protocol. It is the same gotcha the firewall runbook carries, and
// it cost a round trip the first time this tool was copied to a node.
//
// # The mock is never inferred
//
// The real backend needs util-linux on PATH. When any of it is missing this
// command REFUSES and names the missing tool; it does not fall through to
// MockBackend, and no environment variable can make it. That is not caution in
// the abstract — on 2026-09-01 an OS image shipped without `wipefs`, the agent
// inferred the mock, and `storage.enumerate` answered a real controlplane with
// three fixture disks and ok:true. The mock models disks, partitions and live
// mounts precisely so the safety rules can be tested against it, and that
// fidelity is exactly what makes its output indistinguishable from truth. See
// storage.MissingTools.
//
// The mock is reachable here, by typing `--backend mock` and nothing else, and
// every line it produces is stamped as fixture output.
package main

import (
	"context"
	"os"
)

// main is one line on purpose. Everything below it takes its writers as
// arguments and returns an exit code, so the whole command — flag parsing,
// backend selection, every refusal and every line of output — is reachable
// from a test without a process boundary. A bench tool whose main() cannot be
// driven is one whose output rots between bench sessions, which is how the
// throwaway this replaced ended up printing a field nobody could check.
func main() {
	os.Exit(dispatch(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
