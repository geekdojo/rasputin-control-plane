package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The console root password (geekdojo/geekdojo-brain#587, decision #558).
//
// Nothing is baked into an image. The operator chooses the password in the
// control plane's first-run wizard, and a job delivers it to every node in
// inventory — the controlplane included — over that node's own command lane.
//
// What travels is the HASH, never the password. The api hashes what the
// browser sent, stores only the hash, and puts it into this command at
// dispatch time; the plaintext exists only for the length of one HTTP
// request. The hash is secret material all the same — it is what an offline
// cracker needs — so it appears in no job spec, no step result, no event and
// no log line. Everything that needs to NAME a particular password refers to
// it by HashID instead.
//
// Encoding: the crypt(3) string the node writes into root's /etc/shadow
// field, SHA-512 ("$6$"), in either of the format's two spellings —
// "$6$<salt>$<hash>" at crypt's 5,000-round default, or
// "$6$rounds=N$<salt>$<hash>". BusyBox 1.37 (the firewall image's crypt) and
// glibc/libxcrypt (the Buildroot OS) produce byte-identical output for both,
// checked both ways against each other and against OpenSSL's `passwd -6`
// (2026-09-19).
//
// The api mints ONE round count for the whole fleet
// (console.CryptRounds) — a cluster half on one and half on another is
// invisible until someone needs a console. Both spellings are ACCEPTED here
// because this is the check an agent runs on what it was handed, and it must
// not refuse a value a later api legitimately mints.

// ConsoleRootHashVerb is the agent command that delivers the console root
// password hash: rasputin.node.<id>.cmd.console.root_hash.
const ConsoleRootHashVerb = "console.root_hash"

// ConsoleRootHashPrefix introduces the one hash form this verb carries.
const ConsoleRootHashPrefix = "$6$"

// ConsoleRootHashCmd carries the hash to one node.
type ConsoleRootHashCmd struct {
	// Hash is the crypt(3) SHA-512 string for root. SECRET: an agent must
	// not log it, echo it, or write it anywhere but root's shadow entry.
	Hash string `json:"hash"`
	// HashID is ConsoleRootHashID(Hash) — the non-secret name for this
	// password. Sent so the agent can answer "I already hold this one"
	// without the api having to compare hashes in a result.
	HashID string `json:"hashId"`
}

// ConsoleRootHashAck is the agent's answer.
//
// OK means root's shadow entry now holds exactly this hash, persisted. An
// agent that cannot apply one — no writable shadow file, an image whose
// console model does not accept a delivered hash, a hash form it cannot
// verify — answers OK=false with Detail saying why. It must never answer
// OK=true for a node it did not change, and must never quietly succeed by
// doing nothing: the control plane fails that node on an OK=false, and the
// operator is told which node and why.
type ConsoleRootHashAck struct {
	NodeID string `json:"nodeId"`
	OK     bool   `json:"ok"`
	// HashID is the id of the hash the node holds after handling the
	// command; "" when it holds none or could not tell.
	HashID string `json:"hashId,omitempty"`
	// Changed is false when the node already held this hash and nothing
	// was written. Still OK=true — the node is converged either way.
	Changed bool `json:"changed,omitempty"`
	// Detail is the reason on a refusal, and may be empty on success.
	// Never the hash, and never the password.
	Detail string `json:"detail,omitempty"`
}

// ConsoleRootHashID names a hash without carrying it: the first 16 hex
// characters of the SHA-256 of the whole crypt string.
//
// Safe to put in a job spec, a step result, an event, a log line and the UI.
// The digest is taken over the salt as well as the hash, so it cannot be
// tested against a password guess by anyone who does not already hold the
// hash itself. Same shape and same reasoning as bmc.ConfigHash.
//
// An empty hash has an empty id — "no password set" is not a value to name.
func ConsoleRootHashID(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:])[:16]
}

// ErrConsoleRootHashForm is wrapped by every ValidConsoleRootHash failure.
var ErrConsoleRootHashForm = errors.New(`console root hash must be a crypt(3) SHA-512 string ("$6$<salt>$<hash>" or "$6$rounds=N$<salt>$<hash>")`)

// ValidConsoleRootHash checks the shape of a hash before it goes on the wire
// or into a shadow file: the "$6$" prefix, an optional well-formed
// "rounds=N", a non-empty salt, an 86-character SHA-512 crypt digest, and
// none of the characters that would split a shadow line into the wrong
// fields. Checked on BOTH ends — the api will not dispatch a malformed hash,
// and an agent will not write one.
func ValidConsoleRootHash(hash string) error {
	if !strings.HasPrefix(hash, ConsoleRootHashPrefix) {
		return fmt.Errorf("%w (prefix)", ErrConsoleRootHashForm)
	}
	if strings.ContainsAny(hash, ":\n\r\x00 \t") {
		return fmt.Errorf("%w (illegal character)", ErrConsoleRootHashForm)
	}
	parts := strings.Split(hash, "$")
	// "" / "6" / [rounds=N] / salt / digest
	switch len(parts) {
	case 4:
	case 5:
		spec, ok := strings.CutPrefix(parts[2], "rounds=")
		if !ok {
			return fmt.Errorf("%w (the third field must be rounds=N)", ErrConsoleRootHashForm)
		}
		n, err := strconv.Atoi(spec)
		if err != nil || n < 1000 || n > 999999999 {
			return fmt.Errorf("%w (rounds must be 1000..999999999)", ErrConsoleRootHashForm)
		}
		parts = append(parts[:2], parts[3:]...)
	default:
		return fmt.Errorf("%w (want $6$<salt>$<hash> or $6$rounds=N$<salt>$<hash>)", ErrConsoleRootHashForm)
	}
	salt, digest := parts[2], parts[3]
	if salt == "" || len(salt) > 16 {
		return fmt.Errorf("%w (salt must be 1..16 characters)", ErrConsoleRootHashForm)
	}
	if len(digest) != 86 {
		return fmt.Errorf("%w (digest must be 86 characters, got %d)", ErrConsoleRootHashForm, len(digest))
	}
	for _, r := range salt + digest {
		if !isCryptB64(r) {
			return fmt.Errorf("%w (illegal character)", ErrConsoleRootHashForm)
		}
	}
	return nil
}

// isCryptB64 reports whether r is in crypt(3)'s alphabet ("./0-9A-Za-z").
func isCryptB64(r rune) bool {
	switch {
	case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		return true
	case r == '.' || r == '/':
		return true
	}
	return false
}
