package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// A real hash, produced by `openssl passwd -6 -salt saltstring 'Hello world!'`
// and byte-identical to BusyBox 1.37's `mkpasswd -m sha512 -S saltstring`.
const sampleHash = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"

func TestValidConsoleRootHash(t *testing.T) {
	if err := ValidConsoleRootHash(sampleHash); err != nil {
		t.Fatalf("a real $6$ hash was refused: %v", err)
	}
	bad := map[string]string{
		"empty":            "",
		"md5":              "$1$saltstrin$T0bHfzpPnpcfqGLPRQHnT0",
		"locked":           "!",
		"bcrypt":           "$2b$10$abcdefghijklmnopqrstuv",
		"rounds variant":   "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
		"no salt":          "$6$$" + strings.Repeat("a", 86),
		"short digest":     "$6$salt$" + strings.Repeat("a", 85),
		"long digest":      "$6$salt$" + strings.Repeat("a", 87),
		"colon in digest":  "$6$salt$" + strings.Repeat("a", 85) + ":",
		"newline":          sampleHash + "\n",
		"space":            sampleHash[:10] + " " + sampleHash[11:],
		"bad salt char":    "$6$sa!t$" + strings.Repeat("a", 86),
		"oversized salt":   "$6$" + strings.Repeat("s", 17) + "$" + strings.Repeat("a", 86),
		"trailing garbage": sampleHash + "$x",
	}
	for name, h := range bad {
		if err := ValidConsoleRootHash(h); err == nil {
			t.Errorf("%s: accepted %q, want a refusal", name, h)
		}
	}
}

// The id names a hash without being one, and is stable.
func TestConsoleRootHashID(t *testing.T) {
	id := ConsoleRootHashID(sampleHash)
	if len(id) != 16 {
		t.Fatalf("id %q: want 16 hex characters", id)
	}
	if strings.Contains(sampleHash, id) {
		t.Fatalf("id %q is a substring of the hash", id)
	}
	if got := ConsoleRootHashID(sampleHash); got != id {
		t.Fatalf("id is not stable: %q then %q", id, got)
	}
	if other := ConsoleRootHashID(sampleHash[:len(sampleHash)-1] + "0"); other == id {
		t.Fatal("two different hashes share an id")
	}
	if ConsoleRootHashID("") != "" || ConsoleRootHashID("  ") != "" {
		t.Fatal(`"no password set" must not have an id`)
	}
}

// The ack round-trips, and its zero value is a refusal rather than a success
// — a decoder that fails silently must not read as "applied".
func TestConsoleRootHashAckZeroValueIsRefusal(t *testing.T) {
	var ack ConsoleRootHashAck
	if err := json.Unmarshal([]byte(`{}`), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.OK {
		t.Fatal("an empty ack decoded as OK")
	}
	raw, err := json.Marshal(ConsoleRootHashAck{NodeID: "n1", OK: true, HashID: "abc", Changed: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "$6$") {
		t.Fatalf("ack carries a hash: %s", raw)
	}
}

// The command names the node's own lane.
func TestConsoleRootHashSubject(t *testing.T) {
	subj := NodeCmdSubject("e12bench-compute1", ConsoleRootHashVerb)
	if subj != "rasputin.node.e12bench-compute1.cmd.console.root_hash" {
		t.Fatalf("subject %q", subj)
	}
	node, verb, ok := CmdSubjectVerb(subj)
	if !ok || node != "e12bench-compute1" || verb != ConsoleRootHashVerb {
		t.Fatalf("CmdSubjectVerb(%q) = (%q, %q, %v)", subj, node, verb, ok)
	}
}
