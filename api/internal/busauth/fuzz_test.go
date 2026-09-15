package busauth

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// The node id an unauthenticated client presents is the most exposed input the
// api has: it arrives as the NATS CONNECT username, is checked before any token
// lookup, and is spliced into the subject permissions of the credential the bus
// mints. So the property worth fuzzing is not "does it parse" but "can an
// accepted id ever be more than one literal subject token" — the shape that let
// a `*` username take every node's lane.

// singleLiteralToken reports whether s is exactly one literal NATS subject
// token: non-empty, no separator, no wildcard, no whitespace or control byte.
func singleLiteralToken(s string) bool {
	if s == "" || strings.ContainsAny(s, ".*> \t\r\n") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// FuzzValidNodeID asserts the invariant every caller of ValidNodeID relies on:
// an accepted id is one literal subject token AND a lowercase DNS label. The
// label rule is the stricter of the two, so this pins both — a future rewrite
// that loosened the charset to, say, "anything without a dot" would fail here
// rather than in production.
func FuzzValidNodeID(f *testing.F) {
	for _, seed := range []string{
		"cp-1", "cp-compute4", "node-9bbaa24a", "e12bench-controlplane1",
		"a", strings.Repeat("a", 63), strings.Repeat("a", 64),
		"", "*", ">", "a.b", "a b", "CP-1", "cp_1", "-bad", "bad-", "a\tb",
		"café", "a\x00b", "rasputin.node.cp-1.cmd.>",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if !ValidNodeID(id) {
			// checkNodeID must agree with ValidNodeID, always: they are the
			// reject path every caller maps to a client error.
			if err := checkNodeID(id); err == nil {
				t.Fatalf("ValidNodeID(%q) is false but checkNodeID returned nil", id)
			}
			return
		}
		if err := checkNodeID(id); err != nil {
			t.Fatalf("ValidNodeID(%q) is true but checkNodeID returned %v", id, err)
		}
		if !singleLiteralToken(id) {
			t.Fatalf("accepted node id %q is not a single literal subject token: "+
				"spliced into rasputin.node.<id>.> it would widen or malform the grant", id)
		}
		if n := len(id); n < 1 || n > 63 {
			t.Fatalf("accepted node id %q has length %d, outside the DNS label range 1-63", id, n)
		}
		if id[0] == '-' || id[len(id)-1] == '-' {
			t.Fatalf("accepted node id %q starts or ends with a hyphen", id)
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				t.Fatalf("accepted node id %q contains %q, outside [a-z0-9-]", id, c)
			}
		}
	})
}

// FuzzMintUserJWT asserts that whatever node id reaches credential minting, the
// minted permissions never name more than one node. This is the invariant the
// wildcard-username bug broke: every subject under the node prefix must carry
// exactly one literal token, so a credential can only ever address its own lane.
func FuzzMintUserJWT(f *testing.F) {
	issuer, err := EnsureIssuer(f.TempDir())
	if err != nil {
		f.Fatalf("EnsureIssuer: %v", err)
	}
	ukp, err := nkeys.CreateUser()
	if err != nil {
		f.Fatalf("CreateUser: %v", err)
	}
	upub, err := ukp.PublicKey()
	if err != nil {
		f.Fatalf("user public key: %v", err)
	}
	r := NewResponder(nil, issuer, nil)

	for _, seed := range []string{"cp-1", "cp-compute4", "", "*", ">", "a.b", "a b", "CP-1", "cp_1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, nodeID string) {
		tok, err := r.mintUserJWT(upub, nodeID)
		if err != nil {
			return // refusing is always an acceptable outcome
		}
		if !ValidNodeID(nodeID) {
			t.Fatalf("minted a credential for invalid node id %q", nodeID)
		}
		uc, err := jwt.DecodeUserClaims(tok)
		if err != nil {
			t.Fatalf("minted credential for %q does not decode: %v", nodeID, err)
		}
		check := func(kind string, subjects jwt.StringList) {
			for _, s := range subjects {
				rest, ok := strings.CutPrefix(s, "rasputin.node.")
				if !ok {
					continue // _INBOX.> and friends are not node-scoped
				}
				first, _, _ := strings.Cut(rest, ".")
				if first != nodeID {
					t.Fatalf("%s subject %q scopes node %q, not %q", kind, s, first, nodeID)
				}
				if !singleLiteralToken(first) {
					t.Fatalf("%s subject %q does not name exactly one node", kind, s)
				}
			}
		}
		if uc.Permissions.Pub.Allow != nil {
			check("pub", uc.Permissions.Pub.Allow)
		}
		if uc.Permissions.Sub.Allow != nil {
			check("sub", uc.Permissions.Sub.Allow)
		}
	})
}

// FuzzParsePreseed fuzzes the controlplane's matched-set preseed file — the one
// attacker-reachable-adjacent parser that is reached by physical/seed-media
// access rather than the network. It asserts no crash and that parsing is
// stable: whatever came out re-marshals and re-parses to the same entries, so a
// later rewrite cannot silently reinterpret a file the provisioner wrote.
//
// Entry VALIDATION is deliberately not asserted here: it lives in
// Store.PreloadHashes (and the unbound-entry question is geekdojo-brain#423),
// so pinning it here would freeze a decision this parser does not own.
func FuzzParsePreseed(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"hash":"` + strings.Repeat("ab", 32) + `","nodeId":"cp-1","label":"compute"}]`))
	f.Add([]byte(`[{"hash":"","nodeId":"","label":""}]`))
	f.Add([]byte(`[{"hash":"zz","nodeId":"CP-1"}]`))
	f.Add([]byte(`{"hash":"x"}`))
	f.Add([]byte(`[{"hash":1}]`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		toks, err := ParsePreseed(data)
		if err != nil {
			if toks != nil {
				t.Fatalf("ParsePreseed returned %d entries alongside error %v; want nil", len(toks), err)
			}
			return
		}
		again, err := ParsePreseed(mustMarshalPreseed(t, toks))
		if err != nil {
			t.Fatalf("re-parsing our own output failed: %v", err)
		}
		if len(again) != len(toks) {
			t.Fatalf("round-trip changed entry count: %d -> %d", len(toks), len(again))
		}
		for i := range toks {
			if again[i] != toks[i] {
				t.Fatalf("round-trip changed entry %d: %+v -> %+v", i, toks[i], again[i])
			}
		}
	})
}

func mustMarshalPreseed(t *testing.T, toks []PreseedToken) []byte {
	t.Helper()
	b, err := json.Marshal(toks)
	if err != nil {
		t.Fatalf("marshal preseed: %v", err)
	}
	return b
}
