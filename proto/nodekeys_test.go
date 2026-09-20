package proto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
)

func testSPKIHash(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NodeKeySPKIHash(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A node key hash is a bus pin by another name: same algorithm, same
// encoding, same parser. An operator who can read one can read the other, and
// a future algorithm is a new prefix rather than a reinterpretation.
func TestNodeKeySPKIHashIsThePinEncoding(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NodeKeySPKIHash(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	pin, err := BusPinForPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	if h != pin {
		t.Errorf("NodeKeySPKIHash = %q, BusPinForPublicKey = %q; want one encoding", h, pin)
	}
	if _, err := ParseNodeKeySPKIHash(h); err != nil {
		t.Errorf("ParseNodeKeySPKIHash(%q): %v", h, err)
	}
	if _, err := ParseNodeKeySPKIHash("sha256/not-base64"); err == nil {
		t.Error("a malformed hash parsed")
	}
}

// The api reads registration metadata after a JSON round-trip, so the decoder
// is exercised on exactly what it will see on the wire.
func TestDecodeNodeKeys(t *testing.T) {
	good := testSPKIHash(t)
	other := testSPKIHash(t)

	t.Run("absent is not an error", func(t *testing.T) {
		keys, ok, err := DecodeNodeKeys(map[string]any{MetadataBusTLS: true})
		if err != nil || ok || keys != nil {
			t.Fatalf("got (%v, %v, %v), want (nil, false, nil)", keys, ok, err)
		}
	})

	t.Run("wire form", func(t *testing.T) {
		meta := map[string]any{MetadataNodeKeys: NodeKeys{NodeKeyAgent: good, NodeKeyCollector: other}}
		blob, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(blob, &decoded); err != nil {
			t.Fatal(err)
		}
		keys, ok, err := DecodeNodeKeys(decoded)
		if err != nil || !ok {
			t.Fatalf("got (%v, %v, %v)", keys, ok, err)
		}
		want := NodeKeys{NodeKeyAgent: good, NodeKeyCollector: other}
		if !reflect.DeepEqual(keys, want) {
			t.Errorf("keys = %v, want %v", keys, want)
		}
	})

	t.Run("typed form", func(t *testing.T) {
		keys, ok, err := DecodeNodeKeys(map[string]any{MetadataNodeKeys: NodeKeys{NodeKeyAgent: good}})
		if err != nil || !ok || keys[NodeKeyAgent] != good {
			t.Fatalf("got (%v, %v, %v)", keys, ok, err)
		}
	})

	// A purpose a newer agent knows and this release does not is skipped,
	// not refused: that is a newer node, not a broken one.
	t.Run("unknown purpose is skipped", func(t *testing.T) {
		keys, ok, err := DecodeNodeKeys(map[string]any{
			MetadataNodeKeys: map[string]any{"agent": good, "someFuturePurpose": other},
		})
		if err != nil || !ok {
			t.Fatalf("got (%v, %v, %v)", keys, ok, err)
		}
		if len(keys) != 1 || keys[NodeKeyAgent] != good {
			t.Errorf("keys = %v, want only the agent key", keys)
		}
	})

	// Fail closed on anything malformed: a node that half-reports its
	// identity is not one whose identity the api should half-record.
	for name, meta := range map[string]map[string]any{
		"not an object":      {MetadataNodeKeys: "sha256/..."},
		"value not a string": {MetadataNodeKeys: map[string]any{"agent": 7}},
		"unparseable hash":   {MetadataNodeKeys: map[string]any{"agent": "sha256/nope"}},
		"empty hash":         {MetadataNodeKeys: map[string]any{"collector": ""}},
	} {
		t.Run(name, func(t *testing.T) {
			keys, ok, err := DecodeNodeKeys(meta)
			if err == nil {
				t.Fatalf("got (%v, %v, nil), want an error", keys, ok)
			}
			if ok || keys != nil {
				t.Errorf("a refused report still returned (%v, %v)", keys, ok)
			}
		})
	}
}

// A key is taken only where the node proved which control plane it is
// talking to. Absent, false, or a non-boolean all read as "not pinned".
func TestNodeKeysAcceptable(t *testing.T) {
	for name, tc := range map[string]struct {
		meta map[string]any
		want bool
	}{
		"pinned tls":     {map[string]any{MetadataBusTLS: true}, true},
		"plaintext":      {map[string]any{MetadataBusTLS: false}, false},
		"absent":         {map[string]any{}, false},
		"not a bool":     {map[string]any{MetadataBusTLS: "true"}, false},
		"null":           {map[string]any{MetadataBusTLS: nil}, false},
		"nil metadata":   {nil, false},
		"other key only": {map[string]any{MetadataMeshCAFingerprint: "abc"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := NodeKeysAcceptable(tc.meta); got != tc.want {
				t.Errorf("NodeKeysAcceptable(%v) = %v, want %v", tc.meta, got, tc.want)
			}
		})
	}
}

func TestNodeKeysEqualAndClone(t *testing.T) {
	a := testSPKIHash(t)
	b := testSPKIHash(t)
	keys := NodeKeys{NodeKeyAgent: a, NodeKeyCollector: b}
	clone := keys.Clone()
	if !keys.Equal(clone) {
		t.Fatal("a clone is not equal to its source")
	}
	clone[NodeKeyAgent] = b
	if keys.Equal(clone) || keys[NodeKeyAgent] != a {
		t.Fatal("Clone shares state with its source")
	}
	if NodeKeys(nil).Clone() != nil {
		t.Error("cloning nil did not stay nil")
	}
	if !NodeKeys(nil).Equal(NodeKeys{}) {
		t.Error("nil and empty record different things")
	}
	if want := []NodeKeyPurpose{NodeKeyAgent, NodeKeyCollector}; !reflect.DeepEqual(keys.Purposes(), want) {
		t.Errorf("Purposes = %v, want %v", keys.Purposes(), want)
	}
}
