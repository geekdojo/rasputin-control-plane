package storage

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

const custodyMember = "volumes/app/data.rasputin-archive"

// openArmed opens a session on v's bytes, binds it to job and arms it for
// one member of generation gen.
func openArmed(t *testing.T, r *RestoreSessions, v secret.Value, job, gen string) string {
	t.Helper()
	id, err := r.Open(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Bind(id, job); err != nil {
		t.Fatal(err)
	}
	if err := r.Arm(id, "/mnt/x", "part", gen, "n1", []RestoreVolumePlan{{Member: custodyMember}}); err != nil {
		t.Fatal(err)
	}
	return id
}

func assertZeroed(t *testing.T, label string, b []byte) {
	t.Helper()
	if len(b) == 0 || !allZero(b) {
		t.Fatalf("%s: %d bytes, not all zero", label, len(b))
	}
}

// TC-732-16: every holder of a restore key owns an independent payload
// (F-732-02), and each is zeroed and dropped when its holder lets go
// (F-732-03).
func TestRestoreSessions_IndependentPayloads(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := priv.Bytes()

	for _, closeVia := range []string{"Close", "CloseJob"} {
		r := NewRestoreSessions()
		v := secret.New(key)
		id := openArmed(t, r, v, "job-1", "gen-1")

		// The handler's deferred Destroy does not reach the session.
		v.Destroy()
		s := r.Get(id)
		if s == nil || !bytes.Equal(s.key.Reveal(), key) {
			t.Fatalf("%s: the session lost its key when the handler destroyed its own", closeVia)
		}

		g, ok := r.Lookup("job-1", "gen-1", custodyMember)
		if !ok {
			t.Fatalf("%s: Lookup refused an armed session", closeVia)
		}
		sk := s.key.Reveal()
		gk := g.Key().Reveal()

		// Closing the session mid-stream does not reach the grant.
		switch closeVia {
		case "Close":
			r.Close(id)
		case "CloseJob":
			r.CloseJob("job-1")
		}
		if !bytes.Equal(g.Key().Reveal(), key) {
			t.Fatalf("%s: closing the session zeroed the grant's key", closeVia)
		}
		assertZeroed(t, closeVia+": the session's bytes after close", sk)
		if s.key.Len() != 0 {
			t.Fatalf("%s: the session's key still has Len %d after close", closeVia, s.key.Len())
		}

		g.Release()
		assertZeroed(t, closeVia+": the grant's bytes after Release", gk)
		if g.Key().Len() != 0 {
			t.Fatalf("%s: the grant's key still has Len %d after Release", closeVia, g.Key().Len())
		}
	}
}

// TC-732-16: Open refuses a short, an all-zero and a destroyed Value.
func TestRestoreSessions_OpenRefusesABadValue(t *testing.T) {
	r := NewRestoreSessions()
	destroyed := secret.New(bytes.Repeat([]byte{9}, 32))
	destroyed.Destroy()
	for name, v := range map[string]secret.Value{
		"31 bytes":  secret.New(bytes.Repeat([]byte{9}, 31)),
		"all zero":  secret.New(make([]byte, 32)),
		"destroyed": destroyed,
		"zero":      {},
	} {
		if _, err := r.Open(v); err == nil {
			t.Errorf("Open accepted a %s Value", name)
		}
	}
	if _, active := r.Active(); active {
		t.Fatal("a refused Open left a session")
	}
}
