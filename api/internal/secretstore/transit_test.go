package secretstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

func transitKey(t *testing.T, name string) secretstore.TransitKey {
	t.Helper()
	k, err := secretstore.NewTransitKey("rasputin-app-keys", name)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A Transit key is one segment of the path alphabet under a checked mount.
func TestNewTransitKey(t *testing.T) {
	k := transitKey(t, "app-01J9ZK3Q0M8X7Y6W5V4T3S2R1A-wrap")
	if k.Mount() != "rasputin-app-keys" || k.Name() != "app-01J9ZK3Q0M8X7Y6W5V4T3S2R1A-wrap" || k.String() != "rasputin-app-keys/keys/app-01J9ZK3Q0M8X7Y6W5V4T3S2R1A-wrap" {
		t.Errorf("key = %q %q %q", k.Mount(), k.Name(), k.String())
	}
	for _, bad := range [][2]string{{"", "k"}, {"m", ""}, {"m", "a/b"}, {"m", ".."}, {"m", "a b"}, {"m", "a?x"}} {
		if _, err := secretstore.NewTransitKey(bad[0], bad[1]); err == nil {
			t.Errorf("NewTransitKey(%q, %q) accepted", bad[0], bad[1])
		}
	}
}

// transitServer answers like the pinned store, from its fields, and records
// each request.
type transitServer struct {
	mu     sync.Mutex
	reqs   []string
	bodies []map[string]any
	status map[string]int
	errs   map[string]string
	data   map[string]any
}

func (s *transitServer) handle(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	s.mu.Lock()
	s.reqs = append(s.reqs, key)
	s.bodies = append(s.bodies, body)
	s.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != loginToken {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	code, ok := s.status[key]
	if !ok {
		code = http.StatusOK
	}
	switch {
	case s.errs[key] != "":
		writeJSON(w, code, map[string]any{"errors": []string{s.errs[key]}})
	case code == http.StatusNoContent:
		w.WriteHeader(code)
	default:
		writeJSON(w, code, map[string]any{"data": s.data})
	}
}

// The client's Transit calls: the path, the method and the exact body each
// sends, and the measured 400 messages of OpenBao 2.7.2 classified as
// F-1084-05 has them (ErrNotFound at the config, DELETE and decrypt steps;
// ErrInvalidCiphertext for a ciphertext that does not decrypt; anything else
// ErrProtocol). Supports TC-1084-05, whose functional case asserts the same
// against the real store.
func TestClient_Transit(t *testing.T) {
	const name = "app-01J9ZK3Q0M8X7Y6W5V4T3S2R1A-wrap"
	base := "/v1/rasputin-app-keys/"
	k := transitKey(t, name)

	t.Run("create sends only the pinned type", func(t *testing.T) {
		s := &transitServer{data: map[string]any{"name": name}}
		f := newFixture(t, s.handle)
		if err := f.client.TransitCreateKey(t.Context(), tok(loginToken), k); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(s.reqs, []string{"POST " + base + "keys/" + name}) || len(s.bodies[0]) != 1 || s.bodies[0]["type"] != "aes256-gcm96" {
			t.Errorf("requests %v bodies %v", s.reqs, s.bodies)
		}
	})
	t.Run("encrypt and decrypt carry the value in the body and return data", func(t *testing.T) {
		s := &transitServer{data: map[string]any{"ciphertext": "vault:v1:abc", "plaintext": "aGVsbG8="}}
		f := newFixture(t, s.handle)
		ct, err := f.client.TransitEncrypt(t.Context(), tok(loginToken), k, tok("aGVsbG8="))
		if err != nil || string(ct.Reveal()) != "vault:v1:abc" {
			t.Fatalf("encrypt = %q, %v", ct.Reveal(), err)
		}
		pt, err := f.client.TransitDecrypt(t.Context(), tok(loginToken), k, tok("vault:v1:abc"))
		if err != nil || string(pt.Reveal()) != "aGVsbG8=" {
			t.Fatalf("decrypt = %q, %v", pt.Reveal(), err)
		}
		if !slices.Equal(s.reqs, []string{"POST " + base + "encrypt/" + name, "POST " + base + "decrypt/" + name}) ||
			s.bodies[0]["plaintext"] != "aGVsbG8=" || len(s.bodies[0]) != 1 || s.bodies[1]["ciphertext"] != "vault:v1:abc" || len(s.bodies[1]) != 1 {
			t.Errorf("requests %v bodies %v", s.reqs, s.bodies)
		}
	})
	t.Run("destroy sets deletion_allowed as a string, then deletes", func(t *testing.T) {
		s := &transitServer{status: map[string]int{"DELETE " + base + "keys/" + name: http.StatusNoContent}}
		f := newFixture(t, s.handle)
		if err := f.client.TransitDestroyKey(t.Context(), tok(loginToken), k); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(s.reqs, []string{"POST " + base + "keys/" + name + "/config", "DELETE " + base + "keys/" + name}) || s.bodies[0]["deletion_allowed"] != "true" {
			t.Errorf("requests %v bodies %v", s.reqs, s.bodies)
		}
	})
	for _, tc := range []struct {
		name string
		call func(*fixture) error
		key  string
		msg  string
		want error
		reqs int
	}{
		{"absent at config", destroy(k), "POST " + base + "keys/" + name + "/config", "no existing key named " + name + " could be found", secretstore.ErrNotFound, 1},
		{"absent at DELETE", destroy(k), "DELETE " + base + "keys/" + name, "error deleting policy " + name + ": could not delete key; not found", secretstore.ErrNotFound, 2},
		{"absent at decrypt", decrypt(k), "POST " + base + "decrypt/" + name, "encryption key not found", secretstore.ErrNotFound, 1},
		{"tampered or another key's", decrypt(k), "POST " + base + "decrypt/" + name, "cipher: message authentication failed", secretstore.ErrInvalidCiphertext, 1},
		{"a version too new", decrypt(k), "POST " + base + "decrypt/" + name, "invalid ciphertext: version is too new", secretstore.ErrInvalidCiphertext, 1},
		{"any other 400", decrypt(k), "POST " + base + "decrypt/" + name, "something else", secretstore.ErrProtocol, 1},
		{"an encrypt 400 on bad base64", encrypt(k), "POST " + base + "encrypt/" + name, "illegal base64 data at input byte 3", secretstore.ErrProtocol, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &transitServer{status: map[string]int{tc.key: http.StatusBadRequest}, errs: map[string]string{tc.key: tc.msg}}
			f := newFixture(t, s.handle)
			err := tc.call(f)
			var se *secretstore.Error
			if !errors.Is(err, tc.want) || !errors.As(err, &se) || !strings.HasPrefix(se.Op, "transit_") {
				t.Fatalf("err = %v, want %v with a transit_ Op", err, tc.want)
			}
			if len(s.reqs) != tc.reqs {
				t.Errorf("requests %v, want %d", s.reqs, tc.reqs)
			}
			if strings.Contains(err.Error(), tc.msg) {
				t.Error("the error string repeats the store's text")
			}
		})
	}
	t.Run("a kv call's 400 is never read as a Transit absence", func(t *testing.T) {
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"encryption key not found"}})
		})
		if _, err := f.client.Read(t.Context(), tok(loginToken), kvPath(t, "kv", "a"), 0); !errors.Is(err, secretstore.ErrProtocol) {
			t.Errorf("Read = %v, want ErrProtocol", err)
		}
	})
	t.Run("the zero key sends nothing", func(t *testing.T) {
		f := newFixture(t, func(http.ResponseWriter, *http.Request) {})
		var zero secretstore.TransitKey
		for _, err := range []error{
			f.client.TransitCreateKey(t.Context(), tok(loginToken), zero),
			f.client.TransitDestroyKey(t.Context(), tok(loginToken), zero),
			func() error { _, e := f.client.TransitEncrypt(t.Context(), tok(loginToken), zero, tok("x")); return e }(),
		} {
			if !errors.Is(err, secretstore.ErrInvalidValue) {
				t.Errorf("err = %v, want ErrInvalidValue", err)
			}
		}
		if f.hits.Load() != 0 {
			t.Errorf("%d requests for the zero key", f.hits.Load())
		}
	})
	t.Run("a 200 with no ciphertext is a protocol error", func(t *testing.T) {
		s := &transitServer{data: map[string]any{"other": "x"}}
		f := newFixture(t, s.handle)
		if _, err := f.client.TransitEncrypt(t.Context(), tok(loginToken), k, tok("aGVsbG8=")); !errors.Is(err, secretstore.ErrProtocol) {
			t.Errorf("err = %v, want ErrProtocol", err)
		}
	})
}

func destroy(k secretstore.TransitKey) func(*fixture) error {
	return func(f *fixture) error { return f.client.TransitDestroyKey(context.Background(), tok(loginToken), k) }
}

func decrypt(k secretstore.TransitKey) func(*fixture) error {
	return func(f *fixture) error {
		_, err := f.client.TransitDecrypt(context.Background(), tok(loginToken), k, tok("vault:v1:abc"))
		return err
	}
}

func encrypt(k secretstore.TransitKey) func(*fixture) error {
	return func(f *fixture) error {
		_, err := f.client.TransitEncrypt(context.Background(), tok(loginToken), k, tok("x"))
		return err
	}
}

// The Mock's keys behave as the client reports the store's: encrypt under an
// absent key is denied, decrypt under it is not found, a ciphertext under
// another key does not decrypt, and destroy forgets the key.
func TestMock_Transit(t *testing.T) {
	m := secretstore.NewMock(time.Now)
	ctx := t.Context()
	a, b := transitKey(t, "a"), transitKey(t, "b")
	if _, err := m.TransitEncrypt(ctx, tok(""), a, tok("aGk=")); !errors.Is(err, secretstore.ErrDenied) {
		t.Errorf("encrypt under an absent key = %v, want ErrDenied", err)
	}
	if _, err := m.TransitDecrypt(ctx, tok(""), a, tok("vault:v1:x")); !errors.Is(err, secretstore.ErrNotFound) {
		t.Errorf("decrypt under an absent key = %v, want ErrNotFound", err)
	}
	for _, k := range []secretstore.TransitKey{a, a, b} {
		if err := m.TransitCreateKey(ctx, tok(""), k); err != nil {
			t.Fatal(err)
		}
	}
	ct, err := m.TransitEncrypt(ctx, tok(""), a, tok("aGk="))
	if err != nil || !strings.HasPrefix(string(ct.Reveal()), "vault:v1:") {
		t.Fatalf("encrypt = %q, %v", ct.Reveal(), err)
	}
	if pt, err := m.TransitDecrypt(ctx, tok(""), a, ct); err != nil || string(pt.Reveal()) != "aGk=" {
		t.Errorf("decrypt = %q, %v", pt.Reveal(), err)
	}
	for _, bad := range []string{string(ct.Reveal()), "vault:v1:@@", "plain"} {
		k := a
		if bad == string(ct.Reveal()) {
			k = b
		}
		if _, err := m.TransitDecrypt(ctx, tok(""), k, tok(bad)); !errors.Is(err, secretstore.ErrInvalidCiphertext) {
			t.Errorf("decrypt %q = %v, want ErrInvalidCiphertext", bad, err)
		}
	}
	if err := m.TransitDestroyKey(ctx, tok(""), a); err != nil {
		t.Fatal(err)
	}
	if err := m.TransitDestroyKey(ctx, tok(""), a); !errors.Is(err, secretstore.ErrNotFound) {
		t.Errorf("a second destroy = %v, want ErrNotFound", err)
	}
	if err := m.TransitCreateKey(ctx, tok(""), secretstore.TransitKey{}); !errors.Is(err, secretstore.ErrInvalidValue) {
		t.Errorf("create of the zero key = %v", err)
	}
}

// TC-1084-11 (store side): the switched-off store refuses every Transit call
// with ErrDisabled and no I/O.
func TestDisabled_Transit(t *testing.T) {
	d := secretstore.Disabled{}
	ctx := t.Context()
	k := transitKey(t, "a")
	_, e1 := d.TransitEncrypt(ctx, tok(""), k, tok("x"))
	_, e2 := d.TransitDecrypt(ctx, tok(""), k, tok("x"))
	for _, err := range []error{d.TransitCreateKey(ctx, tok(""), k), e1, e2, d.TransitDestroyKey(ctx, tok(""), k)} {
		if !errors.Is(err, secretstore.ErrDisabled) {
			t.Errorf("err = %v, want ErrDisabled", err)
		}
	}
}
