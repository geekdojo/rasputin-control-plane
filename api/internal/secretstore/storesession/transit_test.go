package storesession_test

import (
	"context"
	"errors"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// transitRig is a key session's Transit store over the rig's KV bookkeeping:
// each call records its token as a KV call does.
type transitRig struct{ *rig }

func (r transitRig) TransitCreateKey(_ context.Context, tok secret.Value, _ secretstore.TransitKey) error {
	return r.kv(tok)
}

func (r transitRig) TransitEncrypt(_ context.Context, tok secret.Value, _ secretstore.TransitKey, _ secret.Value) (secret.Value, error) {
	if err := r.kv(tok); err != nil {
		return secret.Value{}, err
	}
	return secret.New([]byte("vault:v1:x")), nil
}

func (r transitRig) TransitDecrypt(_ context.Context, tok secret.Value, _ secretstore.TransitKey, _ secret.Value) (secret.Value, error) {
	if err := r.kv(tok); err != nil {
		return secret.Value{}, err
	}
	return secret.New([]byte("aGk=")), nil
}

func (r transitRig) TransitDestroyKey(_ context.Context, tok secret.Value, _ secretstore.TransitKey) error {
	return r.kv(tok)
}

// newKeyRig is a key session: a Transit store and no KV store.
func newKeyRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t}
	log, rec := logkittest.New()
	r.rec = rec
	s, err := storesession.New(storesession.Config{Role: "rasputin-app-keys", Login: r, Transit: transitRig{r}, Observer: r, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.sess = s
	return r
}

// A key session (geekdojo/geekdojo-brain#1084) carries its token to each
// Transit call, logs in as its own role, and a refused token gets the one
// re-login and retry every call gets. A KV call on it is refused with
// ErrDisabled and no login, and a Transit call on a KV-only session likewise.
func TestSession_Transit(t *testing.T) {
	k, err := secretstore.NewTransitKey("rasputin-app-keys", "app-x-y")
	if err != nil {
		t.Fatal(err)
	}
	for name, do := range map[string]func(*rig) error{
		"create":  func(r *rig) error { return r.sess.TransitCreateKey(t.Context(), k) },
		"destroy": func(r *rig) error { return r.sess.TransitDestroyKey(t.Context(), k) },
		"encrypt": func(r *rig) error {
			v, err := r.sess.TransitEncrypt(t.Context(), k, secret.New([]byte("aGk=")))
			if err == nil && string(v.Reveal()) != "vault:v1:x" {
				t.Errorf("encrypt returned %q", v.Reveal())
			}
			return err
		},
		"decrypt": func(r *rig) error {
			v, err := r.sess.TransitDecrypt(t.Context(), k, secret.New([]byte("vault:v1:x")))
			if err == nil && string(v.Reveal()) != "aGk=" {
				t.Errorf("decrypt returned %q", v.Reveal())
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newKeyRig(t)
			if err := do(r); err != nil {
				t.Fatalf("the first %s = %v", name, err)
			}
			r.kvFn = func(n int, _ string) error {
				if n == 2 {
					return denied("transit")
				}
				return nil
			}
			if err := do(r); err != nil {
				t.Fatalf("%s = %v, want success after the re-login", name, err)
			}
			logins, calls, _ := r.counts()
			_, toks, _ := r.snapshot()
			if logins != 2 || calls != 3 || toks[1] != sentinel(1) || toks[2] != sentinel(2) {
				t.Errorf("logins %d calls %d tokens %v; want 2, 3, the refused then the new token", logins, calls, toks)
			}
			if r.roles[0] != "rasputin-app-keys" {
				t.Errorf("logged in as %q", r.roles[0])
			}
		})
	}
	t.Run("a key session has no KV store", func(t *testing.T) {
		r := newKeyRig(t)
		if _, err := r.sess.Read(t.Context(), path(t), 0); !errors.Is(err, secretstore.ErrDisabled) {
			t.Errorf("Read = %v, want ErrDisabled", err)
		}
		if _, err := r.sess.Write(t.Context(), path(t), nil, 0); !errors.Is(err, secretstore.ErrDisabled) {
			t.Errorf("Write = %v, want ErrDisabled", err)
		}
		if _, err := r.sess.Versions(t.Context(), path(t)); !errors.Is(err, secretstore.ErrDisabled) {
			t.Errorf("Versions = %v, want ErrDisabled", err)
		}
		if err := r.sess.Delete(t.Context(), path(t)); !errors.Is(err, secretstore.ErrDisabled) {
			t.Errorf("Delete = %v, want ErrDisabled", err)
		}
		if logins, _, _ := r.counts(); logins != 0 {
			t.Errorf("%d logins for calls with no backend", logins)
		}
	})
	t.Run("a KV session has no Transit store", func(t *testing.T) {
		r := newRig(t)
		_, e1 := r.sess.TransitEncrypt(t.Context(), k, secret.New([]byte("x")))
		_, e2 := r.sess.TransitDecrypt(t.Context(), k, secret.New([]byte("x")))
		for _, err := range []error{r.sess.TransitCreateKey(t.Context(), k), e1, e2, r.sess.TransitDestroyKey(t.Context(), k)} {
			if !errors.Is(err, secretstore.ErrDisabled) {
				t.Errorf("err = %v, want ErrDisabled", err)
			}
		}
		if logins, _, _ := r.counts(); logins != 0 {
			t.Errorf("%d logins for calls with no backend", logins)
		}
	})
}
