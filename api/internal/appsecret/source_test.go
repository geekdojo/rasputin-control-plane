package appsecret

import (
	"bytes"
	"context"
	"testing"
)

func sourceTestSeed(t *testing.T) *Seed {
	t.Helper()
	seed, err := NewSeed(bytes.Repeat([]byte{0x42}, SeedLen), DerivationVersion)
	if err != nil {
		t.Fatalf("NewSeed: %v", err)
	}
	return seed
}

// TC-692-09: the adapter's constructor refuses a nil seed (ARCH-IOC).
func TestNewHKDFSourceRefusesANilSeed(t *testing.T) {
	src, err := NewHKDFSource(nil)
	if err == nil {
		t.Fatal("NewHKDFSource(nil) returned no error")
	}
	if src != nil {
		t.Fatalf("NewHKDFSource(nil) returned a source: %#v", src)
	}
}

// TC-692-10: a nil receiver and a zero HKDFSource each refuse every compose,
// tokenised and token-free, with the zero Value and without panicking.
func TestHKDFSourceWithNoSeedRefusesEveryCompose(t *testing.T) {
	var nilSource *HKDFSource
	sources := map[string]*HKDFSource{
		"nil receiver":      nilSource,
		"zero HKDFSource{}": {},
	}
	composes := map[string]string{
		"tokenised":  "services:\n  db:\n    environment:\n      PW: ${secret:db-password}\n",
		"token-free": "services:\n  web:\n    image: nginx\n",
	}
	for sname, src := range sources {
		for cname, compose := range composes {
			t.Run(sname+"/"+cname, func(t *testing.T) {
				v, err := src.ResolveCompose(context.Background(), "01APPID", compose)
				if err == nil || err.Error() != "appsecret: HKDF source has no seed" {
					t.Fatalf("err = %v, want %q", err, "appsecret: HKDF source has no seed")
				}
				if v.Len() != 0 {
					t.Fatalf("value Len = %d, want 0", v.Len())
				}
			})
		}
	}
}

// TC-692-11: the adapter returns exactly Resolve at InitialVersion, and a
// token-free compose comes back byte for byte.
func TestHKDFSourceEqualsResolveAtInitialVersion(t *testing.T) {
	seed := sourceTestSeed(t)
	src, err := NewHKDFSource(seed)
	if err != nil {
		t.Fatalf("NewHKDFSource: %v", err)
	}
	const id = "01APPID"
	for name, compose := range map[string]string{
		"tokenised":  "services:\n  db:\n    environment:\n      PW: ${secret:db-password}\n      U: ${secret:admin-user}\n",
		"token-free": "services:\n  web:\n    image: nginx\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := src.ResolveCompose(context.Background(), id, compose)
			if err != nil {
				t.Fatalf("ResolveCompose: %v", err)
			}
			want, err := Resolve(compose, id, seed, InitialVersion)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if !bytes.Equal(got.Reveal(), want.Reveal()) {
				t.Fatal("ResolveCompose differs from Resolve at InitialVersion")
			}
			if name == "token-free" && !bytes.Equal(got.Reveal(), []byte(compose)) {
				t.Fatal("a token-free compose was not returned verbatim")
			}
			if name == "tokenised" && bytes.Contains(got.Reveal(), []byte("${secret:")) {
				t.Fatal("a token survived resolution")
			}
		})
	}
}

// TC-692-12: a malformed token is Resolve's refusal, passed through unchanged
// with the zero Value.
func TestHKDFSourcePassesResolvesRefusalThrough(t *testing.T) {
	seed := sourceTestSeed(t)
	src, err := NewHKDFSource(seed)
	if err != nil {
		t.Fatalf("NewHKDFSource: %v", err)
	}
	const id = "01APPID"
	compose := "services:\n  db:\n    environment:\n      PW: ${secret:db-password\n"
	got, err := src.ResolveCompose(context.Background(), id, compose)
	if err == nil {
		t.Fatal("a malformed token was not refused")
	}
	_, want := Resolve(compose, id, seed, InitialVersion)
	if want == nil || err.Error() != want.Error() {
		t.Fatalf("err = %v, want Resolve's %v", err, want)
	}
	if got.Len() != 0 {
		t.Fatalf("value Len = %d, want 0", got.Len())
	}
}
