package signin

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/iotest"
)

// vectors is testdata/signin-vectors.json, schema 1: the file the Go client
// and the Python client (#967) both pass.
type vectors struct {
	Schema int `json:"schema"`
	PKCE   *struct {
		Verifier, Challenge string
	} `json:"pkce_rfc7636"`
	TOTP *struct {
		SeedASCII string               `json:"seed_ascii"`
		KeyBytes  map[string]int       `json:"key_bytes"`
		Digits    int                  `json:"digits"`
		Period    int64                `json:"period"`
		Cases     [][3]json.RawMessage `json:"cases"`
	} `json:"totp_rfc6238"`
	WebAuthn *struct {
		Assertion    json.RawMessage `json:"assertion"`
		Registration json.RawMessage `json:"registration"`
	} `json:"webauthn"`
	Pages []struct {
		ID      string `json:"id"`
		Fixture string `json:"fixture"`
		SHA256  string `json:"sha256"`
		Forms   []struct {
			ID     string   `json:"id"`
			Fields []string `json:"fields"`
		} `json:"forms"`
	} `json:"pages"`
	Flows []struct {
		Step    string   `json:"step"`
		Verb    string   `json:"verb"`
		PageIDs []string `json:"page_ids"`
	} `json:"flows"`
	Source *struct {
		Keycloak, Run string
	} `json:"source"`
}

const vectorFile = "../testdata/signin-vectors.json"

func loadVectors(t *testing.T) (vectors, []byte) {
	t.Helper()
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v, raw
}

// TC-966-09: each of #959's 12 fixtures parses to its own id and the forms
// and fields the vector file lists (written from #959's Python parser, so the
// two parsers are checked against each other), and its bytes hash to the
// file's sha256. An unknown id and a missing id are refused.
func TestParsePage_Fixtures(t *testing.T) {
	v, _ := loadVectors(t)
	if len(v.Pages) != 12 || len(v.Pages) != len(KnownPages) {
		t.Fatalf("%d pages in the vector file, %d known; want 12 of each", len(v.Pages), len(KnownPages))
	}
	for _, want := range v.Pages {
		t.Run(want.ID, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("..", "testdata", want.Fixture))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) != want.SHA256 {
				t.Errorf("%s sha256 = %x, the vector file says %s", want.Fixture, sum, want.SHA256)
			}
			page, err := ParsePage(b)
			if err != nil {
				t.Fatal(err)
			}
			if page.ID != want.ID {
				t.Errorf("id = %q, want %q", page.ID, want.ID)
			}
			if len(page.Forms) != len(want.Forms) {
				t.Fatalf("%d forms, want %d: %+v", len(page.Forms), len(want.Forms), page.Forms)
			}
			for i, wf := range want.Forms {
				got := page.Forms[i]
				var names []string
				for k := range got.Fields {
					names = append(names, k)
				}
				sort.Strings(names)
				if got.ID != wf.ID || strings.Join(names, ",") != strings.Join(wf.Fields, ",") {
					t.Errorf("form %d = %q %v, want %q %v", i, got.ID, names, wf.ID, wf.Fields)
				}
			}
		})
	}
}

func TestParsePage_Refusals(t *testing.T) {
	_, err := ParsePage([]byte(`<html><body data-page-id="login-new-thing"><form id="f"></form></body></html>`))
	var u *UnknownPageError
	if !errors.As(err, &u) || u.ID != "login-new-thing" {
		t.Errorf("unknown id: err = %v, want *UnknownPageError{login-new-thing}", err)
	}
	if _, err := ParsePage([]byte(`<html><body><p>hello</p></body></html>`)); !errors.Is(err, ErrNoPageID) ||
		!strings.Contains(err.Error(), "no data-page-id") {
		t.Errorf("missing id: err = %v, want ErrNoPageID", err)
	}
	if _, err := ParsePage(nil); !errors.Is(err, ErrNoPageID) {
		t.Errorf("empty page: err = %v, want ErrNoPageID", err)
	}
}

// The feedback sentence is read from the page, as a person would read it.
func TestParsePage_Alert(t *testing.T) {
	for id, want := range map[string]string{
		"login-error":          "This account signs in with two steps, and none of its second steps works here. Ask another administrator to reset your sign-in.",
		"login-webauthn-error": "Passkey origin mismatch.",
		"login-login":          "",
	} {
		b, err := os.ReadFile(filepath.Join("..", "testdata", "pages", id+".html"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePage(b)
		if err != nil || p.Alert != want {
			t.Errorf("%s alert = %q, %v; want %q", id, p.Alert, err, want)
		}
	}
}

// TC-966-10: Challenge reproduces RFC 7636's appendix B pair from the vector
// file; Verifier reads 43 to 128 unreserved characters from its reader and
// wraps a reader's error.
func TestPKCE(t *testing.T) {
	v, _ := loadVectors(t)
	if v.PKCE == nil || v.PKCE.Verifier == "" {
		t.Fatal("the vector file has no pkce_rfc7636")
	}
	if got := Challenge(v.PKCE.Verifier); got != v.PKCE.Challenge {
		t.Errorf("Challenge(%q) = %q, want %q", v.PKCE.Verifier, got, v.PKCE.Challenge)
	}
	ver, err := Verifier(strings.NewReader(strings.Repeat("\x07", 64)))
	if err != nil {
		t.Fatal(err)
	}
	if len(ver) < 43 || len(ver) > 128 {
		t.Errorf("verifier length %d, want 43 to 128", len(ver))
	}
	for _, r := range ver {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", r) {
			t.Errorf("verifier %q holds %q, outside the unreserved set", ver, r)
		}
	}
	errX := errors.New("reader broke")
	if _, err := Verifier(iotest.ErrReader(errX)); !errors.Is(err, errX) {
		t.Errorf("Verifier on a failing reader = %v, want it wrapped", err)
	}
}

// webauthnSHA256 are the sha256 of encoding/json's form of #959's
// vectors.json "assertion" and "registration" objects (keys sorted,
// compact), taken from geekdojo-brain
// projects/rasputin/research/identity-evidence/959/harness/spike/959/vectors.json
// when this file was written. The vector file's copies must hash the same.
const (
	assertionVectorSHA256    = "d8f8ab559b70d60d0065a93e35e783544e88f4f782d92dc795c17ae047b1eca7"
	registrationVectorSHA256 = "7464492425e67ab0dc342f3a5015593e12577308bb7a65db6b3f579c9bb77a1a"
)

func canonicalSHA256(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TC-966-11: the vector file is schema 1 with every section; the webauthn
// sections are #959's unchanged; every TOTP case reproduces from the ASCII
// seed; and the file holds no hex TOTP key literal (what gitleaks flagged on
// #959).
func TestVectorFile(t *testing.T) {
	v, raw := loadVectors(t)
	if v.Schema != 1 {
		t.Errorf("schema = %d, want 1", v.Schema)
	}
	if v.PKCE == nil || v.TOTP == nil || v.WebAuthn == nil || v.Source == nil || len(v.Pages) == 0 || len(v.Flows) == 0 {
		t.Fatalf("a section is missing: %+v", v)
	}
	if v.WebAuthn.Assertion == nil || v.WebAuthn.Registration == nil {
		t.Fatal("webauthn.assertion or webauthn.registration is missing")
	}
	if got := canonicalSHA256(t, v.WebAuthn.Assertion); got != assertionVectorSHA256 {
		t.Errorf("webauthn.assertion differs from #959's: sha256 %s", got)
	}
	if got := canonicalSHA256(t, v.WebAuthn.Registration); got != registrationVectorSHA256 {
		t.Errorf("webauthn.registration differs from #959's: sha256 %s", got)
	}
	if v.Source.Keycloak != "26.8.2" {
		t.Errorf("source.keycloak = %q", v.Source.Keycloak)
	}

	hashes := map[string]func() hash.Hash{"sha1": sha1.New, "sha256": sha256.New, "sha512": sha512.New}
	if len(v.TOTP.Cases) == 0 {
		t.Fatal("no TOTP cases")
	}
	for _, c := range v.TOTP.Cases {
		var at int64
		var alg, want string
		if json.Unmarshal(c[0], &at) != nil || json.Unmarshal(c[1], &alg) != nil || json.Unmarshal(c[2], &want) != nil {
			t.Fatalf("case %s is not [time, hash, code]", c)
		}
		n, ok := v.TOTP.KeyBytes[alg]
		newHash, known := hashes[alg]
		if !ok || !known {
			t.Fatalf("case hash %q has no key length or no implementation", alg)
		}
		key := []byte(strings.Repeat(v.TOTP.SeedASCII, n/len(v.TOTP.SeedASCII)+1)[:n])
		if got := totp(newHash, key, at, v.TOTP.Period, v.TOTP.Digits); got != want {
			t.Errorf("TOTP %s at %d = %s, want %s", alg, at, got, want)
		}
	}
	seedHex := hex.EncodeToString([]byte(v.TOTP.SeedASCII))
	if strings.Contains(string(raw), seedHex[:16]) {
		t.Errorf("the vector file holds the TOTP seed as hex (%s…)", seedHex[:16])
	}
}

// totp is RFC 6238 over stdlib HMAC, the reference the vectors are checked
// against.
func totp(newHash func() hash.Hash, key []byte, at, period int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at/period))
	m := hmac.New(newHash, key)
	_, _ = m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// The flows section is every verb of #959's run in order; the password
// sign-in this client implements saw exactly login-login.
func TestVectorFile_Flows(t *testing.T) {
	v, _ := loadVectors(t)
	found := false
	for _, f := range v.Flows {
		if f.Step == "FL2" {
			found = f.Verb == "sign-in" && strings.Join(f.PageIDs, ",") == "login-login"
		}
	}
	if !found {
		t.Error("flows has no FL2 password sign-in seeing [login-login]")
	}
}
