package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// ============================================================================
// A software authenticator holding a pre-update passkey, so the tests drive
// the retired passkey sign-in through the real go-webauthn types.
// ============================================================================

type softAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	origin string
	rpID   string
	count  uint32
	// noUV makes the authenticator skip user verification (UV flag clear).
	noUV bool
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softAuthenticator{key: key, credID: id, origin: "http://localhost:3000", rpID: "localhost"}
}

// flags is UP | UV plus extra, without UV when the authenticator skips it.
func (a *softAuthenticator) flags(extra byte) byte {
	f := byte(0x05) | extra
	if a.noUV {
		f &^= 0x04
	}
	return f
}

// assert answers an assertion request (options JSON, bare or wrapped in
// "stepUp") as userID's passkey, returning the body the api expects.
func (a *softAuthenticator) assert(t *testing.T, optionsJSON []byte, userID []byte) string {
	t.Helper()
	var wrapped struct {
		StepUp    json.RawMessage `json:"stepUp"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &wrapped); err != nil {
		t.Fatalf("assertion options: %v", err)
	}
	if wrapped.StepUp != nil {
		optionsJSON = wrapped.StepUp
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil || opts.PublicKey.Challenge == "" {
		t.Fatalf("assertion options: %v %s", err, optionsJSON)
	}
	clientData, _ := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": opts.PublicKey.Challenge, "origin": a.origin,
	})
	rpHash := sha256.Sum256([]byte(a.rpID))
	a.count++
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, a.flags(0)) // UP | UV
	authData = binary.BigEndian.AppendUint32(authData, a.count)
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(userID),
		},
	})
	return string(body)
}

func (f *authFixture) handler() http.Handler {
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	return mux
}

// enrol gives u a passkey held by a new software authenticator, written
// straight to the store.
func (f *authFixture) enrol(t *testing.T, u *User) *softAuthenticator {
	t.Helper()
	a := newSoftAuthenticator(t)
	pub, err := a.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	raw := pub.Bytes()
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateCredential(f.ctx, &Credential{
		ID: a.credID, UserID: u.ID, PublicKey: cose, AttestationType: "none", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return a
}

func post(h http.Handler, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
