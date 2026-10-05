package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TC-825-32: the create-mesh-key handler reveals the minted key into its one
// response, exactly as minted; a mint failure answers an error with no
// hsValue and records no intent.
func TestHandleCreateMeshKey_ReturnsTheMintedKeyOnce(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/keys", `{"name":"laptop"}`, c)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		HSValue string `json:"hsValue"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The fake mints "plain-<user>".
	if want := "plain-" + f.meshFake.lastCreate.User; got.HSValue != want {
		t.Errorf("hsValue = %q, want the minted key %q", got.HSValue, want)
	}

	f.meshFake.createErr = errors.New("headscale down")
	w = f.do(t, http.MethodPost, "/api/mesh/keys", `{"name":"phone"}`, c)
	if w.Code < 400 {
		t.Fatalf("a failed mint answered %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "hsValue") {
		t.Errorf("a failed mint's response carries hsValue: %s", w.Body.String())
	}
	w = f.do(t, http.MethodGet, "/api/mesh/keys", "", c)
	var list []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Errorf("after a failed mint the keys are %s (err %v), want only the first", w.Body.String(), err)
	}
}
