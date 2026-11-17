package apprelay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-1084-22: the key routes. POST and DELETE /v1/keys/{name} are create and
// destroy; POST …/encrypt and …/decrypt carry the value in and out under
// their own JSON names; GET and PUT answer 405; an oversized body 413; the
// forwarded app is the socket's own whatever the request says; and each
// reply code maps to its status.
func TestKeyRoutes_HTTPContract(t *testing.T) {
	type call struct {
		method, path, body string
		reply              proto.AppSecretReply
		status             int
		code               string
		wantOp, wantValue  string
		answerKey          string
	}
	ok := proto.AppSecretReply{Code: proto.AppSecretOK, Value: "out"}
	for name, c := range map[string]call{
		"POST create":        {http.MethodPost, "/v1/keys/wrap", "", ok, http.StatusCreated, "", proto.AppKeyCreate, "", ""},
		"DELETE destroy":     {http.MethodDelete, "/v1/keys/wrap", "", ok, http.StatusNoContent, "", proto.AppKeyDestroy, "", ""},
		"encrypt":            {http.MethodPost, "/v1/keys/wrap/encrypt", `{"plaintext":"aGk="}`, ok, http.StatusOK, "", proto.AppKeyEncrypt, "aGk=", "ciphertext"},
		"decrypt":            {http.MethodPost, "/v1/keys/wrap/decrypt", `{"ciphertext":"vault:v1:x"}`, ok, http.StatusOK, "", proto.AppKeyDecrypt, "vault:v1:x", "plaintext"},
		"GET a key":          {http.MethodGet, "/v1/keys/wrap", "", ok, http.StatusMethodNotAllowed, proto.AppSecretMethodNotAllowed, "", "", ""},
		"PUT a key":          {http.MethodPut, "/v1/keys/wrap", "", ok, http.StatusMethodNotAllowed, proto.AppSecretMethodNotAllowed, "", "", ""},
		"GET encrypt":        {http.MethodGet, "/v1/keys/wrap/encrypt", "", ok, http.StatusMethodNotAllowed, proto.AppSecretMethodNotAllowed, "", "", ""},
		"PUT decrypt":        {http.MethodPut, "/v1/keys/wrap/decrypt", "", ok, http.StatusMethodNotAllowed, proto.AppSecretMethodNotAllowed, "", "", ""},
		"body over the cap":  {http.MethodPost, "/v1/keys/wrap/encrypt", strings.Repeat(" ", maxBodyBytes+1) + `{"plaintext":"aGk="}`, ok, http.StatusRequestEntityTooLarge, proto.AppSecretTooLarge, "", "", ""},
		"wrong field":        {http.MethodPost, "/v1/keys/wrap/encrypt", `{"value":"aGk="}`, ok, http.StatusBadRequest, proto.AppSecretInvalid, "", "", ""},
		"malformed JSON":     {http.MethodPost, "/v1/keys/wrap/decrypt", `{"ciphertext":`, ok, http.StatusBadRequest, proto.AppSecretInvalid, "", "", ""},
		"no key":             {http.MethodPost, "/v1/keys/wrap/decrypt", `{"ciphertext":"vault:v1:x"}`, proto.AppSecretReply{Code: proto.AppSecretNotFound, Message: "The key does not exist."}, http.StatusNotFound, proto.AppSecretNotFound, proto.AppKeyDecrypt, "vault:v1:x", ""},
		"bad ciphertext":     {http.MethodPost, "/v1/keys/wrap/decrypt", `{"ciphertext":"vault:v1:x"}`, proto.AppSecretReply{Code: proto.AppSecretInvalid, Message: "No."}, http.StatusBadRequest, proto.AppSecretInvalid, proto.AppKeyDecrypt, "vault:v1:x", ""},
		"forbidden":          {http.MethodPost, "/v1/keys/wrap", "", proto.AppSecretReply{Code: proto.AppSecretForbidden, Message: "Refused."}, http.StatusForbidden, proto.AppSecretForbidden, proto.AppKeyCreate, "", ""},
		"unavailable":        {http.MethodDelete, "/v1/keys/wrap", "", proto.AppSecretReply{Code: proto.AppSecretUnavailable, Message: "Later."}, http.StatusServiceUnavailable, proto.AppSecretUnavailable, proto.AppKeyDestroy, "", ""},
		"an unknown subpath": {http.MethodPost, "/v1/keys/wrap/rotate", "", ok, http.StatusNotFound, proto.AppSecretNotFound, "", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			fwd := &fakeForwarder{reply: c.reply}
			srv := httptest.NewServer(routes(appA, fwd, counter()))
			defer srv.Close()
			req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(c.body))
			req.Header.Set("X-Rasputin-App", "01J9ZK3Q0M8X7Y6W5V4T3S2R1B")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != c.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, c.status)
			}
			var body map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&body)
			if c.code != "" && (body["code"] != c.code || body["correlationId"] == "" || !strings.HasSuffix(body["message"], ".")) {
				t.Errorf("error body %v, want code %s with a sentence and a correlation id", body, c.code)
			}
			if c.answerKey != "" && (body[c.answerKey] != "out" || len(body) != 1) {
				t.Errorf("answer %v, want {%q:\"out\"}", body, c.answerKey)
			}
			got := fwd.seen()
			if c.wantOp == "" {
				if len(got) != 0 {
					t.Errorf("an agent-side refusal forwarded %d calls", len(got))
				}
				return
			}
			if len(got) != 1 || got[0].AppID != appA || got[0].Op != c.wantOp || got[0].Name != "wrap" || got[0].Value != c.wantValue {
				t.Errorf("forwarded %+v, want app %s op %s name wrap value %q", got, appA, c.wantOp, c.wantValue)
			}
		})
	}
}

// TC-1084-16 (agent side): the largest plaintext the bound accepts is
// forwarded, one byte more is 413 too_large with nothing forwarded, and the
// largest ciphertext that plaintext makes (10-digit version) is forwarded to
// decrypt.
func TestKeyRoutes_SizeBound(t *testing.T) {
	maxCT := "vault:v" + strings.Repeat("9", 10) + ":" + base64.StdEncoding.EncodeToString(make([]byte, 12+proto.AppKeyMaxPlaintextBytes+16))
	for _, c := range []struct {
		name, path, field, value string
		status                   int
	}{
		{"the largest plaintext", "/v1/keys/k/encrypt", "plaintext", base64.StdEncoding.EncodeToString(make([]byte, proto.AppKeyMaxPlaintextBytes)), http.StatusOK},
		{"one byte over", "/v1/keys/k/encrypt", "plaintext", base64.StdEncoding.EncodeToString(make([]byte, proto.AppKeyMaxPlaintextBytes+1)), http.StatusRequestEntityTooLarge},
		{"the largest ciphertext", "/v1/keys/k/decrypt", "ciphertext", maxCT, http.StatusOK},
		{"a ciphertext over the value bound", "/v1/keys/k/decrypt", "ciphertext", strings.Repeat("A", proto.AppRelayMaxValueBytes+1), http.StatusRequestEntityTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			fwd := &fakeForwarder{reply: proto.AppSecretReply{Code: proto.AppSecretOK, Value: "x"}}
			srv := httptest.NewServer(routes(appA, fwd, counter()))
			defer srv.Close()
			b, _ := json.Marshal(map[string]string{c.field: c.value})
			resp, err := http.Post(srv.URL+c.path, "application/json", strings.NewReader(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var body map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&body)
			if resp.StatusCode != c.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, c.status)
			}
			if c.status == http.StatusRequestEntityTooLarge && (body["code"] != proto.AppSecretTooLarge || len(fwd.seen()) != 0) {
				t.Errorf("body %v, %d forwarded; want too_large and none", body, len(fwd.seen()))
			}
			if c.status == http.StatusOK && (len(fwd.seen()) != 1 || fwd.seen()[0].Value != c.value) {
				t.Errorf("the value was not forwarded whole")
			}
		})
	}
}
