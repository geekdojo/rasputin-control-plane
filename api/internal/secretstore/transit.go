package secretstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The Transit calls an app's keys need (geekdojo/geekdojo-brain#1084): create
// a key, encrypt and decrypt under it, and destroy it. Plaintext travels as
// the standard base64 Transit takes and returns; ciphertext is Transit's own
// vault:v<N>:<base64> text. Both travel as secret.Value, and the request body
// that carried them is cleared.

// TransitKeyType is the one key type the api creates, which the store's
// rasputin-app-keys policy pins at create.
const TransitKeyType = "aes256-gcm96"

// transitOpPrefix starts every Transit operation's name, so statusError reads
// Transit's 400 messages only for Transit calls.
const transitOpPrefix = "transit_"

// Transit answers an absent key, and a ciphertext that does not decrypt, with
// a 400 and a message, never a 404 (F-1084-05; measured on the pinned OpenBao
// 2.7.2). These are the messages that tell them from a malformed call.
var (
	transitAbsentTexts = []string{
		"no existing key named",           // keys/<k>/config on an absent key
		"could not delete key; not found", // DELETE keys/<k> on an absent key
		"encryption key not found",        // decrypt/<k> on an absent key
	}
	transitBadCiphertextTexts = []string{
		"message authentication failed", // tampered, or another key's
		"invalid ciphertext",            // a version too new, a bad length or bad base64
	}
)

// transitKind is the kind of a Transit call's 400: ErrNotFound for an absent
// key, ErrInvalidCiphertext for a ciphertext that does not decrypt, and
// ErrProtocol for anything else.
func transitKind(msgs []string) error {
	has := func(texts []string) bool {
		return slices.ContainsFunc(msgs, func(m string) bool {
			return slices.ContainsFunc(texts, func(t string) bool { return strings.Contains(m, t) })
		})
	}
	switch {
	case has(transitAbsentTexts):
		return ErrNotFound
	case has(transitBadCiphertextTexts):
		return ErrInvalidCiphertext
	}
	return ErrProtocol
}

// TransitCreateKey creates key k with TransitKeyType and no other parameter.
// A key that already exists is left as it is and is not an error.
func (c *Client) TransitCreateKey(ctx context.Context, token secret.Value, k TransitKey) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if e := c.transitCreateKey(ctx, token, k); e != nil {
		return c.failed(ctx, e)
	}
	return nil
}

// TransitEncrypt encrypts plaintext, standard base64, under k and returns the
// ciphertext. A key that does not exist is refused by the store's policy
// (ErrDenied): encrypt never creates a key.
func (c *Client) TransitEncrypt(ctx context.Context, token secret.Value, k TransitKey, plaintext secret.Value) (secret.Value, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	v, e := c.transitCrypt(ctx, "transit_encrypt", "encrypt", "plaintext", "ciphertext", token, k, plaintext)
	if e != nil {
		return secret.Value{}, c.failed(ctx, e)
	}
	return v, nil
}

// TransitDecrypt decrypts ciphertext under k and returns the plaintext,
// standard base64. An absent key is ErrNotFound; a ciphertext that does not
// decrypt under k is ErrInvalidCiphertext.
func (c *Client) TransitDecrypt(ctx context.Context, token secret.Value, k TransitKey, ciphertext secret.Value) (secret.Value, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	v, e := c.transitCrypt(ctx, "transit_decrypt", "decrypt", "ciphertext", "plaintext", token, k, ciphertext)
	if e != nil {
		return secret.Value{}, c.failed(ctx, e)
	}
	return v, nil
}

// TransitDestroyKey destroys k: it sets deletion_allowed, sent as the string
// "true" the policy pins, then deletes the key. An absent key is ErrNotFound
// at whichever step finds it; the caller decides whether that is done.
func (c *Client) TransitDestroyKey(ctx context.Context, token secret.Value, k TransitKey) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if e := c.transitDestroyKey(ctx, token, k); e != nil {
		return c.failed(ctx, e)
	}
	return nil
}

func (c *Client) transitCreateKey(ctx context.Context, token secret.Value, k TransitKey) *Error {
	const op = "transit_create"
	p := k.kvPath()
	if !k.valid() {
		return fail(op, p, ErrInvalidValue, errors.New("the key is the zero TransitKey"))
	}
	body := []byte(`{"type":"` + TransitKeyType + `"}`)
	status, rb, e := c.round(ctx, op, p, http.MethodPost, "/v1/"+k.mount+"/keys/"+k.name, &token, body)
	if e != nil {
		return e
	}
	defer clear(rb)
	if status != http.StatusOK && status != http.StatusNoContent {
		return c.statusError(ctx, op, p, status, rb)
	}
	return nil
}

// transitCrypt posts {in: value} to /v1/<mount>/<verb>/<name> and returns
// data.<out>.
func (c *Client) transitCrypt(ctx context.Context, op, verb, in, out string, token secret.Value, k TransitKey, value secret.Value) (secret.Value, *Error) {
	p := k.kvPath()
	if !k.valid() {
		return secret.Value{}, fail(op, p, ErrInvalidValue, errors.New("the key is the zero TransitKey"))
	}
	body := make([]byte, 0, len(in)+6*value.Len()+8)
	body = append(body, '{')
	body = appendJSONString(body, []byte(in))
	body = append(body, ':')
	body = appendJSONString(body, value.Reveal())
	body = append(body, '}')
	status, rb, e := c.round(ctx, op, p, http.MethodPost, "/v1/"+k.mount+"/"+verb+"/"+k.name, &token, body)
	if e != nil {
		return secret.Value{}, e
	}
	defer clear(rb)
	if status != http.StatusOK {
		return secret.Value{}, c.statusError(ctx, op, p, status, rb)
	}
	var env struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := decodeJSON(rb, &env); err != nil {
		return secret.Value{}, withStatus(fail(op, p, ErrProtocol, err), status)
	}
	defer func() {
		for _, raw := range env.Data {
			clear(raw)
		}
	}()
	raw, ok := env.Data[out]
	if !ok {
		return secret.Value{}, withStatus(fail(op, p, ErrProtocol, errors.New("the answer carries no "+out)), status)
	}
	v, err := decodeValue(raw)
	if err != nil {
		return secret.Value{}, withStatus(fail(op, p, ErrProtocol, err), status)
	}
	return v, nil
}

func (c *Client) transitDestroyKey(ctx context.Context, token secret.Value, k TransitKey) *Error {
	const op = "transit_destroy"
	p := k.kvPath()
	if !k.valid() {
		return fail(op, p, ErrInvalidValue, errors.New("the key is the zero TransitKey"))
	}
	status, rb, e := c.round(ctx, op, p, http.MethodPost, "/v1/"+k.mount+"/keys/"+k.name+"/config", &token, []byte(`{"deletion_allowed":"true"}`))
	if e != nil {
		return e
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		defer clear(rb)
		return c.statusError(ctx, op, p, status, rb)
	}
	clear(rb)
	status, rb, e = c.round(ctx, op, p, http.MethodDelete, "/v1/"+k.mount+"/keys/"+k.name, &token, nil)
	if e != nil {
		return e
	}
	defer clear(rb)
	if status != http.StatusNoContent && status != http.StatusOK {
		return c.statusError(ctx, op, p, status, rb)
	}
	return nil
}
