package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storeswitch"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The operator secret endpoints' codes (geekdojo/geekdojo-brain#604).
const (
	codeAppNotFound               = "app_not_found"
	codeOperatorSecretNotDeclared = "operator_secret_not_declared"
	codeInvalidSecretName         = "invalid_secret_name"
	codeSecretValueInvalid        = "secret_value_invalid"
	codeInvalidRequest            = "invalid_request"
	codeSecretWriteConflict       = "secret_write_conflict"
	codeSecretStoreSwitchFailed   = "secret_store_switch_failed"
	codeOperatorSecretFailed      = "operator_secret_failed"
)

// The sentences each code carries. None names a value.
const (
	msgAppNotFound               = "No app has that ID."
	msgOperatorSecretNotDeclared = "This app does not ask its owner for a secret by that name."
	msgInvalidSecretName         = "The secret name must be 1 to 63 lower-case letters, digits or hyphens, and cannot start or end with a hyphen."
	msgSecretValueInvalid        = "The value was refused. It must not be empty, must not contain a NUL byte, and must not be a date and time in RFC 3339 form."
	msgInvalidRequest            = "The request body must be a JSON object with a single string field, value, and be no larger than 8 KiB."
	msgSecretWriteConflict       = "Another request changed this secret at the same time, so this value was not saved. Try again."
	msgSecretStoreUnavailable    = "The secret store could not save the value. The api log names the cause."
	msgSecretStoreSwitchFailed   = "The value was not saved, because the control plane could not record that this cluster now holds owner-supplied secrets. The api log names the cause."
	msgOperatorSecretFailed      = "The secret could not be saved. The api log names the cause."
	msgOperatorSecretsListFailed = "The app's secrets could not be listed. The api log names the cause."
)

// operatorSecretBodyLimit caps the PUT body, as the console password's is.
const operatorSecretBodyLimit = 8 << 10

// operatorSecretsService is the business service the operator secret
// endpoints call (*apps.OperatorSecrets).
type operatorSecretsService interface {
	Status(ctx context.Context, appID string) ([]apps.OperatorSecretStatus, error)
	Set(ctx context.Context, user, appID, name string, value secret.Value) error
}

// operatorSecretRequest is the PUT body. The value travels only here: never
// in the URL, and nothing echoes it.
type operatorSecretRequest struct {
	Value *string `json:"value"`
}

// GET /api/apps/{id}/secrets
// The app's declared operator secrets: name, label, required and set. Never
// a value. It makes no store call, so it answers while the store is sealed.
func (s *Server) handleListOperatorSecrets(w http.ResponseWriter, r *http.Request) {
	id, ok := s.operatorSecretAppID(w, r)
	if !ok {
		return
	}
	st, err := s.operatorSecrets.Status(r.Context(), id)
	switch {
	case errors.Is(err, apps.ErrAppNotFound):
		s.writeCodedError(w, r, http.StatusNotFound, codeAppNotFound, msgAppNotFound, slog.String("app_id", id))
		return
	case err != nil:
		s.writeCodedError(w, r, http.StatusInternalServerError, codeOperatorSecretFailed, msgOperatorSecretsListFailed,
			slog.String("app_id", id), slog.String("err", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// PUT /api/apps/{id}/secrets/{name}
// Body: {"value": "…"}. Sets the app's declared operator secret, write-only,
// and answers 204. It submits no job and starts no redeploy: the owner
// deploys the app to deliver the value.
func (s *Server) handlePutOperatorSecret(w http.ResponseWriter, r *http.Request) {
	id, ok := s.operatorSecretAppID(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !tileschema.ValidSecretName(name) {
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidSecretName, msgInvalidSecretName,
			slog.String("app_id", id), slog.String("cause", "name_invalid"))
		return
	}
	var req operatorSecretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, operatorSecretBodyLimit)).Decode(&req); err != nil || req.Value == nil {
		// The decoder's own text can quote the body's bytes, which are the
		// credential, so only a fixed cause is logged (F-604-03).
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, msgInvalidRequest,
			slog.String("app_id", id), slog.String("name", name), slog.String("cause", bodyCause(err)))
		return
	}
	value := secret.New([]byte(*req.Value))
	err := s.operatorSecrets.Set(r.Context(), userName(r), id, name, value)
	value.Destroy()
	if err != nil {
		s.writeOperatorSecretError(w, r, id, name, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// operatorSecretAppID parses {id} at the boundary (SEC-INPUT). An ID no app
// can have (not a canonical upper-case ULID, as the api mints them) is the
// not-found answer, with no service call.
func (s *Server) operatorSecretAppID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !proto.ValidAppID(id) || strings.ToUpper(id) != id {
		s.writeCodedError(w, r, http.StatusNotFound, codeAppNotFound, msgAppNotFound, slog.String("cause", "id_invalid"))
		return "", false
	}
	return id, true
}

// bodyCause is the fixed cause of a body that did not decode: never the
// decoder's text.
func bodyCause(err error) string {
	var tooLarge *http.MaxBytesError
	switch {
	case err == nil:
		return "value_missing"
	case errors.As(err, &tooLarge):
		return "body_too_large"
	case errors.Is(err, io.EOF):
		return "body_empty"
	}
	return "body_not_json"
}

// writeOperatorSecretError maps Set's error to its status and code. The
// order matters: an invalid value is a store-kind error too, and the switch
// refusing because no store exists is a switch error too.
func (s *Server) writeOperatorSecretError(w http.ResponseWriter, r *http.Request, id, name string, err error) {
	at := []slog.Attr{slog.String("app_id", id), slog.String("name", name)}
	var se *secretstore.Error
	switch {
	case errors.Is(err, apps.ErrAppNotFound), errors.Is(err, secrets.ErrNoSuchApp):
		s.writeCodedError(w, r, http.StatusNotFound, codeAppNotFound, msgAppNotFound, at...)
	case errors.Is(err, apps.ErrOperatorSecretNotDeclared):
		s.writeCodedError(w, r, http.StatusNotFound, codeOperatorSecretNotDeclared, msgOperatorSecretNotDeclared, at...)
	case errors.Is(err, apps.ErrOperatorSecretEmpty):
		s.writeCodedError(w, r, http.StatusBadRequest, codeSecretValueInvalid, msgSecretValueInvalid,
			append(at, slog.String("cause", "value_empty"))...)
	case errors.Is(err, secretstore.ErrInvalidValue):
		s.writeCodedError(w, r, http.StatusBadRequest, codeSecretValueInvalid, msgSecretValueInvalid,
			append(at, slog.String("cause", "value_invalid"))...)
	case errors.Is(err, secrets.ErrConflict):
		s.writeCodedError(w, r, http.StatusConflict, codeSecretWriteConflict, msgSecretWriteConflict, at...)
	case errors.Is(err, storeswitch.ErrNoStore):
		s.writeCodedError(w, r, http.StatusServiceUnavailable, appsecret.CodeStoreUnavailable, msgSecretStoreUnavailable,
			append(at, slog.String("cause", "no_store"))...)
	case errors.As(err, &se):
		s.writeCodedError(w, r, http.StatusServiceUnavailable, appsecret.CodeStoreUnavailable, msgSecretStoreUnavailable,
			append(at, se.LogAttrs()...)...)
	case errors.Is(err, secrets.ErrSwitch):
		s.writeCodedError(w, r, http.StatusInternalServerError, codeSecretStoreSwitchFailed, msgSecretStoreSwitchFailed,
			append(at, slog.String("err", err.Error()))...)
	default:
		s.writeCodedError(w, r, http.StatusInternalServerError, codeOperatorSecretFailed, msgOperatorSecretFailed,
			append(at, slog.String("err", err.Error()))...)
	}
}
