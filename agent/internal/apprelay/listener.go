package apprelay

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// headerTimeout bounds reading one request's headers on the socket. It only
// bounds that I/O: a client that sends nothing is far outside normal bounds.
const headerTimeout = 10 * time.Second

// maxBodyBytes bounds a request body: room for the largest value the relay
// accepts, JSON-escaped. The value itself is then checked against
// proto.AppRelayMaxValueBytes.
const maxBodyBytes = 2*proto.AppRelayMaxValueBytes + 1024

// listener is one app's socket: a Unix listener under TLS 1.3, serving the
// relay's HTTP routes.
type listener struct {
	srv *http.Server
}

// listen opens the socket at sockPath for appID, removing a stale socket file
// a previous process left first. The certificate and key are read from disk
// at each handshake, so a re-install takes effect with no restart.
func listen(appID, sockPath, certPath, keyPath string, fwd Forwarder, ids func() string, log *slog.Logger) (*listener, error) {
	if err := os.Remove(sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove the stale relay socket of %s: %w", appID, err)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("open the relay socket of %s: %w", appID, err)
	}
	if err := os.Chmod(sockPath, socketMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("open the relay socket of %s: %w", appID, err)
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &c, nil
		},
	}
	srv := &http.Server{
		Handler:           routes(appID, fwd, ids),
		ReadHeaderTimeout: headerTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		// Serve returns ErrServerClosed once close runs; anything else means
		// the socket stopped answering, which the app sees and the log says.
		if err := srv.Serve(tls.NewListener(ln, cfg)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("app relay socket stopped", "component", "apprelay", "event", "apprelay.serve_failed", "app_id", appID, "err", err.Error())
		}
	}()
	return &listener{srv: srv}, nil
}

// close stops the socket. Close also closes the listener, which removes the
// socket file.
func (l *listener) close() { _ = l.srv.Close() }

// valueBody is the JSON body of a create or replace, and of a read's answer.
type valueBody struct {
	Value string `json:"value"`
}

// errorBody is every error the socket answers with: a stable code, a safe
// sentence and a correlation id (ERR-BOUNDARY).
type errorBody struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlationId"`
}

// routes is the relay's HTTP API on one app's socket:
//
//	GET    /v1/secrets/{name}  read      200 {"value":…}, 404
//	POST   /v1/secrets/{name}  create    201, 409 when it exists
//	PUT    /v1/secrets/{name}  replace   200, 404 when it is absent
//	DELETE /v1/secrets/{name}  delete    204, present or absent
//
// The app the call is for is appID, the socket's own, whatever the path,
// headers or body say.
func routes(appID string, fwd Forwarder, ids func() string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var op string
		switch r.Method {
		case http.MethodGet:
			op = proto.AppSecretRead
		case http.MethodPost:
			op = proto.AppSecretCreate
		case http.MethodPut:
			op = proto.AppSecretReplace
		case http.MethodDelete:
			op = proto.AppSecretDelete
		default:
			w.Header().Set("Allow", "GET, POST, PUT, DELETE")
			writeError(w, http.StatusMethodNotAllowed, proto.AppSecretMethodNotAllowed, "The method is not one the relay answers; use GET, POST, PUT or DELETE.", ids())
			return
		}
		call := proto.AppSecretCall{AppID: appID, Op: op, Name: name}
		if op == proto.AppSecretCreate || op == proto.AppSecretReplace {
			var body valueBody
			err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body)
			var tooBig *http.MaxBytesError
			switch {
			case errors.As(err, &tooBig) || err == nil && len(body.Value) > proto.AppRelayMaxValueBytes:
				writeError(w, http.StatusRequestEntityTooLarge, proto.AppSecretTooLarge,
					fmt.Sprintf("The value is longer than %d bytes.", proto.AppRelayMaxValueBytes), ids())
				return
			case err != nil:
				writeError(w, http.StatusBadRequest, proto.AppSecretInvalid, `The body is not JSON of the form {"value":"..."}.`, ids())
				return
			}
			call.Value = body.Value
		}
		answer(w, op, fwd.Forward(appID, call, ids()))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, proto.AppSecretNotFound, "The path is not one the relay answers; use /v1/secrets/{name}.", ids())
	})
	return mux
}

// answer writes the api's reply to op as its HTTP status and body.
func answer(w http.ResponseWriter, op string, rep proto.AppSecretReply) {
	if rep.Code == proto.AppSecretOK {
		switch op {
		case proto.AppSecretRead:
			writeJSON(w, http.StatusOK, valueBody{Value: rep.Value})
		case proto.AppSecretCreate:
			w.WriteHeader(http.StatusCreated)
		case proto.AppSecretReplace:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	writeError(w, statusFor(rep.Code), rep.Code, rep.Message, rep.CorrelationID)
}

// statusFor maps a reply's code to its HTTP status. A code this agent does
// not know is the api failing, never the app's fault.
func statusFor(code string) int {
	switch code {
	case proto.AppSecretNotFound:
		return http.StatusNotFound
	case proto.AppSecretExists, proto.AppSecretConflict:
		return http.StatusConflict
	case proto.AppSecretForbidden:
		return http.StatusForbidden
	case proto.AppSecretInvalid:
		return http.StatusBadRequest
	case proto.AppSecretUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

func writeError(w http.ResponseWriter, status int, code, message, cid string) {
	writeJSON(w, status, errorBody{Code: code, Message: message, CorrelationID: cid})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
