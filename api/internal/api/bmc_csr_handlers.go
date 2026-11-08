package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bmccert"
)

// bmcCSRSigner is the business service behind POST /api/bmc/csr
// (*bmccert.Signer, geekdojo/geekdojo-brain#1065).
type bmcCSRSigner interface {
	Sign(ctx context.Context, user string, csr *x509.CertificateRequest) (bmccert.Signed, error)
}

// bmcCSRMaxBody bounds the request body. A Super4C BMC's request is about
// half a kilobyte.
const bmcCSRMaxBody = 8 << 10

// The sentences a refused request answers with.
const (
	msgBMCCSRInvalid    = "The request must carry one PEM certificate request from a Super4C BMC."
	msgBMCCSRSignature  = "The certificate request's signature does not verify."
	msgBMCCSRKeyType    = "The certificate request must use an ECDSA P-256 key."
	msgBMCCSRExtension  = "The certificate request asks for more than its name, such as a CA flag. Only the name is accepted."
	msgBMCCSRName       = "The certificate request must name exactly one host, rasputin-bmc-<12 lowercase hex digits>.local, and nothing else."
	msgBMCCSRNoUser     = "Signing a BMC certificate needs a signed-in operator."
	msgBMCCSRSignFailed = "The control plane could not sign the certificate request."
)

// bmcCSRRequest is {"csr":"<PEM>"}.
type bmcCSRRequest struct {
	CSR string `json:"csr"`
}

// bmcCSRResponse is the signed leaf and the CA that vouches for it.
type bmcCSRResponse struct {
	Name     string    `json:"name"`
	LeafPEM  string    `json:"leafPem"`
	CAPEM    string    `json:"caPem"`
	NotAfter time.Time `json:"notAfter"`
}

// handleBMCSignCSR signs a Super4C BMC's certificate request under the
// controlplane CA. 400 on a body that is not one PEM certificate request, or
// on a request the policy refuses; 403 with no operator to record; 500 when
// the CA could not sign. Nothing from the body is logged.
func (s *Server) handleBMCSignCSR(w http.ResponseWriter, r *http.Request) {
	csr, err := decodeBMCCSR(w, r)
	if err != nil {
		s.writeCodedError(w, r, http.StatusBadRequest, codeBMCCSRInvalid, msgBMCCSRInvalid, slog.String("cause", err.Error()))
		return
	}
	signed, err := s.bmcCSR.Sign(r.Context(), userName(r), csr)
	if err != nil {
		status, code, msg := bmcCSRRefusal(err)
		s.writeCodedError(w, r, status, code, msg, slog.String("cause", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, bmcCSRResponse{
		Name:     signed.Name,
		LeafPEM:  string(signed.LeafPEM),
		CAPEM:    string(signed.CAPEM),
		NotAfter: signed.NotAfter,
	})
}

// decodeBMCCSR reads the bounded body and returns its one certificate
// request. The error names what was wrong, never the bytes.
func decodeBMCCSR(w http.ResponseWriter, r *http.Request) (*x509.CertificateRequest, error) {
	var req bmcCSRRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, bmcCSRMaxBody)).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, errors.New("body over the size bound")
		}
		return nil, errors.New("body is not JSON")
	}
	block, rest := pem.Decode([]byte(req.CSR))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block is not a CERTIFICATE REQUEST")
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, errors.New("more than one PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.New("certificate request does not parse")
	}
	return csr, nil
}

// bmcCSRRefusal maps a Sign error to its response.
func bmcCSRRefusal(err error) (status int, code, msg string) {
	switch {
	case errors.Is(err, bmccert.ErrSignature):
		return http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRSignature
	case errors.Is(err, bmccert.ErrKeyType):
		return http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRKeyType
	case errors.Is(err, bmccert.ErrExtension):
		return http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRExtension
	case errors.Is(err, bmccert.ErrName):
		return http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRName
	case errors.Is(err, bmccert.ErrNoUser):
		return http.StatusForbidden, codeBMCCSRRefused, msgBMCCSRNoUser
	}
	return http.StatusInternalServerError, codeBMCCSRSignFailed, msgBMCCSRSignFailed
}
