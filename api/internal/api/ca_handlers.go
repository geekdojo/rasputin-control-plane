package api

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The controlplane CA's download routes. Each serves <trustDir>/mesh-ca.pem —
// the controlplane TLS CA, whose routes and file name are compatibility names
// (tlsca package comment) — and never root-ca.pem (the bundle-signing root)
// or store-ca.pem (the store CA, which no device trusts). An earlier revision
// of the iOS handler delivered root-ca.pem by mistake, which would have made
// operator devices trust the wrong CA for the wrong purpose.
//
// Unauthenticated BY DESIGN (see Handler): the CA public cert is not a secret,
// and the first-run flow needs it before any passkey exists — the operator
// installs the CA over plain HTTP, then registers their first credential over
// HTTPS on a now-trusted connection.
//
// The bytes are read from the trust dir on every request, so a CA restore is
// picked up without a restart.

// caUnavailable is all a client is told when the CA cannot be read. The path
// and the error go to the log: neither is the client's to see (ERR-BOUNDARY).
const caUnavailable = "controlplane CA not available"

// readControlplaneCA reads the controlplane CA's PEM, or answers the request
// itself and returns false. A missing file is 404 (tlsca.Ensure creates it at
// start, so it is gone only if the trust dir was wiped since); any other
// failure is 500.
func (s *Server) readControlplaneCA(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if s.trustDir == "" {
		writeError(w, http.StatusNotFound, "trust dir not configured")
		return nil, false
	}
	path := filepath.Join(s.trustDir, tlsca.ControlplaneCertFile)
	caPEM, err := os.ReadFile(path)
	if err != nil {
		s.log.ErrorContext(r.Context(), "api: controlplane CA could not be read", "path", path, "err", err.Error())
		status := http.StatusInternalServerError
		if os.IsNotExist(err) {
			status = http.StatusNotFound
		}
		writeError(w, status, caUnavailable)
		return nil, false
	}
	return caPEM, true
}

// GET /api/mesh/ios-profile — an Apple .mobileconfig that installs the
// controlplane CA on the operator's device. iOS Safari recognises the
// content-type and disposition and offers to install the profile in Settings
// → General → VPN & Device Management. Required so the iOS Tailscale client
// trusts Headscale's TLS endpoint (see design/control-plane/certificates.md).
func (s *Server) handleMeshIOSProfile(w http.ResponseWriter, r *http.Request) {
	caPEM, ok := s.readControlplaneCA(w, r)
	if !ok {
		return
	}
	// The display name is the one installed devices already show; changing
	// it would give new installs a second name for the same CA.
	profile, err := BuildIOSMobileConfig(caPEM, "Rasputin Mesh TLS CA", "Rasputin")
	if err != nil {
		s.log.ErrorContext(r.Context(), "api: iOS profile could not be built", "err", err.Error())
		writeError(w, http.StatusInternalServerError, caUnavailable)
		return
	}
	// content-type that iOS Safari recognises; disposition triggers the
	// install prompt instead of rendering inline.
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="rasputin-trust.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(profile)
}

// GET /mesh-ca.pem — the controlplane CA public cert as raw PEM. The non-Apple
// counterpart to /api/mesh/ios-profile above: laptops curl this straight into
// their OS trust store (the /trust page shows the per-OS one-liners).
//
// Windows uses /mesh-ca.crt instead — same bytes, different envelope. See
// handleMeshCACRT.
func (s *Server) handleMeshCAPEM(w http.ResponseWriter, r *http.Request) {
	s.serveControlplaneCA(w, r, "application/x-pem-file", "rasputin-mesh-ca.pem")
}

// GET /mesh-ca.crt — the SAME CA bytes as /mesh-ca.pem, wrapped for Windows.
//
// Windows has no shell association for .pem: double-clicking one opens the
// "How do you want to open this file?" picker, which offers no "Install
// Certificate…" verb, so the /trust page's documented Windows steps used to
// dead-end (found 2026-09-15 bringing up a Windows workstation).
//
// This is deliberately NOT a format conversion. Windows crypt32 opens .cer
// and .crt with the Certificate Import Wizard and accepts base64 (PEM) inside
// them just as readily as DER, so the delivered bytes are already correct —
// only the extension and content-type were wrong. The same page's Debian
// one-liner has always renamed to .crt on the way down; Windows simply never
// got the same treatment.
//
// PKCS#12 (.pfx) would be the wrong shape: it is a private-key container, and
// the import wizard defaults it into the Personal store rather than Trusted
// Root — the wrong store for a public CA root.
//
// Byte-identical to /mesh-ca.pem by construction (both go through
// serveControlplaneCA), so the two routes cannot drift into advertising
// different CAs.
func (s *Server) handleMeshCACRT(w http.ResponseWriter, r *http.Request) {
	s.serveControlplaneCA(w, r, "application/x-x509-ca-cert", "rasputin-mesh-ca.crt")
}

// serveControlplaneCA writes the controlplane CA public cert with the given
// content-type and download filename.
func (s *Server) serveControlplaneCA(w http.ResponseWriter, r *http.Request, contentType, filename string) {
	caPEM, ok := s.readControlplaneCA(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(caPEM)
}
