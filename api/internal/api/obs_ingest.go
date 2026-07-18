package api

import (
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Routes served on the api's dedicated mTLS ingress listener. Per-node Alloy
// collectors push here — metrics (§3.10) and, since Slice 1.2c, logs (§3.11).
const (
	obsIngestPattern     = "POST /api/obs/ingest"      // metrics remote-write
	obsLogsIngestPattern = "POST /api/obs/logs/ingest" // Loki log push
)

// Loopback backend paths the ingress forwards to.
const (
	// vmRemoteWritePath is VictoriaMetrics' Prometheus remote-write endpoint
	// (snappy protobuf). NOT the api's own host-metrics sink path
	// (/api/v1/import/prometheus, text); per-node Alloy speaks remote-write.
	vmRemoteWritePath = "/api/v1/write"
	// lokiPushPath is Loki's push endpoint (snappy protobuf). Unlike VM's
	// remote-write it has no extra_label query arg, so node_id is carried in the
	// stream labels by the collector's controlplane-rendered config, not stamped
	// here (§3.11 decision (a)).
	lokiPushPath = "/loki/api/v1/push"
)

// ObsIngestHandler builds the http.Handler served on the api's dedicated mTLS
// ingress listener (wired in main.go). Every route here has NO session
// middleware: the TLS handshake (RequireAndVerifyClientCert against the
// per-installation mesh CA) IS the authentication, and the verified client
// cert's CommonName is the authorization identity. Everything reachable on this
// listener must be safe to expose to any mesh-CA-signed node and nothing else.
//
// Kept separate from Handler()/BootstrapHandler() (the browser-facing surfaces,
// server-auth only — browsers don't present client certs) so requiring a client
// cert can't break the UI. See observability-stack.md §3.10–3.11.
func (s *Server) ObsIngestHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(obsIngestPattern, s.handleObsIngest)
	mux.HandleFunc(obsLogsIngestPattern, s.handleObsLogsIngest)
	return mux
}

// authenticateCollector runs the two authorization gates every mTLS ingress
// route shares, beyond the listener's already-completed RequireAndVerifyClient
// Cert handshake:
//
//  1. Identity — node_id is the verified client leaf's CommonName (mesh.MintLeaf
//     sets CN = node_id). Read from the cert, never from request data, so a node
//     cannot claim another's identity.
//  2. Membership / revocation — inv.Get returns (nil, nil) for an unknown id (a
//     leaf whose node was removed, or that outlived its node); reject it. A real
//     store error is a 503, not a 403 — we don't know membership, so we don't
//     silently drop the push.
//
// On any failure it writes the response and returns ok=false. `label` prefixes
// the log lines and error bodies so the two routes are distinguishable.
func (s *Server) authenticateCollector(w http.ResponseWriter, r *http.Request, label string) (nodeID string, ok bool) {
	nodeID, err := nodeIDFromClientCert(r.TLS)
	if err != nil {
		// Defense in depth: RequireAndVerifyClientCert should make this
		// unreachable, but fail closed rather than proxy anonymously.
		log.Printf("%s: rejecting request without a usable client cert: %v", label, err)
		writeError(w, http.StatusUnauthorized, label+": client certificate required")
		return "", false
	}
	node, err := s.inv.Get(r.Context(), nodeID)
	if err != nil {
		log.Printf("%s: inventory lookup for %q failed: %v", label, nodeID, err)
		writeError(w, http.StatusServiceUnavailable, label+": inventory unavailable")
		return "", false
	}
	if node == nil {
		log.Printf("%s: rejecting %q — not a current cluster member (removed or stale leaf)", label, nodeID)
		writeError(w, http.StatusForbidden, label+": node is not a current cluster member")
		return "", false
	}
	return nodeID, true
}

// handleObsIngest reverse-proxies a per-node collector's Prometheus remote-write
// stream to the loopback VictoriaMetrics, stamping the caller's verified node
// identity as an authoritative server-side label (VM's extra_label OVERRIDES any
// node_id the payload carried — verified 2026-07-17 — so the api never decodes
// the protobuf yet node_id is server-authoritative). §3.10.
func (s *Server) handleObsIngest(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.authenticateCollector(w, r, "obs ingest")
	if !ok {
		return
	}
	// Empty when obs is off/starting or VM isn't up yet — the collector's WAL
	// retries, so a 503 here is safe backpressure.
	base := s.obs.VMWriteBaseURL(r.Context())
	if base == "" {
		writeError(w, http.StatusServiceUnavailable,
			"obs ingest: metrics backend not ready (observability off or still starting)")
		return
	}
	s.proxyRemoteWrite(w, r, base, nodeID)
}

// handleObsLogsIngest reverse-proxies a per-node collector's Loki push stream to
// the loopback Loki. Same auth as the metrics route, but node_id is NOT stamped
// server-side: Loki has no extra_label equivalent, so the collector carries it
// in the stream labels via its controlplane-rendered config (§3.11 decision (a)).
// The ingress still fails closed and revocation-checks; it just doesn't override
// the label.
func (s *Server) handleObsLogsIngest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticateCollector(w, r, "obs logs ingest"); !ok {
		return
	}
	base := s.obs.LokiWriteBaseURL(r.Context())
	if base == "" {
		writeError(w, http.StatusServiceUnavailable,
			"obs logs ingest: log backend not ready (observability off, Loki disabled, or still starting)")
		return
	}
	s.proxyLokiPush(w, r, base)
}

// proxyRemoteWrite streams r's body to VM's remote-write endpoint at base,
// stamping extra_label=node_id=<nodeID> as the authoritative label. Split out so
// the proxy mechanics are unit-testable against a stub VM.
func (s *Server) proxyRemoteWrite(w http.ResponseWriter, r *http.Request, base, nodeID string) {
	// url.Values.Encode escapes the inner '=' to %3D; VM percent-decodes the
	// query arg before splitting the label, so it reads node_id=<cn> correctly.
	q := url.Values{}
	q.Set("extra_label", "node_id="+nodeID)
	s.reverseProxyIngest(w, r, base, vmRemoteWritePath, q.Encode(), "obs ingest")
}

// proxyLokiPush streams r's body to Loki's push endpoint at base, verbatim — no
// query rewrite (Loki has no extra_label; node_id rides in the stream labels).
func (s *Server) proxyLokiPush(w http.ResponseWriter, r *http.Request, base string) {
	s.reverseProxyIngest(w, r, base, lokiPushPath, "", "obs logs ingest")
}

// reverseProxyIngest streams r's body verbatim to a loopback obs backend at
// base, forcing the outbound path and query regardless of the inbound request.
// Shared by both ingress routes.
func (s *Server) reverseProxyIngest(w http.ResponseWriter, r *http.Request, base, path, rawQuery, label string) {
	target, err := url.Parse(base)
	if err != nil {
		log.Printf("%s: bad backend url %q: %v", label, base, err)
		writeError(w, http.StatusInternalServerError, label+": backend misconfigured")
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req) // sets scheme + host from target
		req.URL.Path = path
		req.URL.RawQuery = rawQuery
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("%s: proxy to backend failed: %v", label, err)
		writeError(w, http.StatusBadGateway, label+": backend error")
	}
	proxy.ServeHTTP(w, r)
}

// nodeIDFromClientCert extracts the calling node's id from a verified mTLS
// connection — the client leaf's Subject CommonName (mesh mints per-node client
// leaves with CN = node_id). Returns an error (all "reject the request"
// conditions) on no TLS state, no peer cert, or an empty CommonName. It does NOT
// re-verify the chain: RequireAndVerifyClientCert already proved the leaf chains
// to the mesh CA before any handler runs; this only reads identity off the
// already-verified leaf (PeerCertificates[0], leaf-first).
func nodeIDFromClientCert(cs *tls.ConnectionState) (string, error) {
	if cs == nil {
		return "", errors.New("no TLS connection state (non-TLS request)")
	}
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("no client certificate presented")
	}
	cn := strings.TrimSpace(cs.PeerCertificates[0].Subject.CommonName)
	if cn == "" {
		return "", errors.New("client certificate has empty CommonName")
	}
	return cn, nil
}
