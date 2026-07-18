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

// obsIngestPattern is the single route served on the api's dedicated mTLS
// ingress listener. Per-node Alloy collectors remote-write here
// (observability-stack.md §3.10, Slice 1.2b).
const obsIngestPattern = "POST /api/obs/ingest"

// vmRemoteWritePath is VictoriaMetrics' Prometheus remote-write endpoint
// (snappy-compressed protobuf). Note this is NOT the path the api's own
// host-metrics push sink uses — that's /api/v1/import/prometheus (text
// exposition). Per-node Alloy speaks the remote-write protocol, so the ingress
// forwards to /api/v1/write. Both endpoints honor the extra_label query arg.
const vmRemoteWritePath = "/api/v1/write"

// ObsIngestHandler builds the http.Handler served on the api's dedicated mTLS
// ingress listener (wired in main.go). It carries a SINGLE route — the
// per-node metric ingress — and deliberately no session middleware: the TLS
// handshake (RequireAndVerifyClientCert against the per-installation mesh CA)
// IS the authentication, and the verified client cert's CommonName is the
// authorization identity. Everything reachable on this listener must therefore
// be safe to expose to any mesh-CA-signed node and nothing else.
//
// Kept separate from Handler()/BootstrapHandler() because those serve the
// browser-facing HTTPS/HTTP surfaces, which are server-auth only (browsers
// don't present client certs). mTLS gets its own listener so requiring a
// client cert can't break the UI. See observability-stack.md §3.10.
func (s *Server) ObsIngestHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(obsIngestPattern, s.handleObsIngest)
	return mux
}

// handleObsIngest reverse-proxies a per-node collector's Prometheus
// remote-write stream to the loopback VictoriaMetrics, stamping the caller's
// verified node identity as an authoritative server-side label.
//
// It runs ONLY on the mTLS listener, so by the time a request arrives the
// listener's RequireAndVerifyClientCert has already proven the client cert
// chains to our mesh CA. Authorization then has two gates beyond that
// handshake:
//
//  1. Identity — node_id is the client leaf's CommonName (mesh.MintLeaf sets
//     CN = node_id for client leaves). It is read from the verified cert, never
//     from request data, so a node cannot claim another's identity.
//  2. Membership / revocation — the node_id must be a currently-registered
//     cluster member. A node removed from inventory loses ingest immediately,
//     even while its still-unexpired leaf remains cryptographically valid. This
//     is the CRL-free revocation path from §3.10: node removal cuts access on
//     the next request, no OCSP/CRL machinery.
//
// On success the raw request body is streamed verbatim to
// VM/api/v1/write?extra_label=node_id=<cn>. VM's extra_label is applied
// server-side and OVERRIDES any node_id the payload carried (verified
// 2026-07-17: injected label wins), so the api never decodes the remote-write
// protobuf and pulls in no protobuf dependency, yet node_id is strictly
// server-authoritative.
func (s *Server) handleObsIngest(w http.ResponseWriter, r *http.Request) {
	nodeID, err := nodeIDFromClientCert(r.TLS)
	if err != nil {
		// Defense in depth: the listener's RequireAndVerifyClientCert should
		// make this unreachable, but if a cert-less request ever gets here
		// (misconfigured listener), fail closed rather than proxy anonymously.
		log.Printf("api/obs/ingest: rejecting request without a usable client cert: %v", err)
		writeError(w, http.StatusUnauthorized, "obs ingest: client certificate required")
		return
	}

	// Membership / revocation gate. inv.Get returns (nil, nil) for an unknown
	// id — a valid leaf whose node was removed from the cluster (or a leaf that
	// outlived its node). Cut it off. A real store error is a 503, not a 403:
	// we don't know the node's membership, so we don't silently drop metrics.
	node, err := s.inv.Get(r.Context(), nodeID)
	if err != nil {
		log.Printf("api/obs/ingest: inventory lookup for %q failed: %v", nodeID, err)
		writeError(w, http.StatusServiceUnavailable, "obs ingest: inventory unavailable")
		return
	}
	if node == nil {
		log.Printf("api/obs/ingest: rejecting %q — not a current cluster member (removed or stale leaf)", nodeID)
		writeError(w, http.StatusForbidden, "obs ingest: node is not a current cluster member")
		return
	}

	// Where to write. Empty when obs is off/starting or VM isn't up yet — the
	// collector's remote-write WAL retries, so a 503 here is safe backpressure.
	base := s.obs.VMWriteBaseURL(r.Context())
	if base == "" {
		writeError(w, http.StatusServiceUnavailable,
			"obs ingest: metrics backend not ready (observability off or still starting)")
		return
	}
	s.proxyRemoteWrite(w, r, base, nodeID)
}

// proxyRemoteWrite streams r's body to VM's remote-write endpoint at base,
// stamping extra_label=node_id=<nodeID> so VM applies the authoritative label
// server-side. Split out from handleObsIngest so the proxy mechanics (path
// rewrite + extra_label + body pass-through) are unit-testable against a stub
// VM without a TLS handshake or a full obs stack.
func (s *Server) proxyRemoteWrite(w http.ResponseWriter, r *http.Request, base, nodeID string) {
	target, err := url.Parse(base)
	if err != nil {
		log.Printf("api/obs/ingest: bad VM base url %q: %v", base, err)
		writeError(w, http.StatusInternalServerError, "obs ingest: metrics backend misconfigured")
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req) // sets scheme + host from target
		// Force the remote-write path regardless of the inbound path, and set
		// the authoritative label. url.Values.Encode escapes the inner '=' to
		// %3D; VM percent-decodes the query arg before splitting the label, so
		// it reads node_id=<cn> correctly.
		req.URL.Path = vmRemoteWritePath
		q := url.Values{}
		q.Set("extra_label", "node_id="+nodeID)
		req.URL.RawQuery = q.Encode()
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("api/obs/ingest: proxy to VM failed: %v", err)
		writeError(w, http.StatusBadGateway, "obs ingest: metrics backend error")
	}
	proxy.ServeHTTP(w, r)
}

// nodeIDFromClientCert extracts the calling node's id from a verified mTLS
// connection. The id is the client leaf's Subject CommonName — the mesh CA
// mints per-node client leaves with CN = node_id (mesh.LeafSpec, §3.10). We
// read the CN (not a SAN) because that is exactly what the minter sets and it
// is a single unambiguous value.
//
// Returns an error — all "reject the request" conditions — when there is no TLS
// state, no peer certificate, or an empty CommonName. It does NOT re-verify the
// chain: the listener's RequireAndVerifyClientCert already proved the leaf
// chains to the mesh CA before any handler runs. This only reads identity off
// the already-verified leaf (PeerCertificates[0], which Go orders leaf-first).
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
