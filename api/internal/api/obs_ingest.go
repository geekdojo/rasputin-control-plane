package api

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/proto"
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

// ObsIngestHandler builds the http.Handler served on the api's dedicated node
// listener (wired in main.go). Every route here has NO session middleware: the
// TLS handshake IS the authentication — the peer presents a key the node
// registered, or, while legacy collectors remain, a mesh-CA-signed client leaf
// — and the key's owner is the authorization identity. Everything reachable on
// this listener must be safe to expose to an admitted node and nothing else.
//
// ⚠️ ALPN does NOT keep an ordinary HTTPS client off this listener: Go adds
// http/1.1 to whatever protocols are offered, so a browser or curl negotiates
// fine. Every check here therefore happens AFTER the handshake, on the
// identity it established, and nothing may be gated on the protocol name.
//
// Kept separate from Handler()/BootstrapHandler() (the browser-facing surfaces,
// server-auth only — browsers don't present client certs) so requiring a client
// cert can't break the UI. See observability-stack.md §3.10–3.11. Its
// responses carry the same security headers as the browser-facing surfaces.
func (s *Server) ObsIngestHandler() http.Handler {
	return securityHeaders(s.obsIngestRoutes())
}

// obsIngestRoutes registers the ingress routes on a recording mux, so the
// route-enumeration test can check that each one refuses a caller without a
// verified client certificate.
func (s *Server) obsIngestRoutes() *routeMux {
	mux := newRouteMux()
	mux.HandleFunc(obsIngestPattern, s.handleObsIngest)
	mux.HandleFunc(obsLogsIngestPattern, s.handleObsLogsIngest)
	return mux
}

// authenticateCollector is the per-request half of node authentication, and it
// reads nothing but the request's own TLS state and the in-memory node
// registry. The identity is the key the peer presented — or, for a legacy
// client, its verified mesh leaf's CommonName — never anything in the request,
// so a node cannot claim another's identity.
//
// The handshake already decided all of this once (obs_ingest_conns.go). It is
// decided AGAIN here, per request, because a connection outlives the facts it
// was admitted on: a kept-alive connection is closed when its node stops
// qualifying, but the request in flight when that happens must not be served
// on the strength of a decision the registry has since reversed. The re-check
// is three map lookups against memory — no request does a database lookup.
//
// The route's purpose is checked here too: a key registered as the node's
// AGENT key is not the collector, so it cannot push the collector's metrics
// and logs even though both belong to the same node. A legacy mesh-chain
// client has no purpose to check and keeps the access it has always had.
//
// A server whose listener was not given the gate (WireObsIngest) refuses every
// request: fail closed.
//
// On any failure it writes the response and returns ok=false. `label` prefixes
// the log lines and error bodies so the two routes are distinguishable.
func (s *Server) authenticateCollector(w http.ResponseWriter, r *http.Request, label string) (nodeID string, ok bool) {
	if s.nodeGate == nil {
		log.Printf("%s: refusing: the listener has no node admission gate", label)
		writeError(w, http.StatusServiceUnavailable, label+": node admission is not configured")
		return "", false
	}
	id, err := s.nodeGate.identify(r.TLS)
	if err != nil {
		// The handshake should make this unreachable; fail closed rather
		// than proxy anonymously if it ever is not.
		log.Printf("%s: rejecting a request whose client certificate is not admitted: %v", label, err)
		writeError(w, http.StatusUnauthorized, label+": a registered node key is required")
		return "", false
	}
	if !s.nodeGate.gate.Admitted(id.nodeID) {
		log.Printf("%s: rejecting a request from %q — it is no longer a member holding a live join token", label, id.nodeID)
		writeError(w, http.StatusForbidden, label+": this node is not admitted")
		return "", false
	}
	if id.purpose != "" && id.purpose != proto.NodeKeyCollector {
		log.Printf("%s: rejecting a request from %q — it presented its %q key, which this route is not for", label, id.nodeID, id.purpose)
		writeError(w, http.StatusForbidden, label+": this key is not the node's collector key")
		return "", false
	}
	return id.nodeID, true
}

// handleObsIngest reverse-proxies a per-node collector's Prometheus remote-write
// stream to the loopback VictoriaMetrics, stamping the caller's verified node
// identity as an authoritative server-side label (VM's extra_label OVERRIDES any
// node_id the payload carried — verified 2026-07-17 — so node_id is
// server-authoritative without the api rewriting the payload). §3.10. The api
// does read each series' metric name, to refuse reserved ones
// (refuseReservedMetrics); the body it forwards is the one it received.
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
	if refused := refuseReservedMetrics(w, r); refused != "" {
		log.Printf("obs ingest: refusing push from %q: %s", nodeID, refused)
		return
	}
	s.proxyRemoteWrite(w, r, base, nodeID)
}

// refuseReservedMetrics reads the whole remote-write body and refuses it when
// any series carries a metric name only the controlplane writes
// (obs.IsReservedMetricName: the api's own rasputin_* host metrics, which the
// alert rules evaluate, and vmalert's ALERTS* state, which the api reads back
// as rule alerts). extra_label stamps node_id but cannot stop a collector from
// writing such a series under another node's labels, so the name itself is
// refused. On success r.Body is replaced with the buffered bytes, unchanged,
// and it returns "". Otherwise it has written the response — which names the
// offending metric or format — and returns a fixed reason for the log line;
// nothing read from the request goes into the log.
//
// This is a name check only — the samples are not read, and nothing about the
// collector's data is evaluated on this path.
func refuseReservedMetrics(w http.ResponseWriter, r *http.Request) (refused string) {
	if err := remoteWriteV1(r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding")); err != nil {
		writeError(w, http.StatusUnsupportedMediaType, "obs ingest: "+err.Error())
		return "unsupported content type or encoding"
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRemoteWriteBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "obs ingest: request body too large")
			return "request body too large"
		}
		writeError(w, http.StatusBadRequest, "obs ingest: read body: "+err.Error())
		return "request body unreadable"
	}
	name, err := reservedSeriesName(body, obs.IsReservedMetricName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "obs ingest: "+err.Error())
		return "not a snappy remote-write 1.0 request"
	}
	if name != "" {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("obs ingest: metric name %q is reserved for the controlplane", name))
		return "a series carries a metric name reserved for the controlplane"
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return ""
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
