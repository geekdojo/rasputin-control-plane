package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Routes served on the api's dedicated mTLS ingress listener. Per-node Alloy
// collectors push here — metrics (§3.10) and, since Slice 1.2c, logs (§3.11) —
// and node agents move backup members here, each by its registered key.
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
	// remote-write it has no extra_label query arg, so the ingress stamps
	// node_id into the stream labels itself (stampLogStreams) rather than
	// trusting the value the collector's config put there.
	lokiPushPath = "/loki/api/v1/push"
)

// ObsIngestHandler builds the http.Handler served on the api's dedicated node
// listener (wired in main.go): the collectors' metrics and log pushes, and the
// agents' backup upload and restore fetch. Every route here has NO session
// middleware: the TLS handshake IS the authentication — the peer presents a
// key the node registered — and the key's owner is the authorization
// identity, with each route's key purpose checked per
// request (authenticateNode). Everything reachable on this listener must be
// safe to expose to an admitted node and nothing else.
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
	// Backup transfer, authenticated by the node's agent key: the only
	// routes a member is uploaded to or fetched from (storage.TransferRouter).
	mux.HandleFunc("PUT "+backupxfer.IngestPathPrefix, s.handleNodeBackupIngest)
	mux.HandleFunc("GET "+backupxfer.EgressPathPrefix, s.handleNodeRestoreEgress)
	return mux
}

// authenticateNode is the per-request half of node authentication, and it
// reads nothing but the request's own TLS state and the in-memory node
// registry. The identity is the owner of the key the peer presented, never
// anything in the request, so a node cannot claim another's identity.
//
// The handshake already decided all of this once (obs_ingest_conns.go). It is
// decided AGAIN here, per request, because a connection outlives the facts it
// was admitted on: a kept-alive connection is closed when its node stops
// qualifying, but the request in flight when that happens must not be served
// on the strength of a decision the registry has since reversed. The re-check
// is three map lookups against memory — no request does a database lookup.
//
// The route's purpose is checked here too: want is the one key purpose the
// route serves, so a node's AGENT key cannot push its collector's metrics and
// its COLLECTOR key cannot move its backups, though both belong to the same
// node.
//
// A server whose listener was not given the gate (WireObsIngest) refuses every
// request: fail closed.
//
// On any failure it writes a coded refusal (writeCodedError: a correlation id
// in the body and in the WARN record, with the node, the purpose of the key
// it presented, the purpose the route serves, and the cause) and returns ok=false. `label` prefixes the error bodies so the
// routes are distinguishable.
func (s *Server) authenticateNode(w http.ResponseWriter, r *http.Request, label string, want proto.NodeKeyPurpose) (nodeID string, ok bool) {
	if s.nodeGate == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeNodeAdmissionUnconfigured, label+": node admission is not configured",
			slog.String("route_purpose", string(want)), slog.String("cause", "the listener has no node admission gate"))
		return "", false
	}
	id, err := s.nodeGate.identify(r.TLS)
	if err != nil {
		// The handshake should make this unreachable; fail closed rather
		// than serve anonymously if it ever is not.
		s.writeCodedError(w, r, http.StatusUnauthorized, codeNodeKeyRequired, label+": a registered node key is required",
			slog.String("route_purpose", string(want)), slog.String("cause", "client certificate not admitted: "+err.Error()))
		return "", false
	}
	refuse := func(code, msg, cause string) (string, bool) {
		s.writeCodedError(w, r, http.StatusForbidden, code, label+": "+msg,
			slog.String("node_id", id.nodeID), slog.String("purpose", string(id.purpose)),
			slog.String("route_purpose", string(want)), slog.String("cause", cause))
		return "", false
	}
	if !s.nodeGate.gate.Admitted(id.nodeID) {
		return refuse(codeNodeNotAdmitted, "this node is not admitted", "the node is no longer a member holding a live join token")
	}
	if id.purpose != want {
		return refuse(codeNodeKeyPurpose, wrongKeyMessage(want), fmt.Sprintf("presented its %s key; this route is for the %s key", id.purpose, want))
	}
	return id.nodeID, true
}

// wrongKeyMessage is the refusal body for a key this route is not for.
func wrongKeyMessage(want proto.NodeKeyPurpose) string {
	if want == proto.NodeKeyAgent {
		return "a registered agent key is required"
	}
	return "this key is not the node's " + string(want) + " key"
}

// handleNodeBackupIngest is PUT /api/backup/ingest/{generation}/{member} on
// the node listener: the request is authenticated by the presenting node's
// registered agent key, and the endpoint is told which node that is, so a
// credential is honoured only from its own node (backupxfer.CheckPresenter).
func (s *Server) handleNodeBackupIngest(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.authenticateNode(w, r, "backup ingest", proto.NodeKeyAgent)
	if !ok {
		return
	}
	if s.backupIngest == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeBackupTransferUnconfigured, "backup ingest is not configured on this api",
			slog.String("node_id", nodeID), slog.String("cause", "the server has no backup ingest wired"))
		return
	}
	s.backupIngest.ServeNode(w, r, nodeID)
}

// handleNodeRestoreEgress is GET /api/backup/egress/{generation}/{member} on
// the node listener, the restore stream's only entry; as the ingest.
func (s *Server) handleNodeRestoreEgress(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.authenticateNode(w, r, "restore egress", proto.NodeKeyAgent)
	if !ok {
		return
	}
	if s.restoreEgress == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeBackupTransferUnconfigured, "app-volume restore is not configured on this api",
			slog.String("node_id", nodeID), slog.String("cause", "the server has no restore egress wired"))
		return
	}
	s.restoreEgress.ServeNode(w, r, nodeID)
}

// handleObsIngest reverse-proxies a per-node collector's Prometheus remote-write
// stream to the loopback VictoriaMetrics, stamping the caller's verified node
// identity as an authoritative server-side label (VM's extra_label OVERRIDES any
// node_id the payload carried — verified 2026-07-17 — so node_id is
// server-authoritative without the api rewriting the payload). §3.10. The api
// does read each series' metric name, to refuse reserved ones
// (refuseReservedMetrics); the body it forwards is the one it received.
func (s *Server) handleObsIngest(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.authenticateNode(w, r, "obs ingest", proto.NodeKeyCollector)
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
		s.log.WarnContext(r.Context(), "obs ingest: refusing a push", "node_id", nodeID, "reason", refused)
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
// the loopback Loki. Same auth as the metrics route, and the same identity rule:
// node_id is the authenticated caller's, decided by the server. Loki has no
// extra_label equivalent, so instead of a query arg the api rewrites the label
// into every stream of the body (stampLogStreams) and refuses a job label
// reserved for the controlplane.
func (s *Server) handleObsLogsIngest(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.authenticateNode(w, r, "obs logs ingest", proto.NodeKeyCollector)
	if !ok {
		return
	}
	base := s.obs.LokiWriteBaseURL(r.Context())
	if base == "" {
		writeError(w, http.StatusServiceUnavailable,
			"obs logs ingest: log backend not ready (observability off, Loki disabled, or still starting)")
		return
	}
	if refused := stampLogStreams(w, r, nodeID); refused != "" {
		s.log.WarnContext(r.Context(), "obs logs ingest: refusing a push", "node_id", nodeID, "reason", refused)
		return
	}
	s.proxyLokiPush(w, r, base)
}

// stampLogStreams reads the whole push body and replaces it with one in which
// every stream carries node_id=<the owner of the presented collector key>. The
// label the collector sent is overwritten, not merged: a node's own key
// authenticates only that node, so its logs are that node's whatever its
// config claims. A stream whose `job` label is reserved for the controlplane
// (obs.IsReservedLogJob) is refused, because no node owns it.
//
// On success r.Body holds the rewritten bytes and ContentLength matches, and
// it returns "". Otherwise it has written the response and returns a fixed
// reason for the log line; nothing read from the request goes into the log.
//
// Log LINES are never parsed — only each stream's label string. The body cap
// bounds what is held in memory to rewrite it.
func stampLogStreams(w http.ResponseWriter, r *http.Request, nodeID string) (refused string) {
	if err := lokiPushV1(r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding")); err != nil {
		writeError(w, http.StatusUnsupportedMediaType, "obs logs ingest: "+err.Error())
		return "unsupported content type or encoding"
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLokiPushBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "obs logs ingest: request body too large")
			return "request body too large"
		}
		writeError(w, http.StatusBadRequest, "obs logs ingest: read body: "+err.Error())
		return "request body unreadable"
	}
	out, refusedJob, err := rewriteLokiPush(body, nodeID, obs.IsReservedLogJob)
	if err != nil {
		writeError(w, http.StatusBadRequest, "obs logs ingest: "+err.Error())
		return "not a snappy Loki push request"
	}
	if refusedJob != "" {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("obs logs ingest: job %q is reserved for the controlplane", refusedJob))
		return "a stream carries a job label reserved for the controlplane"
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.ContentLength = int64(len(out))
	return ""
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
