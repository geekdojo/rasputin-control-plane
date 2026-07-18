package obs

import (
	"context"
	"time"
)

// Status is the read-only view the api's HTTP layer renders at
// /api/obs/status. Bundling Supervisor + VMSink + (optional) LogsClient
// together (instead of passing all three into NewServer) keeps the api
// package's import list narrow and gives the handler one thing to ask
// for a snapshot.
//
// Nil-safe: a zero-value *Status returns a Snapshot whose Enabled flag is
// false and all other fields are their zero values.
//
// Enablement is the operator's *stored* choice, read through EnabledFn —
// not a structural property of this struct. Before Slice 1.6 the supervisor
// was only constructed when RASPUTIN_OBS_ENABLED=1, so "is a supervisor
// wired?" doubled as "is obs on?". The supervisor is now always constructed
// (that's what makes runtime enable possible), so that inference no longer
// holds and the setting is the only honest source.
type Status struct {
	sup        Supervisor
	sink       *VMSink
	logs       *LogsClient
	series     *SeriesClient
	containers *ContainersClient
	enabled    EnabledFn
}

// EnabledFn reports the operator's stored observability intent. Injected as
// a closure so the obs package never imports the settings store. A nil
// EnabledFn falls back to structural detection (a supervisor + sink are
// wired ⇒ on), which is what the package's own tests rely on.
type EnabledFn func(ctx context.Context) (bool, error)

// SetEnabled installs the stored-intent reader. Called once from main after
// the settings store is open. Follows the same post-construction-setter
// pattern as Server.SetAlertsService — the alternative is threading the
// store through NewStatus and every test that builds one.
func (s *Status) SetEnabled(fn EnabledFn) {
	if s == nil {
		return
	}
	s.enabled = fn
}

// Observability lifecycle states, as reported by Snapshot.State.
//
// The three-state split is load-bearing, not cosmetic: enable takes minutes
// on a cold pull (~500 MB), and collapsing "starting" into "off" makes the
// UI say "observability is off" during the exact window the operator is
// watching the thing they just turned on.
const (
	StateOff      = "off"      // operator hasn't opted in
	StateStarting = "starting" // opted in; stack not answering /health yet
	StateOn       = "on"       // opted in and healthy
)

// NewStatus bundles a Supervisor + VMSink + (optional) LogsClient for
// the handler. Supervisor + VMSink are required for Enabled=true;
// LogsClient is optional (Loki may be disabled — Snapshot reports it).
// SeriesClient + ContainersClient are built lazily off the same
// Supervisor when sup+sink are present — handlers ask via Series() /
// Containers().
func NewStatus(sup Supervisor, sink *VMSink, logs *LogsClient) *Status {
	st := &Status{sup: sup, sink: sink, logs: logs}
	if sup != nil && sink != nil {
		if c, err := NewSeriesClient(SeriesClientConfig{Supervisor: sup}); err == nil {
			st.series = c
		}
		if c, err := NewContainersClient(ContainersClientConfig{Supervisor: sup}); err == nil {
			st.containers = c
		}
	}
	return st
}

// Logs returns the obs LogsClient, or nil when obs is off OR Loki is
// disabled. Callers (the /api/obs/logs handler) must guard for nil.
func (s *Status) Logs() *LogsClient {
	if s == nil {
		return nil
	}
	return s.logs
}

// Series returns the SeriesClient for chart-shaped PromQL queries, or
// nil when obs is off. Callers must guard for nil.
func (s *Status) Series() *SeriesClient {
	if s == nil {
		return nil
	}
	return s.series
}

// Containers returns the ContainersClient for cAdvisor-derived
// container summaries, or nil when obs is off. Callers must guard
// for nil — the handler renders 503 when it's nil.
func (s *Status) Containers() *ContainersClient {
	if s == nil {
		return nil
	}
	return s.containers
}

// GrafanaEnabled reports whether the proxy at /observability/* has a
// live Grafana to forward to. False when the operator hasn't opted in,
// OR the supervisor is the Noop one, OR EnableGrafana was disabled.
//
// Takes a ctx because enablement is now a settings read, not a structural
// fact. Without the opt-in check the proxy would forward to a container
// the operator just stopped and surface a raw 502.
func (s *Status) GrafanaEnabled(ctx context.Context) bool {
	if s == nil || s.sup == nil {
		return false
	}
	if _, ok := s.sup.(NoopSupervisor); ok {
		return false
	}
	if s.enabled != nil {
		on, err := s.enabled(ctx)
		if err != nil || !on {
			return false
		}
	}
	return s.sup.GrafanaBaseURL() != ""
}

// GrafanaBaseURL is the host-side URL the api's reverse proxy forwards
// to. Empty when GrafanaEnabled returns false.
func (s *Status) GrafanaBaseURL(ctx context.Context) string {
	if !s.GrafanaEnabled(ctx) {
		return ""
	}
	return s.sup.GrafanaBaseURL()
}

// VMWriteBaseURL is the loopback base URL the obs mTLS ingress
// reverse-proxies per-node remote-write requests to (observability-stack.md
// §3.10). Empty — which the ingress renders as 503 — when there's nowhere to
// write: obs is off (operator hasn't opted in), the supervisor is the Noop
// one, or VM hasn't reported a base URL yet (still starting).
//
// Gating on the stored opt-in (mirrors GrafanaBaseURL) is defense in depth:
// the reconcile saga tears collectors down when obs is disabled, but a stale
// collector that keeps pushing gets a clean 503 here rather than a proxy
// attempt at a torn-down VM. VM itself stays loopback-only; this URL is never
// LAN-facing — it's the api-internal target the ingress forwards to.
func (s *Status) VMWriteBaseURL(ctx context.Context) string {
	if s == nil || s.sup == nil {
		return ""
	}
	if _, ok := s.sup.(NoopSupervisor); ok {
		return ""
	}
	if s.enabled != nil {
		on, err := s.enabled(ctx)
		if err != nil || !on {
			return ""
		}
	}
	return s.sup.VMBaseURL()
}

// Snapshot is the JSON shape returned by /api/obs/status.
type Snapshot struct {
	// Enabled reflects the operator's stored opt-in. False means the
	// stack is deliberately off and the rest of the fields are zero.
	//
	// Enabled is NOT "you can render charts" — during a cold enable it's
	// true for minutes while the stack pulls. Read State for that.
	Enabled bool `json:"enabled"`

	// State is the lifecycle: off | starting | on. Prefer this over
	// Enabled+Healthy — deriving it in each client is how "starting"
	// ends up rendered as "off".
	State string `json:"state"`

	// Healthy is the supervisor's current health probe — true when the
	// VictoriaMetrics container is running and its /health answers 2xx.
	Healthy bool `json:"healthy"`

	// VMBaseURL is where VM is reachable from the api process.
	// Empty until Start has succeeded at least once.
	VMBaseURL string `json:"vmBaseUrl,omitempty"`

	// LastWriteOK is the timestamp of the most recent successful
	// remote-write. Zero until the first sample lands.
	LastWriteOK time.Time `json:"lastWriteOk,omitempty"`

	// LastError is the message from the most recent remote-write
	// failure. Empty when the last write succeeded or no write has been
	// attempted yet. Surfaced in the UI so operators can spot
	// configuration / health issues without tailing logs.
	LastError string `json:"lastError,omitempty"`

	// LokiBaseURL is the host-side base URL Loki is reachable at when
	// log shipping is enabled. Empty when Loki is disabled OR the obs
	// stack hasn't started yet.
	LokiBaseURL string `json:"lokiBaseUrl,omitempty"`

	// GrafanaURL is the operator-facing path (relative to the api
	// host) to the embedded Grafana. Always "/observability/" when
	// Grafana is enabled — surfaced as a field so the UI's "Open
	// Dashboards" link doesn't have to hard-code the path.
	GrafanaURL string `json:"grafanaUrl,omitempty"`
}

// Snapshot returns the current obs state. Cheap — the only I/O is
// StackReady's per-service health GETs (VM, plus Loki/Grafana when enabled),
// each on a short timeout.
func (s *Status) Snapshot(ctx context.Context) Snapshot {
	if s == nil || s.sup == nil || s.sink == nil {
		return Snapshot{Enabled: false, State: StateOff}
	}
	if _, ok := s.sup.(NoopSupervisor); ok {
		// Defensive: even if a sink is wired against the noop
		// supervisor, treat obs as "off" — there's no real VM to talk
		// to. Keeps the UI clear about why it's not seeing charts.
		return Snapshot{Enabled: false, State: StateOff}
	}
	if s.enabled != nil {
		on, err := s.enabled(ctx)
		if err != nil {
			// Surface rather than swallow: reporting "off" for a failed
			// settings read would look identical to a deliberate opt-out
			// and send the operator hunting the wrong problem.
			return Snapshot{
				Enabled:   false,
				State:     StateOff,
				LastError: "read observability setting: " + err.Error(),
			}
		}
		if !on {
			return Snapshot{Enabled: false, State: StateOff}
		}
	}
	// State reflects the WHOLE enabled stack, not just VM. Using VM-only
	// health here was a lie on partial failure: on the bench (2026-07-17) VM
	// came up while Loki crash-looped, and the old logic reported
	// state="on", healthy=true — a green "recording" over a dead sidecar,
	// with nothing actually landing in Loki. StackReady is only true when
	// every enabled service answers.
	ready, _ := s.sup.StackReady(ctx)
	out := Snapshot{
		Enabled:     true,
		State:       StateStarting,
		Healthy:     ready,
		VMBaseURL:   s.sup.VMBaseURL(),
		LokiBaseURL: s.sup.LokiBaseURL(),
	}
	if ready {
		out.State = StateOn
	}
	if s.sup.GrafanaBaseURL() != "" {
		out.GrafanaURL = "/observability/"
	}
	lastOK, lastErr := s.sink.LastWrite()
	out.LastWriteOK = lastOK
	if lastErr != nil {
		out.LastError = lastErr.Error()
	}
	return out
}
