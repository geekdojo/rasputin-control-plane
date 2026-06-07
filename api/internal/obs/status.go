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
// Nil-safe: a zero-value *Status (obs disabled) returns a Snapshot whose
// Enabled flag is false and all other fields are their zero values. The
// handler renders that as "obs is off — set RASPUTIN_OBS_ENABLED=1 to
// turn it on."
type Status struct {
	sup        Supervisor
	sink       *VMSink
	logs       *LogsClient
	series     *SeriesClient
	containers *ContainersClient
}

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
// live Grafana to forward to. False when obs is off OR the supervisor
// is the Noop one OR EnableGrafana was disabled.
func (s *Status) GrafanaEnabled() bool {
	if s == nil || s.sup == nil {
		return false
	}
	if _, ok := s.sup.(NoopSupervisor); ok {
		return false
	}
	return s.sup.GrafanaBaseURL() != ""
}

// GrafanaBaseURL is the host-side URL the api's reverse proxy forwards
// to. Empty when GrafanaEnabled returns false.
func (s *Status) GrafanaBaseURL() string {
	if !s.GrafanaEnabled() {
		return ""
	}
	return s.sup.GrafanaBaseURL()
}

// Snapshot is the JSON shape returned by /api/obs/status.
type Snapshot struct {
	// Enabled is true when both a non-noop Supervisor and a non-nil
	// VMSink are wired. False means obs is off — the rest of the fields
	// are zero values and the UI should render an "enable obs" CTA
	// rather than charts.
	Enabled bool `json:"enabled"`

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

// Snapshot returns the current obs state. Cheap — no I/O beyond the
// supervisor's Healthy probe, which itself does a 2s-timeout HTTP GET.
func (s *Status) Snapshot(ctx context.Context) Snapshot {
	if s == nil || s.sup == nil || s.sink == nil {
		return Snapshot{Enabled: false}
	}
	if _, ok := s.sup.(NoopSupervisor); ok {
		// Defensive: even if a sink is wired against the noop
		// supervisor, treat obs as "off" — there's no real VM to talk
		// to. Keeps the UI clear about why it's not seeing charts.
		return Snapshot{Enabled: false}
	}
	healthy, _ := s.sup.Healthy(ctx)
	out := Snapshot{
		Enabled:     true,
		Healthy:     healthy,
		VMBaseURL:   s.sup.VMBaseURL(),
		LokiBaseURL: s.sup.LokiBaseURL(),
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
