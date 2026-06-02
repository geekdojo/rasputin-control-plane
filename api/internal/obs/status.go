package obs

import (
	"context"
	"time"
)

// Status is the read-only view the api's HTTP layer renders at
// /api/obs/status. Bundling Supervisor + VMSink together (instead of
// passing both into NewServer) keeps the api package's import list
// narrow and gives the handler one thing to ask for a snapshot.
//
// Nil-safe: a zero-value *Status (obs disabled) returns a Snapshot whose
// Enabled flag is false and all other fields are their zero values. The
// handler renders that as "obs is off — set RASPUTIN_OBS_ENABLED=1 to
// turn it on."
type Status struct {
	sup  Supervisor
	sink *VMSink
}

// NewStatus bundles a Supervisor + VMSink for the handler. Both are
// optional; passing nil for either yields an Enabled=false snapshot.
func NewStatus(sup Supervisor, sink *VMSink) *Status {
	return &Status{sup: sup, sink: sink}
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
		Enabled:   true,
		Healthy:   healthy,
		VMBaseURL: s.sup.VMBaseURL(),
	}
	lastOK, lastErr := s.sink.LastWrite()
	out.LastWriteOK = lastOK
	if lastErr != nil {
		out.LastError = lastErr.Error()
	}
	return out
}
