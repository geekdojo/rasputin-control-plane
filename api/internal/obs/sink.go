package obs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Sink is the abstract "second home" for every metric sample the api
// receives. The Tier 1 SQLite store is implicit and always written first;
// adding obs.VMSink to metrics.Service is what turns on the Tier 2
// fan-out. Adding more sinks later (StatsD, OTLP, whatever) is a matter
// of registering them — the interface is intentionally minimal.
//
// Implementations MUST be safe for concurrent use; metrics.Service may
// call Write from multiple subscriber goroutines simultaneously when
// several nodes publish their 10s samples in the same window.
type Sink interface {
	// Write delivers a single MetricsEvt to the downstream store.
	// Best-effort: errors are surfaced to the caller for logging /
	// status, but a failure here MUST NOT block the SQLite write or
	// the next NATS message — metrics.Service treats Write the same
	// way it treats a fan-out failure (log, continue).
	Write(ctx context.Context, evt *proto.MetricsEvt) error
}

// noopSink is the default — a sink that drops every event silently. Used
// when obs is disabled so metrics.Service can hold a non-nil reference
// unconditionally.
type noopSink struct{}

// NewNoopSink returns a Sink that does nothing. Useful for tests and for
// the default dev-time wiring when RASPUTIN_OBS_ENABLED is unset.
func NewNoopSink() Sink                                         { return noopSink{} }
func (noopSink) Write(context.Context, *proto.MetricsEvt) error { return nil }

// VMSink remote-writes every event into VictoriaMetrics via VM's
// /api/v1/import/prometheus endpoint. The endpoint accepts the
// Prometheus text exposition format — one line per sample, no
// snappy/protobuf bookkeeping. For the api's "Tier 1 → VM bridge" role
// this is the right shape: zero new deps, easy to debug with `curl`,
// fully compatible with VM's query layer. When Alloy lands in Slice 1.2
// it'll do real Prometheus remote-write — but Alloy is the canonical
// collector, not the api.
//
// Health gating: a VMSink resolved against a supervisor that reports
// not-healthy short-circuits without an HTTP round-trip. This keeps the
// startup-window log noise down when VM is still booting and means a
// transient obs outage doesn't burn the api's CPU on connection-refused
// retries.
type VMSink struct {
	sup    Supervisor
	client *http.Client

	mu      sync.RWMutex
	lastOK  time.Time
	lastErr error
}

// VMSinkConfig is the constructor input.
type VMSinkConfig struct {
	// Supervisor provides VMBaseURL() and Healthy(). Required.
	Supervisor Supervisor
	// HTTPClient is the client used for the POST. Defaults to a 5s
	// timeout — remote-write is on the critical path of the metrics
	// subscriber goroutine, so a slow VM must not back up the bus.
	HTTPClient *http.Client
}

// NewVMSink constructs a VMSink. Supervisor is required.
func NewVMSink(cfg VMSinkConfig) (*VMSink, error) {
	if cfg.Supervisor == nil {
		return nil, errors.New("obs: VMSink requires a Supervisor")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &VMSink{sup: cfg.Supervisor, client: client}, nil
}

// Write encodes evt as Prometheus text and POSTs it to VM. Returns the
// HTTP / encoding error on failure; the caller (metrics.Service) is
// expected to log it without stopping the pipeline.
func (s *VMSink) Write(ctx context.Context, evt *proto.MetricsEvt) error {
	if evt == nil || evt.NodeID == "" || len(evt.Metrics) == 0 {
		return nil
	}
	healthy, _ := s.sup.Healthy(ctx)
	if !healthy {
		// Don't try when VM isn't up — we don't even have a base URL
		// yet, and the supervisor's startup path will retry shortly.
		err := errors.New("vm not healthy")
		s.recordResult(time.Time{}, err)
		return err
	}
	base := s.sup.VMBaseURL()
	if base == "" {
		err := errors.New("vm base url empty")
		s.recordResult(time.Time{}, err)
		return err
	}

	body := encodePromText(evt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v1/import/prometheus", bytes.NewReader(body))
	if err != nil {
		s.recordResult(time.Time{}, err)
		return err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp, err := s.client.Do(req)
	if err != nil {
		s.recordResult(time.Time{}, err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("vm remote-write: HTTP %d: %s",
			resp.StatusCode, bytes.TrimSpace(snippet))
		s.recordResult(time.Time{}, err)
		return err
	}
	s.recordResult(time.Now().UTC(), nil)
	return nil
}

// LastWrite returns the timestamp of the most recent successful POST and
// the most recent error (if any). Both fields are zero values until the
// first call to Write. Used by /api/obs/status to render last-success +
// last-error for the operator.
func (s *VMSink) LastWrite() (lastOK time.Time, lastErr error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastOK, s.lastErr
}

func (s *VMSink) recordResult(ok time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok.IsZero() {
		s.lastOK = ok
		s.lastErr = nil
		return
	}
	if err != nil {
		s.lastErr = err
	}
}

// encodePromText renders a MetricsEvt as Prometheus text exposition.
// Output shape (one line per metric, sorted by name for stable tests):
//
//	rasputin_<metric> {nodeId="..."} <value> <ts_ms>
//
// We prefix every metric name with `rasputin_` so VM's query namespace
// stays scoped to us — easier to spot ours vs. anything Alloy ships in
// later slices.
//
// Names are mapped to Prometheus-safe identifiers (underscores, no dots).
// The agent already emits compatible names (cpu_percent, mem_used_bytes,
// …), so this is a no-op for the v0 set; the sanitize step keeps us safe
// when a new metric lands without forcing every collector site to think
// about Prometheus rules.
func encodePromText(evt *proto.MetricsEvt) []byte {
	tsMs := evt.Ts.UnixMilli()
	// Sort keys for deterministic output (tests assert exact strings).
	keys := make([]string, 0, len(evt.Metrics))
	for k := range evt.Metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.Grow(len(keys) * 64)
	for _, name := range keys {
		buf.WriteString("rasputin_")
		buf.WriteString(sanitizeName(name))
		buf.WriteString(`{nodeId=`)
		buf.WriteString(strconv.Quote(evt.NodeID))
		buf.WriteString(`} `)
		buf.WriteString(strconv.FormatFloat(evt.Metrics[name], 'f', -1, 64))
		buf.WriteByte(' ')
		buf.WriteString(strconv.FormatInt(tsMs, 10))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// sanitizeName collapses any non-[a-zA-Z0-9_] character to '_'. Prometheus
// metric names accept [a-zA-Z_:][a-zA-Z0-9_:]*; we don't use ':' so we
// don't allow it on input either.
func sanitizeName(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '_':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	return string(b)
}
