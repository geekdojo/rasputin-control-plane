package proto

import "time"

// Metric names emitted by the agent. Centralized so the api and UI can refer
// to them by constant, and so the v0 set is documented in one place.
//
// All values are float64 to keep the wire shape uniform. Bytes are bytes,
// percents are 0–100, counts are integers cast to float, durations are
// seconds.
const (
	MetricCPUPercent    = "cpu_percent"
	MetricMemUsedBytes  = "mem_used_bytes"
	MetricMemTotalBytes = "mem_total_bytes"
	MetricDiskUsedBytes = "disk_used_bytes"
	MetricDiskTotalBytes = "disk_total_bytes"
	MetricAgentUptimeSeconds = "agent_uptime_seconds"
	MetricGoroutines = "goroutines"
)

// MetricsEvt is the payload published every collection tick on
// rasputin.node.<id>.metrics. The api persists each (name, value) tuple as a
// row in the metrics ring buffer.
type MetricsEvt struct {
	NodeID  string             `json:"nodeId"`
	Ts      time.Time          `json:"ts"`
	Metrics map[string]float64 `json:"metrics"`
}

// NodeMetricsSubject returns the publish subject for a node's metrics.
func NodeMetricsSubject(nodeID string) string {
	return "rasputin.node." + nodeID + ".metrics"
}

// AllMetricsFilter matches every node's metrics subject. Used by the api's
// metrics subscriber.
const AllMetricsFilter = "rasputin.node.*.metrics"
