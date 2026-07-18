// Package metrics is the agent's host-metrics collector. Every Interval it
// gathers CPU/memory/disk/uptime/goroutine numbers and publishes them on
// rasputin.node.<id>.metrics for the api to ingest.
//
// In Tier 1 (current) the api persists the events directly into a 24h ring
// buffer in SQLite and the UI renders sparklines from that. Tier 2 will add
// a VictoriaMetrics sidecar; the agent's wire format won't need to change
// because the api will simply forward into VM as well as storing locally.
package metrics

import (
	"context"
	"encoding/json"
	"log"
	"runtime"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

// Interval is the gap between samples. 10s matches the heartbeat cadence so
// metrics and presence track together. Exposed as a var (not a const) so
// tests that exercise the Run loop can shrink it to milliseconds without
// burning 10s of real time per case.
var Interval = 10 * time.Second

// Run is the collector loop. Blocks until ctx is cancelled. Errors during
// individual probes (e.g. disk usage on a path we can't reach) are logged
// and skipped — a single bad probe shouldn't take down the loop.
//
// diskPath is the filesystem the disk metric measures. It must be a path on
// the node's persistent DATA partition — NOT "/", which on the appliance is the
// read-only squashfs rootfs (RAUC A/B) and reads ~100% full by design. statfs
// reports filesystem-level totals, so any path on that partition works; the
// caller passes the agent's own state dir (`/var/lib/rasputin/agent-state` on
// the appliance), the same partition Docker data and the obs stack live on.
func Run(ctx context.Context, nc *nats.Conn, nodeID, diskPath string, uptime func() time.Duration) {
	// Prime the CPU sampler — the first non-blocking call returns 0 because
	// it has no prior reading to delta against. This 100ms call gives us a
	// baseline so the first published sample is real.
	_, _ = cpu.PercentWithContext(ctx, 100*time.Millisecond, false)

	subj := proto.NodeMetricsSubject(nodeID)
	t := time.NewTicker(Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ev := collect(ctx, nodeID, diskPath, uptime)
			payload, err := json.Marshal(ev)
			if err != nil {
				log.Printf("metrics: marshal: %v", err)
				continue
			}
			if err := nc.Publish(subj, payload); err != nil {
				log.Printf("metrics: publish: %v", err)
			}
		}
	}
}

// collect snapshots the current host state into a MetricsEvt. Probes that
// fail are silently omitted from the output map; the api treats missing keys
// as "no data at this tick" which surfaces as gaps in the UI sparkline.
func collect(ctx context.Context, nodeID, diskPath string, uptime func() time.Duration) proto.MetricsEvt {
	m := map[string]float64{
		proto.MetricAgentUptimeSeconds: uptime().Seconds(),
		proto.MetricGoroutines:         float64(runtime.NumGoroutine()),
	}
	if pcts, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(pcts) > 0 {
		m[proto.MetricCPUPercent] = pcts[0]
	}
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		m[proto.MetricMemUsedBytes] = float64(v.Used)
		m[proto.MetricMemTotalBytes] = float64(v.Total)
	}
	// Measure the persistent data partition, not "/". See Run's doc.
	if du, err := disk.UsageWithContext(ctx, diskPath); err == nil {
		m[proto.MetricDiskUsedBytes] = float64(du.Used)
		m[proto.MetricDiskTotalBytes] = float64(du.Total)
	}
	return proto.MetricsEvt{
		NodeID:  nodeID,
		Ts:      time.Now().UTC(),
		Metrics: m,
	}
}
