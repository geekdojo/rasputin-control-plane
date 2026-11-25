package idclient

import (
	"context"
	"log/slog"
)

// HealthReport is the body of the identity service's /health/ready: the
// overall status and each named check's. A 503 names the check that is DOWN,
// which is how a stopped database is told apart from a service that is not
// up yet (capability row K-HEALTH).
type HealthReport struct {
	Status string        `json:"status"`
	Checks []HealthCheck `json:"checks"`
}

// HealthCheck is one check of a HealthReport.
type HealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Down reports whether the check called name is in the report with a status
// other than UP.
func (r HealthReport) Down(name string) bool {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status != "UP"
		}
	}
	return false
}

// Health asks the management listener's /health/ready once and returns its
// report, under the client's call bound. Its errors are Ready's; with a 5xx
// whose body is the health JSON, the report comes back with the error. It
// writes its record for a failed call at DEBUG: its caller, the identity
// state monitor, turns every answer into a state and logs the transition
// itself (geekdojo/geekdojo-brain#979). CodeQL's go/log-injection at its
// LogAttrs call is the false positive the register records for failed's
// (client.go), on the same grounds.
func (c *Client) Health(ctx context.Context) (HealthReport, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	rep, e := c.health(ctx, "health")
	if e != nil {
		c.log.LogAttrs(ctx, slog.LevelDebug, "identity service call failed",
			append([]slog.Attr{slog.String("component", "identity")}, e.LogAttrs()...)...)
		return rep, e
	}
	return rep, nil
}
