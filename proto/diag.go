package proto

import "time"

// DiagPingCmd is the request body for a diag.ping command.
type DiagPingCmd struct {
	JobID string `json:"jobId"`
}

// DiagPongEvt is the reply an agent returns to a diag.ping command.
type DiagPongEvt struct {
	JobID    string    `json:"jobId"`
	NodeID   string    `json:"nodeId"`
	Hostname string    `json:"hostname"`
	Uptime   string    `json:"uptime"`
	Ts       time.Time `json:"ts"`
}

// DiagHealthCmd requests a role-aware health check. Unlike diag.ping (which only
// proves the agent process is up + reachable), the agent runs checks specific to
// what its role must actually do — e.g. the firewall verifies its data plane
// (nftables ruleset loaded, dnsmasq serving) so an update that boots the agent
// but breaks NAT/DHCP is caught and rolled back instead of committed. Used by
// the node.update saga's post-reboot health gate.
type DiagHealthCmd struct {
	JobID string `json:"jobId"`
}

// HealthCheck is one named probe result. Overall health (DiagHealthAck.OK) is
// the AND of every Critical check; non-critical checks are reported for
// visibility but don't fail the gate (e.g. a WAN route that may still be
// re-acquiring a DHCP lease shortly after a reboot).
type HealthCheck struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Critical bool   `json:"critical"`
	Detail   string `json:"detail,omitempty"`
}

// DiagHealthAck is the agent's reply to diag.health. OK is the health verdict
// the saga commits / rolls-back on.
type DiagHealthAck struct {
	JobID  string        `json:"jobId"`
	NodeID string        `json:"nodeId"`
	Role   string        `json:"role"`
	OK     bool          `json:"ok"`
	Checks []HealthCheck `json:"checks,omitempty"`
	Detail string        `json:"detail,omitempty"`
	Ts     time.Time     `json:"ts"`
}
