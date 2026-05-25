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
