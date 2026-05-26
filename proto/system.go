package proto

import "time"

// SystemRebootCmd is the request body for rasputin.node.<id>.cmd.system.reboot.
// In v0 the agent simulates downtime by muting its heartbeat for DelaySeconds.
// In production this maps to a BMC power-cycle command sent to the adjacent
// node's slot.
type SystemRebootCmd struct {
	DelaySeconds int `json:"delaySeconds"`
}

// SystemRebootAck is the synchronous reply the agent sends before it goes
// "offline".
type SystemRebootAck struct {
	OK           bool `json:"ok"`
	DelaySeconds int  `json:"delaySeconds"`
}

// SystemRebootingEvt is published on rasputin.node.<id>.evt.rebooting right
// before the agent goes silent. The saga uses it as the cue to advance from
// the "request" step to the "wait for online" step.
type SystemRebootingEvt struct {
	NodeID       string    `json:"nodeId"`
	DelaySeconds int       `json:"delaySeconds"`
	Ts           time.Time `json:"ts"`
}
