package proto

import "time"

// SystemRebootCmd is the request body for rasputin.node.<id>.cmd.system.reboot.
// The agent restarts the node's operating system: it acks, publishes a
// SystemRebootingEvt, waits DelaySeconds so the ack can leave the node, and
// runs the OS reboot command. It is always a PLAIN reboot, never an A/B trial
// boot — only the update path asks for one of those.
type SystemRebootCmd struct {
	DelaySeconds int `json:"delaySeconds"`
}

// SystemRebootAck is the synchronous reply the agent sends before it goes
// offline. OK=false means the reboot was refused and will not happen; Detail
// says why (for example, the image has no reboot command). An agent older than
// the Detail field never sent OK=false.
type SystemRebootAck struct {
	OK           bool   `json:"ok"`
	DelaySeconds int    `json:"delaySeconds"`
	Detail       string `json:"detail,omitempty"`
}

// SystemRebootingEvt is published on rasputin.node.<id>.evt.rebooting right
// before the agent goes silent. The saga uses it as the cue to advance from
// the "request" step to the "wait for online" step.
//
// It is an ANNOUNCEMENT, never evidence: it says a reboot was asked for, not
// that one happened. What proves a reboot is the node answering on a different
// boot identity afterwards.
//
// Reason, Mode and BootID are absent from an agent that predates them.
type SystemRebootingEvt struct {
	NodeID       string `json:"nodeId"`
	DelaySeconds int    `json:"delaySeconds"`
	// Reason names who asked for the reboot, e.g. "system.reboot".
	Reason string `json:"reason,omitempty"`
	// Mode is "plain" or "tryboot" (the Raspberry Pi A/B trial boot).
	Mode string `json:"mode,omitempty"`
	// BootID is the boot identity the node is about to leave.
	BootID string `json:"bootId,omitempty"`
	// Simulated is true only from an agent started in the explicit dev mock
	// configuration, where no operating system is restarted.
	Simulated bool      `json:"simulated,omitempty"`
	Ts        time.Time `json:"ts"`
}

// SystemRebootFailedEvt is published on rasputin.node.<id>.evt.reboot_failed
// when the agent announced a reboot and the OS reboot command then failed. The
// node is still up on the boot it announced it was leaving.
type SystemRebootFailedEvt struct {
	NodeID string `json:"nodeId"`
	Reason string `json:"reason,omitempty"`
	Mode   string `json:"mode,omitempty"`
	BootID string `json:"bootId,omitempty"`
	Detail string `json:"detail"`
	// Definitive is true only when the agent established that the reboot did
	// not happen: the command failed on its own terms, or was killed while
	// the system positively was not shutting down, and no shutdown was under
	// way. It is the only form of this event the control plane ends a
	// restart's verification on.
	//
	// An agent that predates it (up to CP 2026.09.5-dev.182) publishes this
	// event even when the reboot command was killed by the very shutdown it
	// started — a real reboot reported as a failed one
	// (geekdojo/geekdojo-brain#616, cp-compute1 on the bench). Without
	// Definitive the event is therefore not evidence of anything, and the
	// control plane waits on the boot identity instead.
	Definitive bool      `json:"definitive,omitempty"`
	Ts         time.Time `json:"ts"`
}
