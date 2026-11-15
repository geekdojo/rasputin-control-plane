// Package proto defines the wire types and NATS subject names shared
// between rasputin-api and rasputin-agent.
//
// Subject conventions (see design/control-plane/architecture.md §5.2):
//
//	rasputin.node.<node-id>.cmd.<subsystem>.<verb>   control plane → agent
//	rasputin.node.<node-id>.evt.<subsystem>.<event>  agent → control plane (broadcast)
//	rasputin.node.<node-id>.relay.<subsystem>.<verb> agent → control plane (request)
//	rasputin.node.<node-id>.cmd.app.relay.reply.<id> control plane's reply to a relay request
//	rasputin.node.<node-id>.heartbeat                10s liveness
//	rasputin.node.<node-id>.log.<source>             streaming log lines
//	rasputin.job.<job-id>.events                     job lifecycle events
//	rasputin.job.<job-id>.log                        per-job aggregated log
//
// The relay lane is the one request an agent makes of the control plane: an
// app's call on its relay socket (apprelay.go, geekdojo/geekdojo-brain#1081).
// Its reply comes back on the node's own command lane, which only that node
// may subscribe to and no node may publish on, so no node needs an inbox
// grant and none can read another's replies.
package proto

import "fmt"

// NodeCmdSubject returns the subject for a command sent from the control
// plane to an agent. The verb is a dotted path, e.g. "diag.ping".
func NodeCmdSubject(nodeID, verb string) string {
	return fmt.Sprintf("rasputin.node.%s.cmd.%s", nodeID, verb)
}

// NodeCmdFilter returns the wildcard filter that an agent uses to subscribe
// to all commands targeted at it.
func NodeCmdFilter(nodeID string) string {
	return fmt.Sprintf("rasputin.node.%s.cmd.>", nodeID)
}

// NodeEvtSubject returns the subject an agent publishes events to.
func NodeEvtSubject(nodeID, event string) string {
	return fmt.Sprintf("rasputin.node.%s.evt.%s", nodeID, event)
}

// NodeHeartbeatSubject returns the agent's heartbeat subject.
func NodeHeartbeatSubject(nodeID string) string {
	return fmt.Sprintf("rasputin.node.%s.heartbeat", nodeID)
}

// JobEventsSubject is where the api publishes lifecycle events for a job.
// The UI subscribes to "rasputin.job.>" to follow everything.
func JobEventsSubject(jobID string) string {
	return fmt.Sprintf("rasputin.job.%s.events", jobID)
}

// JobLogSubject is where step logs for a job are published.
func JobLogSubject(jobID string) string {
	return fmt.Sprintf("rasputin.job.%s.log", jobID)
}

// AllJobsFilter is the wildcard the UI uses to receive every job event.
const AllJobsFilter = "rasputin.job.>"

// NodeRegisteredSubject is the canonical subject for an agent's registration
// event, published on connect and reconnect.
func NodeRegisteredSubject(nodeID string) string {
	return NodeEvtSubject(nodeID, "registered")
}

// InventoryChangedSubject is the subject the api publishes to when a node's
// status, role, or membership changes. Change is the event name
// (e.g. "added", "online", "stale", "offline", "updated").
func InventoryChangedSubject(nodeID, change string) string {
	return fmt.Sprintf("rasputin.inventory.%s.%s", nodeID, change)
}

// AllInventoryFilter is the wildcard the UI uses to receive every inventory
// change event.
const AllInventoryFilter = "rasputin.inventory.>"

// AllHeartbeatsFilter matches every node's heartbeat.
const AllHeartbeatsFilter = "rasputin.node.*.heartbeat"
