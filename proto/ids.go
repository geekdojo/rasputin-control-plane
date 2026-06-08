package proto

import "time"

// IDSAlertEvt is one parsed snort3 alert, published on
// rasputin.node.<id>.evt.ids.alert when the agent's IDS subsystem sees
// a new line in the firewall's alert_fast log.
//
// The wire shape is intentionally close to snort's alert_fast text: each
// alert is one Evt, with the structured fields the controlplane needs
// for filtering/grouping/labels plus the original log line in Raw for
// fidelity (the parser is best-effort; if a future snort version subtly
// changes the format, the structured fields may degrade but Raw still
// preserves what snort emitted).
//
// Note: snort emits IDSAlertEvts at potentially high rates under a scan
// (hundreds per second per signature). The agent's publisher coalesces
// to keep the bus from drowning — see agent/internal/ids/publisher.go.
type IDSAlertEvt struct {
	NodeID         string    `json:"nodeId"`
	Ts             time.Time `json:"ts"`             // when snort matched, parsed from the log line
	GID            int       `json:"gid"`            // generator id (rule subsystem)
	SID            int       `json:"sid"`            // signature id
	Rev            int       `json:"rev"`            // rule revision
	Message        string    `json:"message"`        // rule's msg: field, human-readable
	Classification string    `json:"classification"` // rule's classtype: text
	Priority       int       `json:"priority"`       // 1=highest, 4=lowest
	Protocol       string    `json:"protocol"`       // TCP/UDP/ICMP/...
	SrcAddr        string    `json:"srcAddr"`        // string form — covers v4, v6, MAC for ARP
	SrcPort        int       `json:"srcPort,omitempty"`
	DstAddr        string    `json:"dstAddr"`
	DstPort        int       `json:"dstPort,omitempty"`
	Raw            string    `json:"raw"` // original alert_fast line, verbatim
}

// IDSAlertSubject returns the subject an agent publishes IDS alerts to.
func IDSAlertSubject(nodeID string) string {
	return NodeEvtSubject(nodeID, "ids.alert")
}

// AllIDSAlertsFilter matches every node's IDS alerts. Used by the api's
// IDS subscriber. (The pattern mirrors AllUpdateProgressFilter — wildcard
// over node id, deep-match over the ids.* subspace so future IDS event
// kinds — stats, ruleset-reloaded, etc. — flow through the same subscriber.)
const AllIDSAlertsFilter = "rasputin.node.*.evt.ids.>"
