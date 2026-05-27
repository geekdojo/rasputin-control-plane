package bmc

import (
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// NodeState is the api's view of one node's BMC-controlled state.
type NodeState struct {
	TargetNodeID  string              `json:"targetNodeId"`
	PowerState    proto.BMCPowerState `json:"powerState"`
	LastCmd       string              `json:"lastCmd,omitempty"`
	LastCmdAt     *time.Time          `json:"lastCmdAt,omitempty"`
	LastCmdResult string              `json:"lastCmdResult,omitempty"`
	UpdatedAt     time.Time           `json:"updatedAt"`
}
