package firewall

import (
	"encoding/json"
	"time"
)

// Intent is the api's persisted form of a user-declared firewall intent.
// Spec is event-kind-specific JSON (see proto.PortForwardSpec etc).
type Intent struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Enabled   bool            `json:"enabled"`
	Spec      json.RawMessage `json:"spec"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// NodeState is the api's view of a firewall node's apply/reconcile status.
type NodeState struct {
	NodeID         string     `json:"nodeId"`
	IntentHash     string     `json:"intentHash"`     // what we last pushed
	ObservedHash   string     `json:"observedHash"`   // what agent reported on last reconcile
	LastApplied    *time.Time `json:"lastApplied,omitempty"`
	LastReconciled *time.Time `json:"lastReconciled,omitempty"`
	// Drift is true when ObservedHash is set and differs from IntentHash.
	// Set to false when not yet reconciled (we don't claim drift on no data).
	Drift bool `json:"drift"`
}
