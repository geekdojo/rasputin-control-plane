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
//
// The state surface is three-valued:
//
//   - in sync: Pending=false AND Drift=false
//   - pending: Pending=true  AND Drift=false (user has changes to push)
//   - drift:   Drift=true                    (firewall changed under us)
//
// When both Pending and Drift are true (user has changes AND firewall was
// hand-edited), drift dominates in the UI — it's the more surprising state.
// Pending is computed on read by the api (handler runs Compile against the
// current intents); it's not persisted.
type NodeState struct {
	NodeID         string     `json:"nodeId"`
	IntentHash     string     `json:"intentHash"`   // what we last pushed
	ObservedHash   string     `json:"observedHash"` // what agent reported on last reconcile
	LastApplied    *time.Time `json:"lastApplied,omitempty"`
	LastReconciled *time.Time `json:"lastReconciled,omitempty"`
	// Drift is true when ObservedHash is set and differs from IntentHash.
	// Set to false when not yet reconciled (we don't claim drift on no data).
	Drift bool `json:"drift"`
	// Pending is true when the current compiled intent hash differs from the
	// last-pushed IntentHash — i.e. the user has changes they haven't
	// Applied yet. Computed at GET-state time, not stored.
	Pending bool `json:"pending"`
}
