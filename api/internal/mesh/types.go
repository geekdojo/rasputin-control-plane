package mesh

import (
	"encoding/json"
	"time"
)

// Intent is one row of the mesh_intents table. Spec is opaque to the
// store — kind determines how to interpret it.
type Intent struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Enabled   bool            `json:"enabled"`
	Spec      json.RawMessage `json:"spec"`
	HSID      string          `json:"hsId,omitempty"`
	HSValue   string          `json:"hsValue,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// MeshState is the singleton row recording last-applied / last-reconciled
// hashes. Mirrors firewall.NodeState in spirit; the tailnet is the unit
// rather than per-node.
type MeshState struct {
	IntentHash     string     `json:"intentHash"`
	ObservedHash   string     `json:"observedHash"`
	LastApplied    *time.Time `json:"lastApplied,omitempty"`
	LastReconciled *time.Time `json:"lastReconciled,omitempty"`
	Drift          bool       `json:"drift"`
}

// Device is one row of the mesh_devices table.
type Device struct {
	HSID             string    `json:"hsId"`
	User             string    `json:"user"`
	Hostname         string    `json:"hostname"`
	TailnetIP        string    `json:"tailnetIp"`
	Tags             []string  `json:"tags"`
	AdvertisedRoutes []string  `json:"advertisedRoutes"`
	RasputinNodeID   string    `json:"rasputinNodeId,omitempty"`
	Kind             string    `json:"kind"` // "rasputin" | "user"
	FirstSeen        time.Time `json:"firstSeen"`
	LastSeen         time.Time `json:"lastSeen"`
}
