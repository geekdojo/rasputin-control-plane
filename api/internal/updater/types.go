package updater

import (
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Bundle is the api-side record of an uploaded RAUC (or mock) bundle. The
// SHA256 is the content-addressed identifier used by agents to fetch.
type Bundle struct {
	SHA256       string    `json:"sha256"`
	Version      string    `json:"version"`
	Compatible   string    `json:"compatible"`
	Architecture string    `json:"architecture"`
	Description  string    `json:"description"`
	BuildDate    string    `json:"buildDate"`
	SizeBytes    int64     `json:"sizeBytes"`
	SignedBy     string    `json:"signedBy"`
	StoragePath  string    `json:"-"` // filesystem location; never exposed in JSON
	UploadedAt   time.Time `json:"uploadedAt"`
	UploadedBy   string    `json:"uploadedBy"`
}

// NodeUpdateStatus is the api's high-level outcome for an update job. The
// per-step detail lives in the jobs table; this is the rollup that the
// Updates UI displays in a list.
type NodeUpdateStatus string

const (
	NodeUpdateInProgress NodeUpdateStatus = "in_progress"
	NodeUpdateCommitted  NodeUpdateStatus = "committed"
	NodeUpdateRolledBack NodeUpdateStatus = "rolled_back"
	NodeUpdateFailed     NodeUpdateStatus = "failed"
)

// NodeUpdate is one row of update history per node.
type NodeUpdate struct {
	JobID        string           `json:"jobId"`
	NodeID       string           `json:"nodeId"`
	BundleSHA256 string           `json:"bundleSha256"`
	FromSlot     proto.UpdateSlot `json:"fromSlot"`
	ToSlot       proto.UpdateSlot `json:"toSlot"`
	FromVersion  string           `json:"fromVersion"`
	ToVersion    string           `json:"toVersion"`
	Status       NodeUpdateStatus `json:"status"`
	StartedAt    time.Time        `json:"startedAt"`
	FinishedAt   *time.Time       `json:"finishedAt,omitempty"`
	Error        string           `json:"error,omitempty"`
}
