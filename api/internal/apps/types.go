package apps

import (
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// App is the api's view of a user-defined application. The api holds the
// declared spec (name, compose YAML, target node) plus the last status the
// agent reported.
type App struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	ComposeYAML   string          `json:"composeYaml"`
	TargetNode    string          `json:"targetNode"`
	LastStatus    proto.AppStatus `json:"lastStatus"`
	LastDetail    string          `json:"lastDetail,omitempty"`
	LastDeployed  *time.Time      `json:"lastDeployed,omitempty"`
	LastStopped   *time.Time      `json:"lastStopped,omitempty"`
	LastStatusAt  *time.Time      `json:"lastStatusAt,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}
