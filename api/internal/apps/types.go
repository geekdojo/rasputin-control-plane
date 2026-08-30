package apps

import (
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// App is the api's view of a user-defined application. The api holds the
// declared spec (name, compose YAML, target node) plus the last status the
// agent reported.
type App struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ComposeYAML string `json:"composeYaml"`
	TargetNode  string `json:"targetNode"`
	// PublishedPort is the host port the reverse proxy fronts for this app
	// (0 = none — a page-less app). Seeded from the catalog tile's web port at
	// install. See app-access.md.
	PublishedPort int `json:"publishedPort,omitempty"`
	// WebTLS says the app serves HTTPS on PublishedPort, so the proxy's upstream
	// leg must be TLS too. Copied from the tile's web port at install (#387),
	// for the same reason DeployBudgetSeconds is: the route is re-asserted to
	// the node from THIS record on every rotation sweep, so a scheme read back
	// from the catalog could change under a running install — or be missing
	// entirely if the tile were withdrawn.
	WebTLS bool `json:"webTls,omitempty"`
	// SourceTile is the catalog tile id this app was installed from ("" for a
	// custom-compose app). Lets the UI show the tile's docs + first-run note (AP-9).
	SourceTile string `json:"sourceTile,omitempty"`
	// DeployBudgetSeconds is how long the agent may spend bringing this app up,
	// copied from its catalog tile at install (0 = the tile declared nothing, so
	// use the default). Stored on the app rather than read back from the tile
	// because the tile can change under a running install, and the budget a
	// deploy is judged against should be the one that was installed. Read it
	// through proto.AppDeployWorkFor / proto.AppDeployRPCFor, never directly.
	DeployBudgetSeconds int `json:"deployBudgetSeconds,omitempty"`
	// ExposeLAN opts the app into LAN reachability (ADR-0004 §9). Default false:
	// the app is tailnet-only — bare <app>.<cluster-id>.internal (tailnet) name,
	// proxy bound to the tailnet interface only. When true it also gets the
	// <app>.lan.<cluster-id>.internal name (LAN IP) and a LAN-interface bind.
	ExposeLAN    bool            `json:"exposeLan"`
	LastStatus   proto.AppStatus `json:"lastStatus"`
	LastDetail   string          `json:"lastDetail,omitempty"`
	LastDeployed *time.Time      `json:"lastDeployed,omitempty"`
	LastStopped  *time.Time      `json:"lastStopped,omitempty"`
	LastStatusAt *time.Time      `json:"lastStatusAt,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`
	UpdatedAt    time.Time       `json:"updatedAt"`
}
