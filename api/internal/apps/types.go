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
	// BackupAck is the install-time acknowledgement design/storage.md §4.4
	// requires when a tile with a `critical` volume is installed while backups
	// are unconfigured (geekdojo/geekdojo-brain#299): the operator was told the
	// data would not be backed up and installed anyway. Nil when the install
	// needed no acknowledgement. It is a record, not a state: the standing nag
	// is derived from the backup ledger, not from this field.
	BackupAck *BackupAck `json:"backupAck,omitempty"`
	// ComposeSHA256 is the hex sha256 of ComposeYAML — the installed compose,
	// as the thing an upgrade check compares against the current tile's
	// (geekdojo/geekdojo-brain#409). Derived by the store on every write that
	// sets the compose, never taken from a caller, so the two cannot disagree.
	ComposeSHA256 string `json:"composeSha256,omitempty"`
	// ComposeCatalogVersion is the catalog version ComposeYAML was taken from.
	// 0 means unknown: a custom-compose app, or a catalog app installed before
	// the column existed, where nothing recorded it.
	ComposeCatalogVersion int `json:"composeCatalogVersion,omitempty"`
	// PreviousComposeYAML is the compose the most recent compose change — an
	// upgrade, a custom edit or a re-apply — replaced; "" if the app's compose
	// has never changed. Kept so a failed change has something to go back to
	// without asking the catalog, which may no longer carry that version, and
	// for a custom app, whose compose exists nowhere else.
	PreviousComposeYAML string `json:"previousComposeYaml,omitempty"`
	// The rest of the record that went with PreviousComposeYAML (#411): the
	// catalog version it came from, and the route and budget it ran with.
	// Re-applying the previous compose swaps all five back together, so the
	// proxy is pointed where that compose actually listens.
	PreviousComposeCatalogVersion int  `json:"previousComposeCatalogVersion,omitempty"`
	PreviousPublishedPort         int  `json:"previousPublishedPort,omitempty"`
	PreviousWebTLS                bool `json:"previousWebTls,omitempty"`
	PreviousDeployBudgetSeconds   int  `json:"previousDeployBudgetSeconds,omitempty"`
	// PrivilegeTier is the tier the installed compose's tile declared —
	// routine, elevated or host-trusting — copied from the tile by install and
	// by every catalog upgrade, and swapped with PreviousPrivilegeTier by a
	// re-apply, so it always describes ComposeYAML. It is what a catalog
	// upgrade's consent compares against (auth-methodology §9 dec 12,
	// geekdojo/geekdojo-brain#522). "" means not recorded: a custom app, which
	// has no tile, or a catalog app installed before the column existed, which
	// an upgrade reads as routine so that anything above it asks once.
	PrivilegeTier string `json:"privilegeTier,omitempty"`
	// PreviousPrivilegeTier is PrivilegeTier as it was beside
	// PreviousComposeYAML.
	PreviousPrivilegeTier string `json:"previousPrivilegeTier,omitempty"`
	// PrivilegeAck is the most recent consent an owner gave to a catalog
	// upgrade that raises this app's tier: who, when, and exactly what they
	// accepted. Nil when no upgrade has needed one. Written by PUT
	// /api/apps/{id}/compose before the upgrade's job starts, and read by that
	// job, which refuses a raise the record does not cover — so consent cannot
	// ride in a job spec, which any caller of POST /api/jobs could write.
	PrivilegeAck *PrivilegeAck `json:"privilegeAck,omitempty"`
}

// PrivilegeAck records an owner's consent to a catalog upgrade that raises an
// app's privilege tier (dec 12), in the style of BackupAck.
type PrivilegeAck struct {
	// At is when the consent was given: the upgrade request's time.
	At time.Time `json:"at"`
	// By is the authenticated user's NAME. Never a session token, never an id.
	By string `json:"by"`
	// What is what was consented to.
	What PrivilegeConsent `json:"what"`
}

// PrivilegeConsent is what a PrivilegeAck accepted: the move from one tier to
// another, the grants and runtime-socket access the target declares, and the
// one compose — by catalog version and hash — the consent is for. The hash is
// what binds it: the upgrade's job honours the record only for that compose.
type PrivilegeConsent struct {
	// FromTier is the tier recorded for the compose being replaced; "" when
	// none was recorded.
	FromTier string `json:"fromTier"`
	// Tier is the target tile's declared tier, resolved (never "").
	Tier         string   `json:"tier"`
	DockerSocket bool     `json:"dockerSocket,omitempty"`
	Grants       []string `json:"grants,omitempty"`
	// CatalogVersion and ComposeSHA256 name the compose consented to.
	CatalogVersion int    `json:"catalogVersion"`
	ComposeSHA256  string `json:"composeSha256"`
}

// BackupAck records that an operator installed an app knowing its critical
// data had nowhere to be backed up to (§4.4's install-time gate, #299).
type BackupAck struct {
	// At is when the acknowledgement was given — the install time.
	At time.Time `json:"at"`
	// By is the authenticated user's NAME. Never a session token, never an
	// id: this is rendered in the drawer as "acknowledged by bryce".
	By string `json:"by"`
}
