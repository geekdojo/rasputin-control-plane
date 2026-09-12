package apps

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// TileLookup resolves a catalog tile id against the catalog in effect,
// returning the tile with its compose attached and the version of the catalog
// that answered, read together. main backs it with
// catalogsync.Store.GetVersioned — the verified store, whose tiles were
// signature-, safety- and pin-checked when their bundle was applied. nil means
// this api has no live catalog, and every tile is unavailable.
//
// A func rather than an interface so "no catalog" is a plain nil: a nil
// *catalogsync.Store inside an interface is not nil, and would be called.
type TileLookup func(id string) (tile tileschema.Tile, catalogVersion int, ok bool)

// UpgradeTarget is the tile an app would be upgraded to, and which catalog
// supplied it.
type UpgradeTarget struct {
	Tile           tileschema.Tile
	CatalogVersion int
}

// ComposeUpgrade is the row write this target makes: the tile's compose, and
// the same three fields install copies from a tile
// (api/internal/api/catalog_handlers.go handleInstallCatalogTile), re-copied
// for the same reason install copies them — the route and the deploy budget
// are read from the app record, and after an upgrade the record has to
// describe the compose that is now installed.
func (t UpgradeTarget) ComposeUpgrade() ComposeUpgrade {
	return ComposeUpgrade{
		ComposeYAML:         t.Tile.ComposeYAML,
		CatalogVersion:      t.CatalogVersion,
		PublishedPort:       t.Tile.WebPort(),
		WebTLS:              t.Tile.WebPortTLS(),
		DeployBudgetSeconds: t.Tile.DeployBudgetSeconds,
	}
}

// The reasons ResolveUpgrade finds nothing to upgrade to. The HTTP layer
// answers ErrUpgradeAlreadyCurrent as the no-op PUT /api/apps/{id}/compose is
// (200, current state, no job), and each of the others with a 409 carrying the
// error text, so the text is written for the owner.
var (
	ErrUpgradeCustomApp       = errors.New("this app was not installed from the catalog, so there is no tile to upgrade it to; a custom app's compose is replaced by sending it as composeYaml")
	ErrUpgradeTileUnavailable = errors.New("this app's catalog tile is not available")
	ErrUpgradeAlreadyCurrent  = errors.New("this app already runs its tile's current compose")
	ErrUpgradeCatalogOlder    = errors.New("the catalog in effect is older than the one this app's compose came from")
)

// ResolveUpgrade decides whether app has an upgrade, and to what.
//
// One implementation, three callers: the upgradeAvailable flag on GET
// /api/apps, PUT /api/apps/{id}/compose with {"source":"catalog"}, and the
// saga's persist step. If the badge and the route answered the question two ways, the
// UI would offer upgrades the route refuses, or hide ones it would take.
//
// The new compose comes from lookup and nowhere else. Signature, tile-safety
// and digest-pin checks run when a bundle is applied, never at install, so the
// verified store's copy is the only compose that has been through them.
func ResolveUpgrade(app *App, lookup TileLookup) (UpgradeTarget, error) {
	if app.SourceTile == "" {
		return UpgradeTarget{}, ErrUpgradeCustomApp
	}
	if lookup == nil {
		return UpgradeTarget{}, fmt.Errorf("%w: this api has no live catalog", ErrUpgradeTileUnavailable)
	}
	tile, version, ok := lookup(app.SourceTile)
	if !ok {
		return UpgradeTarget{}, fmt.Errorf("%w: tile %q is not in the catalog in effect", ErrUpgradeTileUnavailable, app.SourceTile)
	}
	if !tile.Available() {
		return UpgradeTarget{}, fmt.Errorf("%w: tile %q is a preview in the catalog in effect", ErrUpgradeTileUnavailable, app.SourceTile)
	}
	// A recorded version newer than the catalog in effect means the catalog
	// went backwards — a cached bundle that failed re-verification leaves the
	// embedded floor in effect, and the floor can be older than what an app
	// was installed or upgraded from. Its tile differs by hash, so without
	// this it would be offered as an upgrade. It is a downgrade, and a
	// downgrade cannot undo a data migration the newer image may already have
	// run. 0 is "not recorded" (every install before the column existed) and
	// falls through to the hash alone.
	if app.ComposeCatalogVersion > version {
		return UpgradeTarget{}, fmt.Errorf("%w: the catalog in effect is v%d and this app's compose came from v%d, so its tile would be a downgrade",
			ErrUpgradeCatalogOlder, version, app.ComposeCatalogVersion)
	}
	if ComposeHash(tile.ComposeYAML) == app.ComposeSHA256 {
		return UpgradeTarget{}, fmt.Errorf("%w (catalog v%d)", ErrUpgradeAlreadyCurrent, version)
	}
	return UpgradeTarget{Tile: tile, CatalogVersion: version}, nil
}

// UpgradeWorkflow drives app.upgrade (geekdojo/geekdojo-brain#409): replace a
// catalog app's compose with its tile's current one and redeploy it, in place.
//
//  1. load    — the app and its node, checked as a deploy checks them
//  2. pull    — resolve the tile and pull its compose's images on the node,
//     changing nothing else there and nothing on the row (#411, see pull.go)
//  3. persist — resolve the tile again and write its compose onto the row,
//     refusing any compose other than the one just pulled
//  4. push    — the deploy saga's push, unchanged
//  5. leaf    — the deploy saga's leaf step: the tile may have moved its web
//     port or changed its scheme, and the route is built from the row
//
// In place is the point. The app keeps its ULID, so the agent's Compose
// project (proto.AppProjectName) and every named volume (proto.AppVolumeName)
// keep their names, and `up -d` recreates only the containers whose definition
// changed. Delete and reinstall mints a new ULID, and the app starts empty.
//
// ORDERING: the row is written BEFORE the push, deliberately.
//
// The push is the deploy saga's, and it sends whatever compose the row holds,
// so this is also the order that reuses it unchanged — but that is not the
// reason. The reason is what the row says when something goes wrong:
//
//   - The agent writes the compose file to disk before it runs `up`, so from
//     the moment the push is sent the node holds the new compose, whether the
//     push then succeeds or not. Row-first keeps the row naming what the node
//     was last told.
//   - Push-first has a window after the agent acks and before the row is
//     written. An api restart in it leaves new containers running — which may
//     already have migrated the app's data — under a row that still holds the
//     OLD compose. Nothing reports that, and the next ordinary deploy would
//     push the old compose back over the migrated data. That is the direction
//     that cannot be recovered.
//   - Nothing redeploys from the row on its own. The reconcile sweep reports
//     observed status and never pushes a compose; only an owner's deploy (or
//     this saga) does. So the row holding the new compose cannot cause a
//     deploy nobody asked for.
//
// The pull goes before the row write because it does not touch the node's
// compose (pull.go says why that makes a failed pull need no undo at all). A
// failed pull therefore leaves the row, previous_compose_yaml included, and
// the running app exactly as they were, puts the status back, and records the
// registry's error; upgradeAvailable still reads true.
//
// On a failed push — the pull succeeded, so `up` itself failed — the row keeps
// the NEW compose, the replaced one is in previous_compose_yaml, the status is
// failed with the agent's reason, and upgradeAvailable reads false because the
// installed hash now matches the tile. Nothing is reverted automatically: new
// containers may have started and migrated the data. Retrying is an ordinary
// deploy; going back is the owner's explicit re-apply (RevertWorkflow).
func UpgradeWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, mint LeafMinter, lookup TileLookup) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.upgrade",
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: upgradeLoad(store, inv)},
			// A backstop, like push's: the real deadline is the tile's budget,
			// applied inside the step once the tile is resolved.
			{Name: "pull", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: pullStep(store, inv, nc, "upgrade", deploySpecAppID, upgradePullSource(lookup))},
			{Name: "persist", Timeout: 2 * time.Second, Do: upgradePersist(store, inv, nc, lookup)},
			// Same backstop as DeployWorkflow's push, for the same reason: the
			// real deadline is the app's own budget, applied inside deployPush,
			// and here that is the budget persist just re-copied from the tile.
			{Name: "push", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: deployPush(store, inv, nc)},
			{Name: "leaf", Timeout: 15 * time.Second, Do: deployLeaf(store, inv, nc, mint)},
		},
	}
}

func upgradeLoad(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("upgrading %q on %s from tile %q", app.Name, app.TargetNode, app.SourceTile))
		return json.Marshal(map[string]string{"appId": app.ID, "targetNode": app.TargetNode, "sourceTile": app.SourceTile})
	}
}

// upgradePullSource is the compose an upgrade is about to write: the tile's,
// resolved exactly as persist will resolve it. Every refusal ResolveUpgrade
// makes is made here first, before the app is marked or the node is asked
// anything.
func upgradePullSource(lookup TileLookup) pullSource {
	return func(sc *jobs.StepCtx, app *App) (pullTarget, error) {
		target, err := ResolveUpgrade(app, lookup)
		if errors.Is(err, ErrUpgradeAlreadyCurrent) {
			// A second upgrade that lost the race; persist will deploy what
			// the row holds, so that is what gets pulled.
			return pullTarget{ComposeYAML: app.ComposeYAML, DeployBudgetSeconds: app.DeployBudgetSeconds}, nil
		}
		if err != nil {
			return pullTarget{}, err
		}
		return pullTarget{ComposeYAML: target.Tile.ComposeYAML, DeployBudgetSeconds: target.Tile.DeployBudgetSeconds}, nil
	}
}

// errCatalogMovedDuringPull is persist finding that the tile's compose is no
// longer the one whose images the pull step fetched.
var errCatalogMovedDuringPull = errors.New("upgrade not applied: the catalog changed while the images were being pulled, and nothing on the node was changed — request the upgrade again")

// upgradePersist writes the tile's compose onto the app row.
//
// The tile is resolved again here rather than carried from the handler in the
// job spec. A spec is persisted and rendered on the Tasks page, and a compose
// that can travel in a spec is a compose some later caller can put there; the
// spec stays {appId} and the verified store stays the only source.
//
// Resolving again means the catalog can have moved during the pull. The
// compose written must be the one whose images were pulled, so a different
// one is refused — with nothing on the node or the row changed, the status put
// back, and the owner told to ask again.
func upgradePersist(store *Store, inv *inventory.Store, nc *nats.Conn, lookup TileLookup) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		pulled, err := pulledCompose(sc)
		if err != nil {
			return nil, err
		}
		abandon := func(err error) (json.RawMessage, error) {
			abandonAfterPull(sc, store, nc, pulled, err.Error())
			return nil, err
		}
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return abandon(fmt.Errorf("upgrade not applied: %w", err))
		}
		target, err := ResolveUpgrade(app, lookup)
		if errors.Is(err, ErrUpgradeAlreadyCurrent) {
			if app.ComposeSHA256 != pulled.ComposeSHA256 {
				return abandon(errCatalogMovedDuringPull)
			}
			// The handler answers an app that is already current with a no-op
			// and starts no job, so this is a second upgrade that got here
			// first. The row already holds the
			// tile's compose; pushing it is still what this job was asked to
			// bring about, and `up -d` on an unchanged compose changes nothing.
			sc.Log("info", "the row already holds the tile's current compose; deploying it")
			return json.Marshal(map[string]any{"appId": app.ID, "persisted": false, "composeSha256": app.ComposeSHA256})
		}
		if err != nil {
			return abandon(fmt.Errorf("upgrade not applied: %w", err))
		}
		up := target.ComposeUpgrade()
		toHash := ComposeHash(up.ComposeYAML)
		if toHash != pulled.ComposeSHA256 {
			return abandon(errCatalogMovedDuringPull)
		}
		if err := store.UpgradeCompose(sc.Ctx, app.ID, app.ComposeSHA256, up, time.Now().UTC()); err != nil {
			if errors.Is(err, ErrComposeChanged) {
				return abandon(fmt.Errorf("the app's compose changed while this upgrade was starting; nothing was deployed — check the app and request the upgrade again: %w", err))
			}
			return abandon(fmt.Errorf("upgrade not applied: persist upgraded compose: %w", err))
		}
		sc.Log("info", fmt.Sprintf("compose replaced with tile %q from catalog v%d (%.12s → %.12s)",
			app.SourceTile, target.CatalogVersion, app.ComposeSHA256, toHash))
		return json.Marshal(map[string]any{
			"appId": app.ID, "persisted": true, "catalogVersion": target.CatalogVersion,
			"fromComposeSha256": app.ComposeSHA256, "toComposeSha256": toHash,
		})
	}
}
