package apps

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
)

// The app kinds whose tiers differ from the installed one: an upgrade runs
// its tile's current compose, and a revert re-applies the previous one.
const (
	UpgradeKind = "app.upgrade"
	RevertKind  = "app.revert"
)

// appGetter is the one read TierReader makes.
type appGetter interface {
	Get(ctx context.Context, id string) (*App, error)
}

// TierReader is authz.AppReader over the apps store and the catalog: what an
// app job would run, so the kind table can ask for apps or apps.host (E23).
type TierReader struct {
	store appGetter
	tiles TileLookup
}

// NewTierReader returns a TierReader over store and tiles, the catalog in
// effect. It refuses either nil.
func NewTierReader(store appGetter, tiles TileLookup) (*TierReader, error) {
	switch {
	case store == nil:
		return nil, errors.New("apps: NewTierReader: store is nil")
	case tiles == nil:
		return nil, errors.New("apps: NewTierReader: tiles is nil")
	}
	return &TierReader{store: store, tiles: tiles}, nil
}

// AppFacts is the app appID's facts for a job of kind: Custom for a compose
// not installed from the catalog, and every tier the job would run it at,
// the installed one, plus the previous one for a revert and the catalog
// tile's for an upgrade. An upgrade ResolveUpgrade finds nothing to upgrade
// to is decided on the installed tier: the saga's own resolve refuses it. A
// missing app is authz.ErrNoApp; only a store read failure is an error.
func (t *TierReader) AppFacts(ctx context.Context, kind, appID string) (authz.AppFacts, error) {
	app, err := t.store.Get(ctx, appID)
	switch {
	case errors.Is(err, sql.ErrNoRows) || (err == nil && app == nil):
		return authz.AppFacts{}, authz.ErrNoApp
	case err != nil:
		return authz.AppFacts{}, fmt.Errorf("apps: read the app: %w", err)
	}
	facts := authz.AppFacts{Custom: app.SourceTile == "", Tiers: []string{app.PrivilegeTier}}
	switch kind {
	case RevertKind:
		facts.Tiers = append(facts.Tiers, app.PreviousPrivilegeTier)
	case UpgradeKind:
		target, err := ResolveUpgrade(app, t.tiles)
		switch {
		case err == nil:
			facts.Tiers = append(facts.Tiers, target.Tile.DeclaredPrivilege().EffectiveTier())
		case errors.Is(err, ErrUpgradeAlreadyCurrent), errors.Is(err, ErrUpgradeTileUnavailable),
			errors.Is(err, ErrUpgradeCatalogOlder), errors.Is(err, ErrUpgradeCustomApp):
			// Nothing to upgrade to: the saga refuses it at run time.
		default:
			return authz.AppFacts{}, fmt.Errorf("apps: resolve the upgrade: %w", err)
		}
	}
	return facts, nil
}
