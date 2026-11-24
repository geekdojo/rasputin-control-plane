package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// mapApps is an appGetter over a map; err, when set, fails every read.
type mapApps struct {
	apps map[string]*App
	err  error
}

func (m mapApps) Get(_ context.Context, id string) (*App, error) {
	if m.err != nil {
		return nil, m.err
	}
	a, ok := m.apps[id]
	if !ok {
		return nil, sql.ErrNoRows // what Store.Get returns for a missing row
	}
	return a, nil
}

func tile(tier, compose string) tileschema.Tile {
	t := tileschema.Tile{ComposeYAML: compose}
	if tier != "" {
		t.Privilege = &tileschema.Privilege{Tier: tier}
	}
	return t
}

func tilesLookup(tiles map[string]tileschema.Tile, version int) TileLookup {
	return func(id string) (tileschema.Tile, int, bool) {
		t, ok := tiles[id]
		return t, version, ok
	}
}

// TC-1001-11 (apps part): the facts per kind; a missing app is ErrNoApp, a
// store failure an error; the four ResolveUpgrade refusals decide on the
// installed tier with no error, so an already-current upgrade is no 500.
func TestTierReader_TC1001_11_Facts(t *testing.T) {
	apps := mapApps{apps: map[string]*App{
		"tile":    {ID: "tile", SourceTile: "vw", PrivilegeTier: "routine", ComposeSHA256: ComposeHash("old"), ComposeCatalogVersion: 3},
		"current": {ID: "current", SourceTile: "vw", PrivilegeTier: "elevated", ComposeSHA256: ComposeHash("new"), ComposeCatalogVersion: 3},
		"newer":   {ID: "newer", SourceTile: "vw", PrivilegeTier: "routine", ComposeSHA256: ComposeHash("x"), ComposeCatalogVersion: 9},
		"gone":    {ID: "gone", SourceTile: "nope", PrivilegeTier: "routine"},
		"custom":  {ID: "custom", PrivilegeTier: "", PreviousPrivilegeTier: "host-trusting"},
	}}
	r, err := NewTierReader(apps, tilesLookup(map[string]tileschema.Tile{"vw": tile("host-trusting", "new")}, 5))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind, id string
		want     authz.AppFacts
	}{
		{"app.deploy", "tile", authz.AppFacts{Tiers: []string{"routine"}}},
		{UpgradeKind, "tile", authz.AppFacts{Tiers: []string{"routine", "host-trusting"}}},
		{UpgradeKind, "current", authz.AppFacts{Tiers: []string{"elevated"}}},                      // ErrUpgradeAlreadyCurrent
		{UpgradeKind, "newer", authz.AppFacts{Tiers: []string{"routine"}}},                         // ErrUpgradeCatalogOlder
		{UpgradeKind, "gone", authz.AppFacts{Tiers: []string{"routine"}}},                          // ErrUpgradeTileUnavailable
		{UpgradeKind, "custom", authz.AppFacts{Custom: true, Tiers: []string{""}}},                 // ErrUpgradeCustomApp
		{RevertKind, "custom", authz.AppFacts{Custom: true, Tiers: []string{"", "host-trusting"}}}, // the previous tier
		{"app.stop", "custom", authz.AppFacts{Custom: true, Tiers: []string{""}}},
	} {
		got, err := r.AppFacts(t.Context(), tc.kind, tc.id)
		if err != nil || got.Custom != tc.want.Custom || !slices.Equal(got.Tiers, tc.want.Tiers) {
			t.Errorf("%s %s = %+v, %v; want %+v", tc.kind, tc.id, got, err, tc.want)
		}
	}
	if _, err := r.AppFacts(t.Context(), "app.deploy", "missing"); !errors.Is(err, authz.ErrNoApp) {
		t.Errorf("missing app = %v, want ErrNoApp", err)
	}
	down := errors.New("database is locked")
	r, _ = NewTierReader(mapApps{err: down}, tilesLookup(nil, 0))
	if _, err := r.AppFacts(t.Context(), "app.deploy", "tile"); !errors.Is(err, down) || errors.Is(err, authz.ErrNoApp) {
		t.Errorf("store down = %v, want the store's error", err)
	}
}

// TC-1001-11: a missing app in the real store is ErrNoApp.
func TestTierReader_TC1001_11_RealStoreMissing(t *testing.T) {
	r, err := NewTierReader(newStore(t), tilesLookup(nil, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AppFacts(t.Context(), "app.deploy", "no-such-app"); !errors.Is(err, authz.ErrNoApp) {
		t.Errorf("missing app = %v, want ErrNoApp", err)
	}
}

// TC-1001-13 (apps part): NewTierReader refuses either nil.
func TestNewTierReader_TC1001_13_RefusesNil(t *testing.T) {
	if r, err := NewTierReader(nil, tilesLookup(nil, 0)); err == nil || r != nil {
		t.Errorf("NewTierReader(nil, lookup) = %v, %v; want an error", r, err)
	}
	if r, err := NewTierReader(mapApps{}, nil); err == nil || r != nil {
		t.Errorf("NewTierReader(store, nil) = %v, %v; want an error", r, err)
	}
}

// TC-1001-15 (apps part): for a spec with one appId, in any case, the
// policy's target read and the workflow's strict decode read the same id;
// for a duplicated one the policy reads none.
func TestSpecTarget_TC1001_15_MatchesDecodeStrict(t *testing.T) {
	for _, spec := range []string{`{"appId":"a1"}`, `{"APPID":"a1"}`, `{"appid":"a1"}`} {
		var d DeploySpec
		if err := decodeStrict(json.RawMessage(spec), &d); err != nil {
			t.Fatalf("decodeStrict(%s): %v", spec, err)
		}
		got, ok := authz.SpecTarget([]byte(spec), "appId")
		if !ok || got != d.AppID {
			t.Errorf("%s: SpecTarget = %q, %v; decodeStrict read %q", spec, got, ok, d.AppID)
		}
	}
	for _, spec := range []string{`{"appId":"routine","APPID":"custom"}`, `{"appId":"a","appId":"b"}`} {
		var d DeploySpec
		_ = decodeStrict(json.RawMessage(spec), &d)
		if got, ok := authz.SpecTarget([]byte(spec), "appId"); ok {
			t.Errorf("%s: SpecTarget = %q, want no target (the decode reads %q)", spec, got, d.AppID)
		}
	}
}
