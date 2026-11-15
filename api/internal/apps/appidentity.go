package apps

import (
	"context"
	"errors"
)

// AppIdentityIssuer gives an app its runtime identity and takes it away
// (geekdojo/geekdojo-brain#1078, #1081). Under the 2026-11-15 ruling on #1079
// an app reaches the secret store through a per-app relay socket on its
// agent, never the store itself: Issue opens or refreshes that socket on the
// app's node, and Revoke removes it. The deploy family calls Issue from the
// push step, before the deploy command is built, for an app that has been
// granted one; the delete saga calls Revoke. api/internal/apprelay implements
// it.
type AppIdentityIssuer interface {
	Issue(ctx context.Context, app *App) error
	Revoke(ctx context.Context, app *App) error
}

// AppIdentity is the switch that keeps app identities off until an app is
// granted one (geekdojo/geekdojo-brain#1080). Its zero value is the switch
// off: no tile is granted and no issuer is called, so every deploy goes out
// exactly as it did before the switch existed.
//
// A grant is by catalog tile, read from the app row's SourceTile. A custom
// app has no source tile, so it can never be granted.
//
// The fields are unexported. NewAppIdentity is the only way to grant a tile,
// and it refuses a grant with no issuer to honour it.
type AppIdentity struct {
	tiles  map[string]bool
	issuer AppIdentityIssuer
}

// NewAppIdentity grants tiles an identity issued through issuer. It refuses a
// non-empty tile list with a nil issuer: a grant nothing can honour would
// fail every push of the tile. An empty list with a nil issuer is the switch
// off. The empty tile id is never granted, so a custom app never is.
func NewAppIdentity(tiles []string, issuer AppIdentityIssuer) (AppIdentity, error) {
	if len(tiles) > 0 && issuer == nil {
		return AppIdentity{}, errors.New("apps: NewAppIdentity: tiles are granted an identity, but there is no issuer to issue it")
	}
	a := AppIdentity{tiles: map[string]bool{}, issuer: issuer}
	for _, t := range tiles {
		if t != "" {
			a.tiles[t] = true
		}
	}
	return a, nil
}

// Granted reports whether app is granted an identity.
func (a AppIdentity) Granted(app *App) bool {
	return app != nil && app.SourceTile != "" && a.tiles[app.SourceTile]
}

// Any reports whether any tile is granted. The delete saga carries its
// teardown_relay step only when one is, so with the switch off its steps are
// what they were before the switch existed.
func (a AppIdentity) Any() bool {
	return len(a.tiles) > 0
}

// issue issues app its identity if it is granted one, and does nothing
// otherwise. granted says which; the push step sets the deploy command's
// Relay from it.
func (a AppIdentity) issue(ctx context.Context, app *App) (granted bool, err error) {
	if !a.Granted(app) {
		return false, nil
	}
	return true, a.issuer.Issue(ctx, app)
}

// revoke takes app's identity away. It is called for every app the delete
// saga removes while any tile is granted, granted or not: a tile withdrawn
// from the list in a later release may still have left a socket behind.
func (a AppIdentity) revoke(ctx context.Context, app *App) error {
	if a.issuer == nil {
		return nil
	}
	return a.issuer.Revoke(ctx, app)
}
