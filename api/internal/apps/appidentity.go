package apps

import "context"

// AppIdentityIssuer gives an app its own identity at the secrets store
// (geekdojo/geekdojo-brain#1078). The deploy family calls it from the push
// step, before the deploy command is built, for an app that has been granted
// one. geekdojo/geekdojo-brain#1081 implements it: under the 2026-11-15 ruling
// on #1079 an app reaches the store through a per-app relay socket on its
// agent, never the store itself, and #1081 widens this method with whatever
// the relay needs delivered alongside the deploy.
type AppIdentityIssuer interface {
	Issue(ctx context.Context, app *App) error
}

// AppIdentity is the switch that keeps app identities off until an app is
// granted one (geekdojo/geekdojo-brain#1080). Its zero value is the switch
// off: no tile is granted and no issuer is called, so every deploy goes out
// exactly as it did before the switch existed.
//
// A grant is by catalog tile, read from the app row's SourceTile. A custom
// app has no source tile, so it can never be granted.
//
// The fields are unexported and there is no constructor yet: nothing outside
// this package can grant a tile, so a grant without an issuer to honour it
// cannot be wired. #1081 adds the constructor along with the issuer.
type AppIdentity struct {
	tiles  map[string]bool
	issuer AppIdentityIssuer
}

// granted reports whether app is granted an identity.
func (a AppIdentity) granted(app *App) bool {
	return app.SourceTile != "" && a.tiles[app.SourceTile]
}

// issue issues app its identity if it is granted one, and does nothing
// otherwise.
func (a AppIdentity) issue(ctx context.Context, app *App) error {
	if !a.granted(app) {
		return nil
	}
	return a.issuer.Issue(ctx, app)
}
