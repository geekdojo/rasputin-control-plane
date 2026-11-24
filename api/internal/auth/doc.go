// Package auth is the console's authentication: its sign-in through the
// home sign-in door as an OIDC client (signin.go, geekdojo/geekdojo-brain#989),
// the opaque console sessions that sign-in mints (consolesessions.go), the
// session gate every console route sits behind (RequireSession), the
// back-channel logout route and the role-change sink that end sessions, and
// the pre-update passkey store and first-run ceremony that Identity 4.8
// retires.
//
// See projects/rasputin/design/control-plane/architecture.md §7.7
// in the geekdojo-brain.
package auth
