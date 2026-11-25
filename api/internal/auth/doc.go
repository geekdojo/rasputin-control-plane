// Package auth is the console's authentication: its sign-in through the
// home sign-in door as an OIDC client (signin.go, geekdojo/geekdojo-brain#989),
// the opaque console sessions that sign-in mints (consolesessions.go), the
// session gate every console route sits behind (RequireSession), the
// back-channel logout route and the role-change sink that end sessions, the
// first-run predicate and its claim (geekdojo/geekdojo-brain#990: the
// account created first is designated the first administrator, in its
// session's transaction), and the move's bridge over the pre-update
// passkeys with the pre-update session (geekdojo/geekdojo-brain#1005,
// Identity 5.2: bridge.go, preupdate.go).
//
// See projects/rasputin/design/control-plane/architecture.md §7.7
// in the geekdojo-brain.
package auth
