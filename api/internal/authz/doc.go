// Package authz is the console's authorization rules
// (geekdojo/geekdojo-brain#1000; identity-authz.md §3.2): the one function
// that maps a principal to its capabilities (For), the route-class seam the
// routes and Jobs attach to (Requirement, Set.Permits), the role-change
// guards (RoleGuard), and the Job kind table (KindPolicy,
// geekdojo/geekdojo-brain#1001) the runner decides every submission with.
//
// It imports no internal package; tileschema, which the app rule ranks
// tiers with, is a workspace module of its own. auth imports it, never the
// reverse, so the Job runner can authorize kinds without depending on the
// session package.
//
// It decides and never logs: the caller records the outcome under its own
// correlation id. A designation sentence names a person, so it goes to the
// administrator's response only, never to a log.
//
// The control lock's view, control and self classifier is
// api/internal/auth/controllock.go (isControl, selfPrefix, viewSockets). It
// still decides by method and path, because no route carries a Requirement
// yet. Once every route is annotated (geekdojo/geekdojo-brain#1002),
// isControl becomes "the route's Requirement class is ClassControl", so
// Accounts reads (AccountsRead) are refused under the control lock too, and
// viewSockets and selfPrefix give way to the route annotations.
package authz
