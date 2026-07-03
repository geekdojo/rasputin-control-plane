// Package api hosts the HTTP handlers and WebSocket upgrades that the UI
// (and any future external client) talks to. Read paths return state;
// write paths create Jobs.
//
// See projects/rasputin/design/control-plane/architecture.md §2
// in the geekdojo-brain.
package api
