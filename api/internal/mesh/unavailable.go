package mesh

import (
	"context"
	"errors"
	"fmt"
)

// ErrMeshUnavailable is returned by every UnavailableClient method. Sentinel so
// callers can tell "the mesh backend is not configured on this installation"
// apart from "Headscale is configured and returned an error", which are two
// different problems with two different fixes.
var ErrMeshUnavailable = errors.New("mesh backend unavailable")

// UnavailableClient is the mesh Client used when no REAL backend could be
// resolved and the operator did not ask for the mock.
//
// WHY THIS EXISTS rather than falling through to MockClient, which is what the
// `auto` path used to do when it found no Docker and no external Headscale.
//
// MockClient is not an inert stub. It mints keys, accepts nodes, and the enroll
// saga alongside it invents a tailnet address for each one — a djb2 hash of the
// node id projected into 100.64.0.0/24 (see the MockClient branch in jobs.go).
// Those addresses are syntactically indistinguishable from real Tailscale
// addresses, they are written into the mesh store, and /api/mesh/devices serves
// them. So the control plane reports a mesh that does not exist, on hardware,
// with no error anywhere — the same shape as the 2026-09-01 storage incident,
// where a missing tool turned into three fixture disks offered for a
// destructive format (agent/internal/configfault has the full write-up).
//
// The api must still boot and serve /healthz — a control plane gated on its own
// mesh coming up is fragile, and an unreachable control plane cannot be used to
// fix anything. So this client is the honest middle: the api comes up, every
// other subsystem works, and mesh operations fail with a reason that names the
// missing prerequisite instead of succeeding with fiction.
//
// The mock remains available for dev and CI — by name, RASPUTIN_MESH_BACKEND=mock.
type UnavailableClient struct {
	// Reason names what is missing, in the operator's terms. Carried into
	// every error so the fix does not require reading this file.
	Reason string
}

// NewUnavailableClient builds the client with the reason mesh could not be
// wired.
func NewUnavailableClient(reason string) *UnavailableClient {
	return &UnavailableClient{Reason: reason}
}

// Backend reports "unavailable" — deliberately NOT "mock". Anything that
// branches on the backend name (the UI's mesh banner, change events) must be
// able to tell a dev fixture from a control plane that cannot do mesh at all.
func (u *UnavailableClient) Backend() string { return "unavailable" }

func (u *UnavailableClient) err(op string) error {
	return fmt.Errorf("%s: %w — %s; set RASPUTIN_HEADSCALE_URL + RASPUTIN_HEADSCALE_API_KEY "+
		"for an external Headscale, install the docker CLI for the self-hosted one, or set "+
		"RASPUTIN_MESH_BACKEND=mock if this is a dev box", op, ErrMeshUnavailable, u.Reason)
}

func (u *UnavailableClient) CreatePreAuthKey(context.Context, CreatePreAuthKeyInput) (string, string, error) {
	return "", "", u.err("create pre-auth key")
}

func (u *UnavailableClient) ExpirePreAuthKey(context.Context, string) error {
	return u.err("expire pre-auth key")
}

func (u *UnavailableClient) ListPreAuthKeys(context.Context, string) ([]HSPreAuthKey, error) {
	return nil, u.err("list pre-auth keys")
}

func (u *UnavailableClient) ListNodes(context.Context) ([]HSNode, error) {
	return nil, u.err("list nodes")
}

func (u *UnavailableClient) SetNodeRoutes(context.Context, string, []string) error {
	return u.err("set node routes")
}

func (u *UnavailableClient) DeleteNode(context.Context, string) error {
	return u.err("delete node")
}

func (u *UnavailableClient) EnsureUser(context.Context, string) error {
	return u.err("ensure user")
}
