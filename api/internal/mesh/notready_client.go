package mesh

import (
	"context"
	"errors"
)

// ErrMeshNotReady is returned by mesh operations attempted before the
// self-hosted Headscale has finished coming up (container started + admin key
// minted). It's a transient state on a fresh boot, not a hard failure —
// handlers surface it as "mesh initializing" and the next reconcile succeeds
// once bring-up completes.
var ErrMeshNotReady = errors.New("mesh: backend still initializing")

// notReadyClient is the placeholder Client a self-hosted Service serves with
// until Start's background bring-up swaps in the real one. Every op fails
// fast with ErrMeshNotReady so nothing blocks; Backend() reports the target
// backend so the UI shows the intended state rather than "mock".
type notReadyClient struct{ backend string }

// NewNotReadyClient returns a placeholder client reporting the given backend
// name (e.g. "headscale"). Exported so cmd/main can seed a self-hosted
// Service before its real client exists.
func NewNotReadyClient(backend string) Client { return &notReadyClient{backend: backend} }

func (c *notReadyClient) Backend() string { return c.backend }

func (c *notReadyClient) CreatePreAuthKey(context.Context, CreatePreAuthKeyInput) (string, string, error) {
	return "", "", ErrMeshNotReady
}
func (c *notReadyClient) ExpirePreAuthKey(context.Context, string) error { return ErrMeshNotReady }
func (c *notReadyClient) ListPreAuthKeys(context.Context, string) ([]HSPreAuthKey, error) {
	return nil, ErrMeshNotReady
}
func (c *notReadyClient) ListNodes(context.Context) ([]HSNode, error) { return nil, ErrMeshNotReady }
func (c *notReadyClient) SetNodeRoutes(context.Context, string, []string) error {
	return ErrMeshNotReady
}
func (c *notReadyClient) DeleteNode(context.Context, string) error { return ErrMeshNotReady }
func (c *notReadyClient) EnsureUser(context.Context, string) error { return ErrMeshNotReady }
