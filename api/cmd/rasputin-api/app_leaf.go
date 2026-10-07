package main

import (
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// buildAppLeafCmd fills the delivery command from a leaf's certificate —
// shared by every caller of the rotator so the wire shape (FQDNs, upstream
// port) is built in exactly one place. KeyPEM is left empty: the key travels
// beside the command as a secret.Value and apps.deliverLeaf joins them at the
// bus (ADR-0009).
//
// The cert and the route come from different places on purpose. The leaf
// carries BOTH of the app's names whatever its exposure (a cert is an
// identity, not an access control), so the route hosts — and only they —
// decide what the node's proxy will answer for. AppRouteHosts leaves
// LANFQDN empty for a tailnet-only app, and RenderCaddyConfig drops any
// app with no LAN host from the LAN listener.
func buildAppLeafCmd(clusterID string, app *apps.App, certPEM []byte) proto.AppLeafCmd {
	tailnetFQDN, lanFQDN := mesh.AppRouteHosts(clusterID, app.Name, app.ExposeLAN)
	return proto.AppLeafCmd{
		AppID:        app.ID,
		Name:         app.Name,
		CertPEM:      certPEM,
		TailnetFQDN:  tailnetFQDN,
		LANFQDN:      lanFQDN,
		UpstreamPort: app.PublishedPort,
		UpstreamTLS:  app.WebTLS,
	}
}

// newAppLeafRotator is the one disk-backed leaf path. It always returns the
// app's CURRENT desired state — every caller delivers it either way — and
// renewed reports only whether the cert in it is new, which is what decides
// the commit (apps.LeafRotator). The caller owns the returned key and
// destroys it after commit.
func newAppLeafRotator(meshCA *tlsca.MeshCA, appLeafDir, clusterID string) apps.LeafRotator {
	return func(app *apps.App) (apps.Leaf, bool, func() error, error) {
		dir := filepath.Join(appLeafDir, app.ID)
		certPEM, key, renewed, err := mesh.PrepareAppLeaf(meshCA, dir, clusterID, app.Name)
		if err != nil {
			return apps.Leaf{}, false, nil, err
		}
		commit := func() error { return mesh.CommitAppLeaf(dir, certPEM, key) }
		return apps.Leaf{Cmd: buildAppLeafCmd(clusterID, app, certPEM), Key: key}, renewed, commit, nil
	}
}
