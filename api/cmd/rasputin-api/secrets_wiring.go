package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
)

// appTargetNodes is the secrets service's view of the apps table: each app's
// target node, and whether the app exists. It lives here rather than in apps
// because apps will consume the secrets service (#762), and secrets importing
// apps would make a cycle.
type appTargetNodes struct{ store *apps.Store }

// TargetNode reads the app's row. A missing row is found=false, not an error.
func (a appTargetNodes) TargetNode(ctx context.Context, appID string) (string, bool, error) {
	app, err := a.store.Get(ctx, appID)
	if err != nil {
		return "", false, err
	}
	if app == nil {
		return "", false, nil
	}
	return app.TargetNode, true, nil
}

// secretsWiring builds the secrets service (geekdojo/geekdojo-brain#761) over
// the api's store session: the KV repository, and the service that authorizes
// every call against the apps table. It makes no store call.
func secretsWiring(session *storesession.Session, appsStore *apps.Store, logger *slog.Logger) (*secrets.Service, error) {
	switch {
	case session == nil:
		return nil, errors.New("secrets: the store session is nil")
	case appsStore == nil:
		return nil, errors.New("secrets: the apps store is nil")
	case logger == nil:
		return nil, errors.New("secrets: the logger is nil")
	}
	repo, err := secrets.NewRepository(session)
	if err != nil {
		return nil, err
	}
	return secrets.NewService(secrets.Deps{Repo: repo, Apps: appTargetNodes{store: appsStore}, Log: logger})
}

// appSecretRefs is the store reference record as appsecret sees it: apps
// records and lists them, and appsecret cannot import apps, which imports it
// (geekdojo/geekdojo-brain#800).
type appSecretRefs struct{ store *apps.Store }

// RecordSecretRef records app appID's secret name.
func (a appSecretRefs) RecordSecretRef(ctx context.Context, appID, name string) error {
	return a.store.RecordSecretRef(ctx, appID, name)
}

// ListSecretRefs lists every recorded reference.
func (a appSecretRefs) ListSecretRefs(ctx context.Context) ([]appsecret.SecretRef, error) {
	rows, err := a.store.ListSecretRefs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]appsecret.SecretRef, 0, len(rows))
	for _, r := range rows {
		out = append(out, appsecret.SecretRef{AppID: r.AppID, Name: r.Name})
	}
	return out, nil
}
