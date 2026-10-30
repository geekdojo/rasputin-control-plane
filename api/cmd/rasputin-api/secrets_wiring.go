package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storeswitch"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
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
//
// sw is the store's switch marker (geekdojo/geekdojo-brain#604), which every
// operator write sets first: storeSwitchFor's choice.
func secretsWiring(session *storesession.Session, appsStore *apps.Store, sw secrets.Switch, logger *slog.Logger) (*secrets.Service, error) {
	switch {
	case session == nil:
		return nil, errors.New("secrets: the store session is nil")
	case appsStore == nil:
		return nil, errors.New("secrets: the apps store is nil")
	case sw == nil:
		return nil, errors.New("secrets: the store switch is nil")
	case logger == nil:
		return nil, errors.New("secrets: the logger is nil")
	}
	repo, err := secrets.NewRepository(session)
	if err != nil {
		return nil, err
	}
	return secrets.NewService(secrets.Deps{Repo: repo, Apps: appTargetNodes{store: appsStore}, Switch: sw, Log: logger})
}

// storeSwitchReader is the switch marker as the boot read sees it.
type storeSwitchReader interface {
	Switched(ctx context.Context) (bool, error)
}

// storeSwitchedAtBoot reads the switch marker once, at boot
// (geekdojo/geekdojo-brain#604). An unreadable marker is an error, which main
// treats as FATAL: guessing either answer could put HKDF in front of a
// cluster that holds an owner's credential, or refuse every deploy on one
// that does not.
func storeSwitchedAtBoot(ctx context.Context, marker storeSwitchReader) (bool, error) {
	switched, err := marker.Switched(ctx)
	if err != nil {
		return false, fmt.Errorf("secret store switch marker: %w", err)
	}
	return switched, nil
}

// storeSwitchFor is the switch operator writes set (geekdojo/geekdojo-brain#604):
// the marker when a store backend is requested, and NoStore when none is, so
// an operator write on a box with no store is refused and the marker never
// set (F-604-07).
func storeSwitchFor(requested string, marker *storeswitch.Marker) secrets.Switch {
	if requested == "" {
		return storeswitch.NoStore{}
	}
	return marker
}

// appOperatorSecrets is the apps table's operator-secret declarations as
// appsecret's StoreSource reads them (geekdojo/geekdojo-brain#604): appsecret
// cannot import apps, which imports it.
type appOperatorSecrets struct{ store *apps.Store }

// OperatorSecrets reads the app's row. A missing row is an error: the source
// refuses rather than deriving a name it cannot check.
func (a appOperatorSecrets) OperatorSecrets(ctx context.Context, appID string) ([]tileschema.OperatorSecret, error) {
	app, err := a.store.Get(ctx, appID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("app %s does not exist", appID)
	}
	return app.OperatorSecrets, nil
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

// operatorGated puts the operator-secret gate (geekdojo/geekdojo-brain#780)
// in front of BOTH deploy sources, so the source deploySourceWiring picks in
// either store mode refuses a compose whose owner-supplied secret is unset and
// never derives it. With the store requested, the readiness Gate then wraps
// the gated store source, so its not-ready refusal still comes first. With
// the store off, the secrets service reads through secretstore.Disabled, so
// every presence check fails and an app declaring operator secrets is refused
// rather than handed a derived value.
func operatorGated(storeSource, hkdf apps.SecretSource, appsStore *apps.Store, secretsSvc *secrets.Service, logger *slog.Logger) (gatedStore, gatedHKDF apps.SecretSource, err error) {
	if appsStore == nil {
		return nil, nil, errors.New("operator secrets: the apps store is nil")
	}
	if secretsSvc == nil {
		return nil, nil, errors.New("operator secrets: the secrets service is nil")
	}
	gate := func(next apps.SecretSource) (apps.SecretSource, error) {
		return apps.NewOperatorSecretGate(apps.OperatorSecretGateDeps{Next: next, Apps: appsStore, Secrets: secretsSvc, Log: logger})
	}
	if gatedStore, err = gate(storeSource); err != nil {
		return nil, nil, err
	}
	if gatedHKDF, err = gate(hkdf); err != nil {
		return nil, nil, err
	}
	return gatedStore, gatedHKDF, nil
}
