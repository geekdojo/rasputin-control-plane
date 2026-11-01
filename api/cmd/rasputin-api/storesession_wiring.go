package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// storeAPIRole is the store cert role the api logs in as: the role
// rasputin-os's self-init creates, which admits only the api's client leaf
// CommonName (storeClientCN) and grants the rasputin-api policy
// (geekdojo/geekdojo-brain#804, #759).
const storeAPIRole = "rasputin-api"

// noAuditObserver is the login observer when no store backend is requested.
// There is no readiness monitor then, the store is Disabled and its login
// makes no call, so there is no alert to raise or clear.
type noAuditObserver struct{}

func (noAuditObserver) ObserveAudited(context.Context, error) {}

// storeSessionWiring builds the api's login session at the store
// (geekdojo/geekdojo-brain#759): login is storeWiring.login, store is the
// observed store every consumer uses, and observer, when a backend is
// requested, is told each login's outcome (readinessWiring.observer: the
// monitor and the store-health counter, #939). A nil observer (nothing
// requested) becomes noAuditObserver here, explicitly.
//
// It makes no store call: the first call that needs a token logs in.
func storeSessionWiring(login storesession.Login, store storesession.Store, observer storestate.Observer, logger *slog.Logger) (*storesession.Session, error) {
	switch {
	case login == nil:
		return nil, errors.New("store session: the login is nil")
	case store == nil:
		return nil, errors.New("store session: the store is nil")
	case logger == nil:
		return nil, errors.New("store session: the logger is nil")
	}
	var obs storesession.Observer = noAuditObserver{}
	if observer != nil {
		obs = observer
	}
	return storesession.New(storesession.Config{
		Role: storeAPIRole, Login: login, Store: store, Observer: obs, Log: logger,
	})
}
