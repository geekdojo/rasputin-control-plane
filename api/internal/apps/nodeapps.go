package apps

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// The kinds of NodeSecretsError, for errors.Is.
var (
	// ErrNodeSecretsUnreadable: the recorded secrets of the node's apps
	// could not be read, so nothing was removed.
	ErrNodeSecretsUnreadable = errors.New("apps: the secrets of the node's apps could not be read")
	// ErrNodeSecretsUnavailable: the secret store cannot take the deletes,
	// so nothing was removed.
	ErrNodeSecretsUnavailable = errors.New("apps: the secret store cannot delete the secrets of the node's apps")
	// ErrSecretsLeft: the node's apps were removed, but some of their
	// secrets are still in the store.
	ErrSecretsLeft = errors.New("apps: secrets of removed apps are still in the secret store")
)

// NodeSecretsError is a node removal's secret failure. Sentence is what a
// person reads, names only; Cause, when set, is the internal detail, which
// goes to the log and never to the client. It matches its Kind and its Cause
// with errors.Is.
type NodeSecretsError struct {
	Kind     error
	Sentence string
	Cause    error
}

func (e *NodeSecretsError) Error() string {
	if e.Cause != nil {
		return e.Sentence + " " + e.Cause.Error()
	}
	return e.Sentence
}

func (e *NodeSecretsError) Unwrap() []error {
	if e.Cause != nil {
		return []error{e.Kind, e.Cause}
	}
	return []error{e.Kind}
}

// NodeApps is the business service behind removing a node's apps
// (geekdojo/geekdojo-brain#783, F-783-06): the apps on a removed node go with
// it, and so does every secret they had in the store.
type NodeApps struct {
	store *Store
	d     DeleteSecretsDeps
}

// NewNodeApps refuses a nil store or a DeleteSecretsDeps with a nil field.
func NewNodeApps(store *Store, d DeleteSecretsDeps) (*NodeApps, error) {
	if store == nil {
		return nil, errors.New("apps: NewNodeApps: the apps store is nil")
	}
	if err := d.check("NewNodeApps"); err != nil {
		return nil, err
	}
	return &NodeApps{store: store, d: d}, nil
}

// CheckSecrets is node removal's preflight: it refuses, before anything is
// removed, when the store cannot take the deletes of the node's apps'
// secrets. Once the rows are gone nothing could reach those entries again. It
// writes nothing, and with no names it never reads the store's state.
func (n *NodeApps) CheckSecrets(ctx context.Context, nodeID string) error {
	apps, err := n.store.SecretNamesByTargetNode(ctx, nodeID)
	if err != nil {
		return &NodeSecretsError{Kind: ErrNodeSecretsUnreadable, Cause: err,
			Sentence: "The recorded secrets of the node's apps could not be read, so the node was not removed."}
	}
	var names, refs int
	for _, a := range apps {
		names += len(a.Names)
		refs += a.RecordedRefs
	}
	if names == 0 {
		return nil
	}
	check, state, err := checkStoreForDeletes(ctx, n.d.Store, refs)
	switch check {
	case storeUnconfigured:
		return &NodeSecretsError{Kind: ErrNodeSecretsUnavailable,
			Sentence: fmt.Sprintf("No secret store is configured, so the %d stored %s of the node's apps cannot be deleted; the node was not removed.", refs, plural(refs, "secret", "secrets"))}
	case storeNotReady:
		return &NodeSecretsError{Kind: ErrNodeSecretsUnavailable, Cause: err,
			Sentence: "The secret store " + storestate.Clause(state) + ", so the secrets of the node's apps could not be deleted; the node was not removed. Retry when the store is ready."}
	}
	return nil
}

// Remove deletes the rows of every app on nodeID, and their refs, then every
// secret those apps had in the store, on user's behalf, and returns the
// removed app ids. A database error is returned as it is, and nothing is
// deleted from the store. When only store deletes fail, the ids come back
// with a NodeSecretsError of kind ErrSecretsLeft naming each entry left.
//
// The caller passes a context the request cannot cancel (F-783-22): the rows
// are gone by the time the deletes run, and a delete abandoned halfway would
// leave entries nothing names.
func (n *NodeApps) Remove(ctx context.Context, user, nodeID string) ([]string, error) {
	removed, err := n.store.DeleteByTargetNodeWithSecretNames(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(removed))
	var refs []SecretRef
	for i, a := range removed {
		ids[i] = a.AppID
		refs = append(refs, appRefs(a.AppID, a.Names)...)
	}
	if len(refs) == 0 || !n.d.Store.Configured() {
		// With no store, CheckSecrets refused any recorded reference, so
		// every name was derived on each deploy and never stored (F-783-20).
		return ids, nil
	}
	failedRefs, causes := destroyAppSecrets(ctx, n.d.Secrets, secrets.OperatorActor(user), refs)
	if len(failedRefs) == 0 {
		return ids, nil
	}
	failed := make([]string, len(failedRefs))
	for i, r := range failedRefs {
		failed[i] = r.AppID + "/" + r.Name
	}
	n.d.Log.LogAttrs(ctx, slog.LevelError, "secrets of a removed node's apps not deleted from the secret store",
		slog.String("component", "apps"),
		slog.String("event", "apps.node_secrets_destroy_failed"),
		slog.String("node_id", nodeID),
		slog.String("user", user),
		slog.Any("failed", failed),
		slog.String("err", causeText(failed, causes)))
	return ids, &NodeSecretsError{Kind: ErrSecretsLeft,
		Sentence: fmt.Sprintf("The node was removed, but %d %s of its apps could not be deleted from the secret store and %s still in it: %s.",
			len(failed), plural(len(failed), "secret", "secrets"), plural(len(failed), "is", "are"), strings.Join(failed, ", "))}
}
