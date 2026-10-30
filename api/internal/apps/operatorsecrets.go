package apps

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The operator secret service's own refusals (geekdojo/geekdojo-brain#604).
var (
	// ErrAppNotFound: no app has the ID.
	ErrAppNotFound = errors.New("apps: the app does not exist")
	// ErrOperatorSecretNotDeclared: the app's installed compose declares no
	// operator secret by that name, so the owner may not set it.
	ErrOperatorSecretNotDeclared = errors.New("apps: the app declares no operator secret by that name")
	// ErrOperatorSecretEmpty: the value is empty. An unset optional secret
	// already reaches the app as an empty string; storing one would read as
	// set.
	ErrOperatorSecretEmpty = errors.New("apps: an operator secret value must not be empty")
)

// OperatorSecretStatus is one declared operator secret as the owner sees it:
// never a value.
type OperatorSecretStatus struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Required bool   `json:"required"`
	// Set is whether a value has been stored: the name is recorded in
	// app_secret_refs.
	Set bool `json:"set"`
}

// operatorSecretWriter is the secrets service as OperatorSecrets calls it
// (*secrets.Service): an operator's create-only write and its replace.
type operatorSecretWriter interface {
	Create(ctx context.Context, a secrets.Actor, r secrets.Ref, value secret.Value) (int, error)
	Replace(ctx context.Context, a secrets.Actor, r secrets.Ref, value secret.Value) (int, error)
}

// secretRefStore is the store reference record as OperatorSecrets reads and
// writes it (*Store).
type secretRefStore interface {
	RecordSecretRef(ctx context.Context, appID, name string) error
	ListSecretRefs(ctx context.Context) ([]SecretRef, error)
}

// OperatorSecretsDeps is everything an OperatorSecrets needs.
// NewOperatorSecrets refuses a nil one.
type OperatorSecretsDeps struct {
	// Apps reads the app's row, which carries its declarations.
	Apps appReader
	// Secrets writes the value to the store.
	Secrets operatorSecretWriter
	// Refs records each value stored, and answers which are set.
	Refs secretRefStore
	Log  *slog.Logger
}

// OperatorSecrets is the business service behind the operator secret
// endpoints (geekdojo/geekdojo-brain#604): the owner of an app sets the
// secrets its tile declares they supply, write-only, and reads back only
// whether each is set.
type OperatorSecrets struct {
	apps    appReader
	secrets operatorSecretWriter
	refs    secretRefStore
	log     *slog.Logger
}

// NewOperatorSecrets checks d and returns the service. It does no I/O.
func NewOperatorSecrets(d OperatorSecretsDeps) (*OperatorSecrets, error) {
	switch {
	case d.Apps == nil:
		return nil, errors.New("apps: NewOperatorSecrets: Deps.Apps is nil")
	case d.Secrets == nil:
		return nil, errors.New("apps: NewOperatorSecrets: Deps.Secrets is nil")
	case d.Refs == nil:
		return nil, errors.New("apps: NewOperatorSecrets: Deps.Refs is nil")
	case d.Log == nil:
		return nil, errors.New("apps: NewOperatorSecrets: Deps.Log is nil")
	}
	return &OperatorSecrets{apps: d.Apps, secrets: d.Secrets, refs: d.Refs, log: d.Log}, nil
}

// Status lists the app's declared operator secrets in declaration order, each
// with whether it is set. It makes no store call: set is read from the
// reference record. An absent app is ErrAppNotFound.
func (o *OperatorSecrets) Status(ctx context.Context, appID string) ([]OperatorSecretStatus, error) {
	app, err := o.app(ctx, appID)
	if err != nil {
		return nil, err
	}
	refs, err := o.refs.ListSecretRefs(ctx)
	if err != nil {
		return nil, fmt.Errorf("apps: operator secrets of %s: %w", appID, err)
	}
	set := map[string]bool{}
	for _, r := range refs {
		if r.AppID == appID {
			set[r.Name] = true
		}
	}
	out := make([]OperatorSecretStatus, 0, len(app.OperatorSecrets))
	for _, d := range app.OperatorSecrets {
		out = append(out, OperatorSecretStatus{Name: d.Name, Label: d.Label, Required: d.IsRequired(), Set: set[d.Name]})
	}
	return out, nil
}

// Set stores value as app appID's operator secret name, on behalf of user.
// The name must be one the app's installed compose declares. An unset name
// is created; a set one is replaced. The reference is recorded after the
// entry is written (S15 write order). The caller still owns value and
// destroys it.
//
// Refusals: an empty value (ErrOperatorSecretEmpty), an absent app
// (ErrAppNotFound), an undeclared name (ErrOperatorSecretNotDeclared), each
// before any write; the secrets service's own errors (ErrConflict, the
// switch marker's ErrSwitch, a store failure, an invalid value) are returned
// as they are, with no reference recorded.
func (o *OperatorSecrets) Set(ctx context.Context, user, appID, name string, value secret.Value) error {
	if value.Len() == 0 {
		return ErrOperatorSecretEmpty
	}
	app, err := o.app(ctx, appID)
	if err != nil {
		return err
	}
	if _, ok := tileschema.OperatorSecretByName(app.OperatorSecrets, name); !ok {
		return fmt.Errorf("%w: %s", ErrOperatorSecretNotDeclared, name)
	}
	ref, err := secrets.AppSecret(appID, name)
	if err != nil {
		return fmt.Errorf("apps: operator secret %s of %s: %w", name, appID, err)
	}
	actor := secrets.OperatorActor(user)
	_, err = o.secrets.Create(ctx, actor, ref, value)
	if errors.Is(err, secrets.ErrExists) {
		_, err = o.secrets.Replace(ctx, actor, ref, value)
	}
	if err != nil {
		return err
	}
	if err := o.refs.RecordSecretRef(ctx, appID, name); err != nil {
		// The value is stored; only its record is missing, so the owner sees
		// it as unset and a later reference check cannot see it. Setting it
		// again records it.
		o.log.LogAttrs(ctx, slog.LevelWarn, "operator secret stored but not recorded",
			slog.String("component", "apps"),
			slog.String("event", "apps.operator_secret_ref_failed"),
			slog.String("app_id", appID),
			slog.String("ref", ref.String()),
			slog.String("err", err.Error()))
		return fmt.Errorf("apps: recording %s: %w", ref, err)
	}
	return nil
}

// app reads appID's row; an absent one is ErrAppNotFound.
func (o *OperatorSecrets) app(ctx context.Context, appID string) (*App, error) {
	app, err := o.apps.Get(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("apps: reading app %s: %w", appID, err)
	}
	if app == nil {
		return nil, fmt.Errorf("%w: %s", ErrAppNotFound, appID)
	}
	return app, nil
}
