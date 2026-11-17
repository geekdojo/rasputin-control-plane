package apprelay

import (
	"context"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Grants answers whether an app is granted a runtime identity.
// apps.AppIdentity satisfies it.
type Grants interface {
	Granted(app *apps.App) bool
}

// AppLookup reads an app's row. *apps.Store satisfies it.
type AppLookup interface {
	Get(ctx context.Context, id string) (*apps.App, error)
}

// RuntimeIndex is the deletion index of an app's runtime entries.
// *apps.Store satisfies it.
type RuntimeIndex interface {
	RecordRuntimeSecret(ctx context.Context, appID, name string) error
	ForgetRuntimeSecret(ctx context.Context, appID, name string) error
	// The index of the app's Transit keys (geekdojo/geekdojo-brain#1084).
	RecordTransitKey(ctx context.Context, appID, name string) error
	ForgetTransitKey(ctx context.Context, appID, name string) error
	HasTransitKey(ctx context.Context, appID, name string) (bool, error)
}

// RuntimeSecrets is what the service needs of the secrets service.
// *secrets.Service satisfies it.
type RuntimeSecrets interface {
	Read(ctx context.Context, a secrets.Actor, r secrets.Ref) (secrets.Secret, error)
	Create(ctx context.Context, a secrets.Actor, r secrets.Ref, value secret.Value) (int, error)
	Replace(ctx context.Context, a secrets.Actor, r secrets.Ref, value secret.Value) (int, error)
	Delete(ctx context.Context, a secrets.Actor, r secrets.Ref) error
	// The app's Transit keys (geekdojo/geekdojo-brain#1084).
	CreateKey(ctx context.Context, a secrets.Actor, r secrets.Ref) error
	Encrypt(ctx context.Context, a secrets.Actor, r secrets.Ref, plaintext secret.Value) (secret.Value, error)
	Decrypt(ctx context.Context, a secrets.Actor, r secrets.Ref, ciphertext secret.Value) (secret.Value, error)
	DestroyKey(ctx context.Context, a secrets.Actor, r secrets.Ref) error
}

// The service's own refusals, before the secrets service is called.
var (
	// ErrNoApp: no app has the id the call names.
	ErrNoApp = errors.New("apprelay: no such app")
	// ErrNotGranted: the app exists but is not granted a runtime identity.
	ErrNotGranted = errors.New("apprelay: the app is not granted a runtime identity")
	// ErrWrongNode: the call came from a node the app is not deployed to.
	ErrWrongNode = errors.New("apprelay: the call came from a node the app is not deployed to")
	// ErrNoKey: an encrypt or decrypt names a key the app's index does not
	// record, so the store was not called (F-1084-02).
	ErrNoKey = errors.New("apprelay: the app has no key by that name")
)

// Call is one parsed call: the node the broker authenticated, the app the
// agent stamped, the operation, and the entry, already a valid runtime
// reference, or for a key op the app key's reference. Value is set on create
// and replace, and on encrypt (the plaintext, base64) and decrypt (the
// ciphertext); the caller owns it.
type Call struct {
	Node  string
	AppID string
	Op    string
	Ref   secrets.Ref
	Name  string
	Value secret.Value
}

// ServiceDeps is everything a Service needs.
type ServiceDeps struct {
	Apps    AppLookup
	Grants  Grants
	Index   RuntimeIndex
	Secrets RuntimeSecrets
}

// Service is the business layer for an app's calls on its relay socket.
type Service struct {
	d ServiceDeps
}

// NewService refuses a ServiceDeps with a nil field.
func NewService(d ServiceDeps) (*Service, error) {
	switch {
	case d.Apps == nil:
		return nil, errors.New("apprelay: NewService: ServiceDeps.Apps is nil")
	case d.Grants == nil:
		return nil, errors.New("apprelay: NewService: ServiceDeps.Grants is nil")
	case d.Index == nil:
		return nil, errors.New("apprelay: NewService: ServiceDeps.Index is nil")
	case d.Secrets == nil:
		return nil, errors.New("apprelay: NewService: ServiceDeps.Secrets is nil")
	}
	return &Service{d: d}, nil
}

// Do performs c as its app, and returns the value on a read; the caller owns
// and destroys it. An app that does not exist, is not granted, or is not on
// the calling node is refused before any index or store call. The secrets service authorizes the rest:
// the app's own runtime entries, from the node it is deployed to.
//
// Create records the index row before the store create, and delete forgets
// it after the store delete (apps.RecordRuntimeSecret has why). A failed
// store call leaves the row. A key's create and destroy keep the same order
// in the key index, and its encrypt and decrypt check the row first.
func (s *Service) Do(ctx context.Context, c Call) (secret.Value, error) {
	app, err := s.d.Apps.Get(ctx, c.AppID)
	if err != nil {
		return secret.Value{}, fmt.Errorf("apprelay: look up app %s: %w", c.AppID, err)
	}
	if app == nil {
		return secret.Value{}, fmt.Errorf("%w: %s", ErrNoApp, c.AppID)
	}
	if !s.d.Grants.Granted(app) {
		return secret.Value{}, fmt.Errorf("%w: %s", ErrNotGranted, c.AppID)
	}
	// The secrets service checks the node too. Checking it here as well keeps
	// a call another node forged from writing an index row before it is
	// refused.
	if app.TargetNode != c.Node {
		return secret.Value{}, fmt.Errorf("%w: %s is on %s, the call came from %s", ErrWrongNode, c.AppID, app.TargetNode, c.Node)
	}
	actor := secrets.RuntimeActor(c.AppID, c.Node)
	switch c.Op {
	case proto.AppSecretRead:
		got, err := s.d.Secrets.Read(ctx, actor, c.Ref)
		if err != nil {
			return secret.Value{}, err
		}
		return got.Value, nil
	case proto.AppSecretCreate:
		if err := s.d.Index.RecordRuntimeSecret(ctx, c.AppID, c.Name); err != nil {
			return secret.Value{}, err
		}
		_, err := s.d.Secrets.Create(ctx, actor, c.Ref, c.Value)
		return secret.Value{}, err
	case proto.AppSecretReplace:
		_, err := s.d.Secrets.Replace(ctx, actor, c.Ref, c.Value)
		return secret.Value{}, err
	case proto.AppSecretDelete:
		if err := s.d.Secrets.Delete(ctx, actor, c.Ref); err != nil {
			return secret.Value{}, err
		}
		return secret.Value{}, s.d.Index.ForgetRuntimeSecret(ctx, c.AppID, c.Name)
	case proto.AppKeyCreate:
		if err := s.d.Index.RecordTransitKey(ctx, c.AppID, c.Name); err != nil {
			return secret.Value{}, err
		}
		return secret.Value{}, s.d.Secrets.CreateKey(ctx, actor, c.Ref)
	case proto.AppKeyEncrypt, proto.AppKeyDecrypt:
		if err := s.hasKey(ctx, c); err != nil {
			return secret.Value{}, err
		}
		if c.Op == proto.AppKeyEncrypt {
			return s.d.Secrets.Encrypt(ctx, actor, c.Ref, c.Value)
		}
		return s.d.Secrets.Decrypt(ctx, actor, c.Ref, c.Value)
	case proto.AppKeyDestroy:
		if err := s.d.Secrets.DestroyKey(ctx, actor, c.Ref); err != nil {
			return secret.Value{}, err
		}
		return secret.Value{}, s.d.Index.ForgetTransitKey(ctx, c.AppID, c.Name)
	}
	return secret.Value{}, fmt.Errorf("%w: unknown operation %q", secrets.ErrInvalidRef, c.Op)
}

// hasKey refuses an encrypt or decrypt under a key the app's index does not
// record with ErrNoKey, before any store call (F-1084-02): the store would
// answer 403, which reads as a refused token and costs a re-login.
func (s *Service) hasKey(ctx context.Context, c Call) error {
	ok, err := s.d.Index.HasTransitKey(ctx, c.AppID, c.Name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoKey, c.Name)
	}
	return nil
}
