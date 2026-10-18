package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// mount is the kv-v2 mount every secret lives in: the one the store's
// self-init creates and the api's fixed policy grants paths under. A unit test
// holds it equal to storepolicy.Mount, which shipped code does not import.
const mount = "rasputin-secrets"

// valueKey is the one key each entry holds.
const valueKey = "value"

// Store is the token-free store the repository calls: the composition root's
// login session (*storesession.Session).
type Store interface {
	Read(ctx context.Context, p secretstore.KVPath, version int) (secretstore.KV, error)
	Write(ctx context.Context, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error)
	Versions(ctx context.Context, p secretstore.KVPath) (secretstore.Metadata, error)
	Delete(ctx context.Context, p secretstore.KVPath) error
}

// Secret is one secret's latest value and its version. The caller destroys
// Value.
type Secret struct {
	Value   secret.Value
	Version int
}

// KVRepository is the model service: it persists one value per Ref and makes
// no business decision.
type KVRepository struct {
	store Store
}

// NewRepository returns a repository over store. It refuses a nil store.
func NewRepository(store Store) (*KVRepository, error) {
	if store == nil {
		return nil, errors.New("secrets: NewRepository: the store is nil")
	}
	return &KVRepository{store: store}, nil
}

// Get returns the latest version of r. An entry of any shape but exactly one
// "value" key is refused as secretstore.ErrProtocol, with what was read
// destroyed.
func (k *KVRepository) Get(ctx context.Context, r Ref) (Secret, error) {
	p, err := kvPath(r)
	if err != nil {
		return Secret{}, err
	}
	kv, err := k.store.Read(ctx, p, 0)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: read %s: %w", r, err)
	}
	v, ok := kv.Data[valueKey]
	if !ok || len(kv.Data) != 1 {
		kv.Destroy()
		return Secret{}, fmt.Errorf("secrets: read %s: the entry holds %d keys, not one %q key: %w",
			r, len(kv.Data), valueKey, secretstore.ErrProtocol)
	}
	return Secret{Value: v, Version: kv.Version}, nil
}

// Write stores value as r's next version under check-and-set cas (0: only if
// r does not exist) and returns the new version.
func (k *KVRepository) Write(ctx context.Context, r Ref, value secret.Value, cas int) (int, error) {
	p, err := kvPath(r)
	if err != nil {
		return 0, err
	}
	v, err := k.store.Write(ctx, p, map[string]secret.Value{valueKey: value}, cas)
	if err != nil {
		return 0, fmt.Errorf("secrets: write %s: %w", r, err)
	}
	return v, nil
}

// CurrentVersion is r's current version, from its metadata.
func (k *KVRepository) CurrentVersion(ctx context.Context, r Ref) (int, error) {
	p, err := kvPath(r)
	if err != nil {
		return 0, err
	}
	md, err := k.store.Versions(ctx, p)
	if err != nil {
		return 0, fmt.Errorf("secrets: versions of %s: %w", r, err)
	}
	return md.CurrentVersion, nil
}

// Delete removes r with every version, by deleting its metadata.
func (k *KVRepository) Delete(ctx context.Context, r Ref) error {
	p, err := kvPath(r)
	if err != nil {
		return err
	}
	if err := k.store.Delete(ctx, p); err != nil {
		return fmt.Errorf("secrets: delete %s: %w", r, err)
	}
	return nil
}

// kvPath is r's path in the mount. Only a parsed Ref reaches it, and
// NewKVPath checks the result again.
func kvPath(r Ref) (secretstore.KVPath, error) {
	if !r.valid() {
		return secretstore.KVPath{}, fmt.Errorf("%w: the zero reference", ErrInvalidRef)
	}
	p, err := secretstore.NewKVPath(mount, r.String())
	if err != nil {
		return secretstore.KVPath{}, fmt.Errorf("%w: %w", ErrInvalidRef, err)
	}
	return p, nil
}
