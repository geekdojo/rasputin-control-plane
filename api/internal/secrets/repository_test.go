package secrets_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-761-03: each repository method reaches exactly
// rasputin-secrets/apps/<ULID>/<name> or devices/<kind>/<name>; the zero Ref
// makes no store call; the mount is storepolicy.Mount, and the api's policy
// grants both data prefixes.
func TestRepository_PathMapping(t *testing.T) {
	ctx := t.Context()
	for _, tc := range []struct {
		ref  secrets.Ref
		path string
	}{
		{appRef(t, appX, "db-pass"), "apps/" + appX + "/db-pass"},
		{deviceRef(t, "bmc", "node-1"), "devices/bmc/node-1"},
	} {
		fs := &fakeStore{read: func() secretstore.KV {
			return secretstore.KV{Data: map[string]secret.Value{"value": val("v")}, Version: 1}
		}, current: 1}
		repo, err := secrets.NewRepository(fs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Get(ctx, tc.ref); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Write(ctx, tc.ref, val("v"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CurrentVersion(ctx, tc.ref); err != nil {
			t.Fatal(err)
		}
		if err := repo.Delete(ctx, tc.ref); err != nil {
			t.Fatal(err)
		}
		if len(fs.paths) != 4 {
			t.Fatalf("%s: %d store calls, want 4", tc.path, len(fs.paths))
		}
		for i, p := range fs.paths {
			if p.Mount() != storepolicy.Mount || p.Path() != tc.path {
				t.Errorf("%s: call %s reached %s, want %s/%s", tc.path, fs.calls[i], p, storepolicy.Mount, tc.path)
			}
		}
	}

	fs := &fakeStore{}
	repo, err := secrets.NewRepository(fs)
	if err != nil {
		t.Fatal(err)
	}
	var zero secrets.Ref
	_, gErr := repo.Get(ctx, zero)
	_, wErr := repo.Write(ctx, zero, val("v"), 0)
	_, cErr := repo.CurrentVersion(ctx, zero)
	dErr := repo.Delete(ctx, zero)
	for i, err := range []error{gErr, wErr, cErr, dErr} {
		if !errors.Is(err, secrets.ErrInvalidRef) {
			t.Errorf("zero Ref, method %d: err = %v, want ErrInvalidRef", i, err)
		}
	}
	if fs.callCount() != 0 {
		t.Errorf("the zero Ref made %d store calls", fs.callCount())
	}

	policy, err := storepolicy.Text(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{`path "rasputin-secrets/data/apps/*"`, `path "rasputin-secrets/data/devices/*"`} {
		if !bytes.Contains(policy, []byte(grant)) {
			t.Errorf("the api policy has no %s stanza", grant)
		}
	}
}

// TC-761-04: a write stores exactly one "value" key; a read of an entry with
// no value key, or with an extra key, is refused with a zero Secret and every
// value it read destroyed.
func TestRepository_OneValueKey(t *testing.T) {
	ctx := t.Context()
	r := appRef(t, appX, "db-pass")
	fs := &fakeStore{}
	repo, err := secrets.NewRepository(fs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Write(ctx, r, val("v"), 0); err != nil {
		t.Fatal(err)
	}
	if w := fs.written[0]; len(w) != 1 || string(w["value"].Reveal()) != "v" {
		t.Errorf("written map has %d keys, want exactly value", len(w))
	}

	for name, data := range map[string]func() map[string]secret.Value{
		"no value key":   func() map[string]secret.Value { return map[string]secret.Value{"other": val("o")} },
		"an extra key":   func() map[string]secret.Value { return map[string]secret.Value{"value": val("v"), "other": val("o")} },
		"no keys at all": func() map[string]secret.Value { return map[string]secret.Value{} },
	} {
		t.Run(name, func(t *testing.T) {
			var handed map[string]secret.Value
			fs := &fakeStore{read: func() secretstore.KV {
				handed = data()
				return secretstore.KV{Data: handed, Version: 1}
			}}
			repo, err := secrets.NewRepository(fs)
			if err != nil {
				t.Fatal(err)
			}
			s, err := repo.Get(ctx, r)
			if err == nil || !errors.Is(err, secretstore.ErrProtocol) {
				t.Fatalf("Get = %v, want an ErrProtocol refusal", err)
			}
			if s.Version != 0 || s.Value.Len() != 0 {
				t.Errorf("Get returned a non-zero Secret")
			}
			for k, v := range handed {
				if v.Len() != 0 {
					t.Errorf("value %q was not destroyed", k)
				}
			}
		})
	}
}
