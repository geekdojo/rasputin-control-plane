package secretstore_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// kvStore is what the contract table drives: the Client and the Mock both
// satisfy it.
type kvStore interface {
	Read(ctx context.Context, token secret.Value, p secretstore.KVPath, version int) (secretstore.KV, error)
	Write(ctx context.Context, token secret.Value, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error)
	Versions(ctx context.Context, token secret.Value, p secretstore.KVPath) (secretstore.Metadata, error)
}

// contractTable is TC-758-11's table, run against the Mock here and against
// the real store in TC-758-27. p must not exist yet and missing must never be
// written. When wantTime is not zero, every version must be dated with it.
func contractTable(t *testing.T, s kvStore, token secret.Value, p, missing secretstore.KVPath, wantTime time.Time) {
	t.Helper()
	ctx := t.Context()
	one := map[string]secret.Value{"user": tok("alice"), "pass": tok("first-pass")}
	two := map[string]secret.Value{"user": tok("alice"), "pass": tok("second-pass")}

	if v, err := s.Write(ctx, token, p, one, 0); err != nil || v != 1 {
		t.Fatalf("write cas 0 to a new path = %d, %v; want version 1", v, err)
	}
	if _, err := s.Write(ctx, token, p, two, 0); !errors.Is(err, secretstore.ErrCASMismatch) {
		t.Fatalf("write cas 0 to an existing path: err = %v, want ErrCASMismatch", err)
	}
	if v, err := s.Write(ctx, token, p, two, 1); err != nil || v != 2 {
		t.Fatalf("write cas 1 = %d, %v; want version 2", v, err)
	}
	if _, err := s.Write(ctx, token, p, one, 1); !errors.Is(err, secretstore.ErrCASMismatch) {
		t.Fatalf("write cas 1 again: err = %v, want ErrCASMismatch", err)
	}
	latest, err := s.Read(ctx, token, p, 0)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	assertKV(t, "latest", latest, 2, "second-pass", wantTime)
	first, err := s.Read(ctx, token, p, 1)
	if err != nil {
		t.Fatalf("read version 1: %v", err)
	}
	assertKV(t, "version 1", first, 1, "first-pass", wantTime)
	md, err := s.Versions(ctx, token, p)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if _, ok1 := md.Versions[1]; !ok1 || md.CurrentVersion != 2 || len(md.Versions) != 2 {
		t.Errorf("metadata current_version %d with versions %v, want 2 with versions 1 and 2", md.CurrentVersion, slices.Sorted(maps.Keys(md.Versions)))
	} else if _, ok2 := md.Versions[2]; !ok2 {
		t.Errorf("metadata versions %v, want versions 1 and 2", slices.Sorted(maps.Keys(md.Versions)))
	}
	for n, vm := range md.Versions {
		if !wantTime.IsZero() && !vm.CreatedTime.Equal(wantTime) {
			t.Errorf("version %d created %v, want %v", n, vm.CreatedTime, wantTime)
		}
		if vm.CreatedTime.IsZero() || !vm.DeletionTime.IsZero() || vm.Destroyed {
			t.Errorf("version %d metadata = %+v, want created, not deleted or destroyed", n, vm)
		}
	}
	if !wantTime.IsZero() && (!md.CreatedTime.Equal(wantTime) || !md.UpdatedTime.Equal(wantTime)) {
		t.Errorf("metadata created %v updated %v, want %v", md.CreatedTime, md.UpdatedTime, wantTime)
	}
	if _, err := s.Read(ctx, token, missing, 0); !errors.Is(err, secretstore.ErrNotFound) {
		t.Errorf("read of a missing path: err = %v, want ErrNotFound", err)
	}
	if _, err := s.Read(ctx, token, p, 9); !errors.Is(err, secretstore.ErrNotFound) {
		t.Errorf("read of a version never written: err = %v, want ErrNotFound", err)
	}
}

func assertKV(t *testing.T, what string, kv secretstore.KV, version int, pass string, wantTime time.Time) {
	t.Helper()
	if kv.Version != version || len(kv.Data) != 2 ||
		string(kv.Data["user"].Reveal()) != "alice" || string(kv.Data["pass"].Reveal()) != pass {
		t.Errorf("%s = version %d with %d keys, want version %d holding the written data", what, kv.Version, len(kv.Data), version)
	}
	if kv.CreatedTime.IsZero() || (!wantTime.IsZero() && !kv.CreatedTime.Equal(wantTime)) {
		t.Errorf("%s created %v, want %v", what, kv.CreatedTime, wantTime)
	}
}

// TC-758-11: the contract table against Mock, and the Mock's copy-in,
// copy-out ownership.
func TestMock_Contract(t *testing.T) {
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	m := secretstore.NewMock(func() time.Time { return at })
	contractTable(t, m, secret.Value{}, kvPath(t, "kv", "contract/a"), kvPath(t, "kv", "contract/missing"), at)

	if h, err := m.Health(t.Context()); err != nil || !h.Initialized || h.Sealed {
		t.Errorf("mock Health = %+v, %v", h, err)
	}

	p := kvPath(t, "kv", "ownership")
	in := tok("original")
	if _, err := m.Write(t.Context(), secret.Value{}, p, map[string]secret.Value{"k": in}, 0); err != nil {
		t.Fatal(err)
	}
	in.Destroy()
	out, err := m.Read(t.Context(), secret.Value{}, p, 0)
	if err != nil || string(out.Data["k"].Reveal()) != "original" {
		t.Fatalf("after destroying the written value, read = %v, %v; want the original", out, err)
	}
	out.Destroy()
	again, err := m.Read(t.Context(), secret.Value{}, p, 0)
	if err != nil || string(again.Data["k"].Reveal()) != "original" {
		t.Fatalf("after destroying a read value, read = %v, %v; want the original", again, err)
	}

	for name, err := range map[string]error{
		"versions of a missing path": func() error { _, err := m.Versions(t.Context(), secret.Value{}, kvPath(t, "kv", "none")); return err }(),
		"an RFC 3339 value": func() error {
			_, err := m.Write(t.Context(), secret.Value{}, kvPath(t, "kv", "x"), map[string]secret.Value{"k": tok("2026-10-11T09:00:00Z")}, 0)
			return err
		}(),
	} {
		var se *secretstore.Error
		if err == nil || !errors.As(err, &se) {
			t.Errorf("%s: err = %v, want an *Error", name, err)
		}
	}
}
