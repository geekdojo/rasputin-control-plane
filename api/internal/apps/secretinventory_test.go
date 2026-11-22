package apps

import (
	"context"
	"reflect"
	"testing"
)

// TC-1132-14: SecretInventory reads every app in one pass. An app with
// references only; one in the v2026.10.2 shape (no references, tokens in
// both composes); and one whose operator-secret declarations name entries no
// token and no reference names, with runtime rows. Each app's Names is the
// sorted union of references, both composes' tokens and both declaration
// columns; RuntimeNames is its runtime rows. A declaration column that does
// not decode, and a closed database, each return an error and no list.
func TestSecretInventory(t *testing.T) {
	ctx := context.Background()
	const refsOnly, oldShape, declared = "01J8Z3K5QW6X7Y8Z9A0B1C2D3A", "01J8Z3K5QW6X7Y8Z9A0B1C2D3B", "01J8Z3K5QW6X7Y8Z9A0B1C2D3C"
	store := newStore(t)
	for i, id := range []string{refsOnly, oldShape, declared} {
		if err := store.Create(ctx, makeApp(id, []string{"a", "b", "c"}[i])); err != nil {
			t.Fatal(err)
		}
	}
	withSecrets(t, store, refsOnly, "services: {}", "", "z-ref", "a-ref")
	withSecrets(t, store, oldShape, composeNaming("db-pass", "shared"), composeNaming("old-key", "shared"))
	withSecrets(t, store, declared, composeNaming("tok"), "", "tok")
	if _, err := store.db.ExecContext(ctx, `UPDATE apps SET operator_secrets = ?, previous_operator_secrets = ? WHERE id = ?`,
		`[{"name":"smtp-pass"}]`, `[{"name":"api-key"},{"name":"tok"}]`, declared); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"session", "cache"} {
		if err := store.RecordRuntimeSecret(ctx, declared, n); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.SecretInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []AppSecretInventory{
		{AppID: refsOnly, Names: []string{"a-ref", "z-ref"}},
		{AppID: oldShape, Names: []string{"db-pass", "old-key", "shared"}},
		{AppID: declared, Names: []string{"api-key", "smtp-pass", "tok"}, RuntimeNames: []string{"cache", "session"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SecretInventory =\n%+v\nwant\n%+v", got, want)
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE apps SET operator_secrets = ? WHERE id = ?`, `{not json`, declared); err != nil {
		t.Fatal(err)
	}
	if got, err := store.SecretInventory(ctx); err == nil || got != nil {
		t.Fatalf("an undecodable declaration column: (%v, %v), want an error and no list", got, err)
	}

	_ = store.Close()
	if got, err := store.SecretInventory(ctx); err == nil || got != nil {
		t.Fatalf("a closed database: (%v, %v), want an error and no list", got, err)
	}
}
