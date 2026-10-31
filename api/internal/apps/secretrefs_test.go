package apps

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

// geekdojo/geekdojo-brain#800 (F-800-01): a recorded reference is listed
// once however often it is recorded, survives a reopen (the schema runs on
// every open), and goes with its app: deleting the app, directly or by
// target node, removes its rows. A reference to an app that does not exist
// is refused by the foreign key.
func TestSecretRefs_RecordListCascade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apps.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{testAppID, otherAppID} {
		if err := s.Create(ctx, makeApp(id, "app-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []SecretRef{{otherAppID, "token"}, {testAppID, "db-pass"}, {testAppID, "db-pass"}, {testAppID, "api-key"}} {
		if err := s.RecordSecretRef(ctx, r.AppID, r.Name); err != nil {
			t.Fatalf("RecordSecretRef(%v) = %v", r, err)
		}
	}
	want := []SecretRef{{testAppID, "api-key"}, {testAppID, "db-pass"}, {otherAppID, "token"}}
	if got, err := s.ListSecretRefs(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListSecretRefs = (%v, %v), want %v", got, err, want)
	}
	if err := s.RecordSecretRef(ctx, "01J8Z3K5QW6X7Y8Z9A0B1C2D3Z", "x"); err == nil {
		t.Error("a reference to an app that does not exist was recorded")
	}
	_ = s.Close()

	s, err = OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got, err := s.ListSecretRefs(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after a reopen ListSecretRefs = (%v, %v), want %v", got, err, want)
	}
	if err := s.Delete(ctx, testAppID); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ListSecretRefs(ctx); err != nil || !reflect.DeepEqual(got, []SecretRef{{otherAppID, "token"}}) {
		t.Fatalf("after deleting the app ListSecretRefs = (%v, %v)", got, err)
	}
	other, err := s.Get(ctx, otherAppID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteByTargetNodeWithSecretNames(ctx, other.TargetNode); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ListSecretRefs(ctx); err != nil || len(got) != 0 {
		t.Fatalf("after deleting by target node ListSecretRefs = (%v, %v), want none", got, err)
	}
}

// A closed database fails both calls with an error, never an empty answer.
func TestSecretRefs_Errors(t *testing.T) {
	s := newStore(t)
	_ = s.Close()
	if err := s.RecordSecretRef(context.Background(), testAppID, "db-pass"); err == nil {
		t.Error("RecordSecretRef on a closed database = nil")
	}
	if got, err := s.ListSecretRefs(context.Background()); err == nil {
		t.Errorf("ListSecretRefs on a closed database = (%v, nil)", got)
	}
}
