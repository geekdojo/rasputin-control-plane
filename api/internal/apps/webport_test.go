package apps

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// The store half of a custom app's web port (geekdojo/geekdojo-brain#1089).
// seedCustomApp's app runs customV1 on port 8080.

// TC-1089-14: EditCompose with a port sets it and keeps the old one beside
// the old compose; with 0 it leaves the port alone, and the previous record
// still gets it.
func TestStore_EditComposeWithAWebPort(t *testing.T) {
	ctx := context.Background()
	store, _ := seedCustomApp(t, "a")
	now := time.Now().UTC()

	if err := store.EditCompose(ctx, "a", ComposeHash(customV1), customV2, 9090, now); err != nil {
		t.Fatalf("EditCompose with a port: %v", err)
	}
	got, _ := store.Get(ctx, "a")
	if got.ComposeYAML != customV2 || got.PublishedPort != 9090 || got.PreviousPublishedPort != 8080 {
		t.Errorf("with port 9090: compose=%q port=%d previous port=%d, want customV2, 9090 and 8080",
			got.ComposeYAML, got.PublishedPort, got.PreviousPublishedPort)
	}

	if err := store.EditCompose(ctx, "a", ComposeHash(customV2), customV1, 0, now); err != nil {
		t.Fatalf("EditCompose with no port: %v", err)
	}
	got, _ = store.Get(ctx, "a")
	if got.ComposeYAML != customV1 || got.PublishedPort != 9090 || got.PreviousPublishedPort != 9090 {
		t.Errorf("with port 0: compose=%q port=%d previous port=%d, want customV1 and the port unchanged on both records",
			got.ComposeYAML, got.PublishedPort, got.PreviousPublishedPort)
	}
}

// TC-1089-15: SetCustomWebPort changes the port and updated_at and nothing
// else, and refuses a catalog app, a stale hash and an unknown id, each
// leaving the row as it was.
func TestStore_SetCustomWebPort(t *testing.T) {
	ctx := context.Background()
	store, _ := seedCustomApp(t, "a")
	if err := store.Create(ctx, installedApp("cat")); err != nil {
		t.Fatal(err)
	}
	// A retained previous record, so "left alone" is about real values.
	if err := store.EditCompose(ctx, "a", ComposeHash(customV1), customV2, 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Get(ctx, "a")
	catBefore, _ := store.Get(ctx, "cat")
	later := before.UpdatedAt.Add(time.Minute)

	if err := store.SetCustomWebPort(ctx, "cat", catBefore.ComposeSHA256, 9090, later); !errors.Is(err, ErrEditCatalogApp) {
		t.Errorf("catalog app: want ErrEditCatalogApp, got %v", err)
	}
	if err := store.SetCustomWebPort(ctx, "a", ComposeHash(customV1), 9090, later); !errors.Is(err, ErrComposeChanged) {
		t.Errorf("stale hash: want ErrComposeChanged, got %v", err)
	}
	if err := store.SetCustomWebPort(ctx, "ghost", ComposeHash(customV2), 9090, later); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown id: want sql.ErrNoRows, got %v", err)
	}
	if after, _ := store.Get(ctx, "a"); sameRecord(before, after) != "" || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Errorf("a refused write changed the custom app (%s)", sameRecord(before, after))
	}
	if after, _ := store.Get(ctx, "cat"); sameRecord(catBefore, after) != "" || !after.UpdatedAt.Equal(catBefore.UpdatedAt) {
		t.Errorf("a refused write changed the catalog app (%s)", sameRecord(catBefore, after))
	}

	if err := store.SetCustomWebPort(ctx, "a", before.ComposeSHA256, 9090, later); err != nil {
		t.Fatalf("SetCustomWebPort: %v", err)
	}
	after, _ := store.Get(ctx, "a")
	if after.PublishedPort != 9090 || !after.UpdatedAt.Equal(later.Truncate(time.Millisecond)) {
		t.Errorf("port=%d updated=%v, want 9090 and %v", after.PublishedPort, after.UpdatedAt, later)
	}
	want := *before
	want.PublishedPort = 9090
	if field := sameRecord(&want, after); field != "" {
		t.Errorf("SetCustomWebPort changed %s", field)
	}
	if after.PreviousComposeYAML != customV1 || after.PreviousPublishedPort != 8080 || after.PreviousWebTLS != before.PreviousWebTLS {
		t.Errorf("previous record moved: %+v", after)
	}
}
