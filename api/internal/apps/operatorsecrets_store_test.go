package apps

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

const opStoreAppID = "01J9ZK3Q0M8X7Y6W5V4T3S2R2Q"

var (
	opV1Decls = []tileschema.OperatorSecret{{Name: "feed-key", Label: "Feed API key"}, {Name: "map-key", Label: "Map token"}}
	opV2Decls = []tileschema.OperatorSecret{{Name: "radar-key", Label: "Radar key"}}
)

func createOperatorApp(t *testing.T, s *Store, decls []tileschema.OperatorSecret) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.Create(context.Background(), &App{
		ID: opStoreAppID, Name: "feeds", ComposeYAML: "services: {v1: {}}\n", TargetNode: "n", SourceTile: "feeds",
		OperatorSecrets: decls, LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func readBoth(t *testing.T, s *Store) (*App, *App) {
	t.Helper()
	got, err := s.Get(context.Background(), opStoreAppID)
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %v", got, err)
	}
	list, err := s.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v, %v", list, err)
	}
	return got, list[0]
}

// TC-780-08: Create and Get/List round-trip the declarations; UpgradeCompose,
// fed by UpgradeTarget.ComposeUpgrade, replaces them.
func TestOperatorSecretsRoundTripAndUpgrade(t *testing.T) {
	s := newStore(t)
	createOperatorApp(t, s, opV1Decls)
	got, listed := readBoth(t, s)
	if !reflect.DeepEqual(got.OperatorSecrets, opV1Decls) || !reflect.DeepEqual(listed.OperatorSecrets, opV1Decls) {
		t.Fatalf("read back %+v / %+v, want %+v", got.OperatorSecrets, listed.OperatorSecrets, opV1Decls)
	}

	target := UpgradeTarget{CatalogVersion: 7, Tile: tileschema.Tile{
		ComposeYAML: "services: {v2: {}}\n", OperatorSecrets: opV2Decls,
	}}
	if err := s.UpgradeCompose(context.Background(), opStoreAppID, got.ComposeSHA256, target.ComposeUpgrade(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, listed = readBoth(t, s)
	if !reflect.DeepEqual(got.OperatorSecrets, opV2Decls) || !reflect.DeepEqual(listed.OperatorSecrets, opV2Decls) {
		t.Fatalf("after upgrade %+v / %+v, want %+v", got.OperatorSecrets, listed.OperatorSecrets, opV2Decls)
	}
	if !reflect.DeepEqual(got.PreviousOperatorSecrets, opV1Decls) {
		t.Fatalf("previous after upgrade %+v, want %+v", got.PreviousOperatorSecrets, opV1Decls)
	}
}

// F-780-05: a re-apply swaps the declarations with the compose, so a reverted
// compose is gated by the declarations that went with it, and a custom edit
// clears them while keeping what it replaced.
func TestOperatorSecretsSwapOnRevert(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	createOperatorApp(t, s, opV1Decls)
	v1, _ := readBoth(t, s)
	up := UpgradeTarget{Tile: tileschema.Tile{ComposeYAML: "services: {v2: {}}\n", OperatorSecrets: opV2Decls}}.ComposeUpgrade()
	if err := s.UpgradeCompose(ctx, opStoreAppID, v1.ComposeSHA256, up, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	v2, _ := readBoth(t, s)
	if err := s.RevertCompose(ctx, opStoreAppID, v2.ComposeSHA256, v2.PreviousComposeYAML, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, listed := readBoth(t, s)
	if !reflect.DeepEqual(got.OperatorSecrets, opV1Decls) || !reflect.DeepEqual(listed.OperatorSecrets, opV1Decls) {
		t.Fatalf("after revert %+v, want v1's %+v", got.OperatorSecrets, opV1Decls)
	}
	if !reflect.DeepEqual(got.PreviousOperatorSecrets, opV2Decls) {
		t.Fatalf("previous after revert %+v, want v2's %+v", got.PreviousOperatorSecrets, opV2Decls)
	}
}

// A custom edit has no tile, so it declares nothing, and keeps what it
// replaced as the previous record, like privilege_tier.
func TestOperatorSecretsClearedByACustomEdit(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Now().UTC()
	if err := s.Create(ctx, &App{ID: opStoreAppID, Name: "c", ComposeYAML: "services: {a: {}}\n", TargetNode: "n",
		OperatorSecrets: opV1Decls, LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.EditCompose(ctx, opStoreAppID, ComposeHash("services: {a: {}}\n"), "services: {b: {}}\n", now); err != nil {
		t.Fatal(err)
	}
	got, _ := readBoth(t, s)
	if got.OperatorSecrets != nil || !reflect.DeepEqual(got.PreviousOperatorSecrets, opV1Decls) {
		t.Fatalf("after edit %+v / previous %+v", got.OperatorSecrets, got.PreviousOperatorSecrets)
	}
}

// TC-780-08: a database from before the columns migrates, and every existing
// app reads as declaring nothing.
func TestOperatorSecretsMigrateToNone(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apps.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	createOperatorApp(t, s, nil)
	for _, col := range []string{"operator_secrets", "previous_operator_secrets"} {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE apps DROP COLUMN `+col); err != nil {
			t.Fatalf("simulating an old database: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, listed := readBoth(t, s)
	if got.OperatorSecrets != nil || got.PreviousOperatorSecrets != nil || listed.OperatorSecrets != nil {
		t.Fatalf("a migrated row declares %+v / %+v", got.OperatorSecrets, got.PreviousOperatorSecrets)
	}
}

// TC-780-08 (F-780-04): JSON that does not parse fails the read; a field this
// build does not know is ignored.
func TestOperatorSecretsColumnDecoding(t *testing.T) {
	ctx := context.Background()
	t.Run("unparseable JSON is an error", func(t *testing.T) {
		s := newStore(t)
		createOperatorApp(t, s, opV1Decls)
		if _, err := s.db.ExecContext(ctx, `UPDATE apps SET operator_secrets = '{not json' WHERE id = ?`, opStoreAppID); err != nil {
			t.Fatal(err)
		}
		if a, err := s.Get(ctx, opStoreAppID); err == nil {
			t.Fatalf("Get read a corrupt column as %+v", a.OperatorSecrets)
		}
		if _, err := s.List(ctx); err == nil {
			t.Fatal("List read a corrupt column")
		}
	})
	// TC-604-02 (F-604-05): retargeted at a field this build does not know,
	// now that required is one it does.
	t.Run("an unknown field is ignored", func(t *testing.T) {
		s := newStore(t)
		createOperatorApp(t, s, nil)
		if _, err := s.db.ExecContext(ctx, `UPDATE apps SET operator_secrets = '[{"name":"a","label":"A","rotateEvery":"30d"}]' WHERE id = ?`, opStoreAppID); err != nil {
			t.Fatal(err)
		}
		want := []tileschema.OperatorSecret{{Name: "a", Label: "A"}}
		got, listed := readBoth(t, s)
		if !reflect.DeepEqual(got.OperatorSecrets, want) || !reflect.DeepEqual(listed.OperatorSecrets, want) {
			t.Fatalf("read %+v / %+v, want %+v", got.OperatorSecrets, listed.OperatorSecrets, want)
		}
	})
}

// TC-604-02: a row declaring required:false reads it back through Get and
// List, and a row from the previous release (no required) reads as nil,
// which is required.
func TestOperatorSecretsRequiredDecoding(t *testing.T) {
	ctx := context.Background()
	no := false
	for _, c := range []struct {
		why, column string
		want        []tileschema.OperatorSecret
		required    bool
	}{
		{"required false", `[{"name":"a","label":"A","required":false}]`, []tileschema.OperatorSecret{{Name: "a", Label: "A", Required: &no}}, false},
		{"previous release", `[{"name":"a","label":"A"}]`, []tileschema.OperatorSecret{{Name: "a", Label: "A"}}, true},
	} {
		t.Run(c.why, func(t *testing.T) {
			s := newStore(t)
			createOperatorApp(t, s, nil)
			if _, err := s.db.ExecContext(ctx, `UPDATE apps SET operator_secrets = ? WHERE id = ?`, c.column, opStoreAppID); err != nil {
				t.Fatal(err)
			}
			got, listed := readBoth(t, s)
			if !reflect.DeepEqual(got.OperatorSecrets, c.want) || !reflect.DeepEqual(listed.OperatorSecrets, c.want) {
				t.Fatalf("read %+v / %+v, want %+v", got.OperatorSecrets, listed.OperatorSecrets, c.want)
			}
			if got.OperatorSecrets[0].IsRequired() != c.required || listed.OperatorSecrets[0].IsRequired() != c.required {
				t.Fatalf("IsRequired() = %v, want %v", got.OperatorSecrets[0].IsRequired(), c.required)
			}
		})
	}
	t.Run("round trip through Create", func(t *testing.T) {
		s := newStore(t)
		decls := []tileschema.OperatorSecret{{Name: "a", Label: "A", Required: &no}}
		createOperatorApp(t, s, decls)
		got, _ := readBoth(t, s)
		if !reflect.DeepEqual(got.OperatorSecrets, decls) {
			t.Fatalf("read back %+v, want %+v", got.OperatorSecrets, decls)
		}
	})
}
