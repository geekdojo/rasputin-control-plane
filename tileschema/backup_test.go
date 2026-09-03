package tileschema

import (
	"encoding/json"
	"strings"
	"testing"
)

// okVolume is a plausible declaration: an app's own state, copied with the
// service stopped, which is what §4.3 says most tiles land on.
func okVolume() Volume {
	return Volume{Name: "uptime-kuma-data", Backup: BackupState, Quiesce: QuiesceStop}
}

func tileWithVolumes(vs ...Volume) Tile {
	t := okTile()
	t.Volumes = vs
	return t
}

// A tile declaring no volumes stays valid. Every tile published before this
// field existed is that shape, and so is a genuinely stateless app — the
// refusal is per DECLARED volume, not per tile.
func TestValidateTile_NoVolumesIsStillValid(t *testing.T) {
	x := okTile()
	x.Volumes = nil
	if err := ValidateTile(x); err != nil {
		t.Fatalf("a tile with no volumes should validate, got %v", err)
	}
}

func TestValidateTile_AcceptsEveryBackupClass(t *testing.T) {
	for _, class := range BackupClasses {
		t.Run(class, func(t *testing.T) {
			v := okVolume()
			v.Backup = class
			// cache is never copied, so it must take quiesce none — see the
			// cross-field rule. Every other class is free to take stop.
			if class == BackupCache {
				v.Quiesce = QuiesceNone
			}
			if err := ValidateTile(tileWithVolumes(v)); err != nil {
				t.Fatalf("backup %q should be accepted, got %v", class, err)
			}
		})
	}
}

func TestValidateTile_AcceptsEveryQuiesceStrategy(t *testing.T) {
	for _, strategy := range QuiesceStrategies {
		t.Run(strategy, func(t *testing.T) {
			v := okVolume()
			v.Quiesce = strategy
			if err := ValidateTile(tileWithVolumes(v)); err != nil {
				t.Fatalf("quiesce %q should be accepted, got %v", strategy, err)
			}
		})
	}
}

// The core of §4.2: an unclassified volume is REFUSED, and the refusal says
// enough to act on without opening this package.
func TestValidateTile_RejectsUnclassifiedVolumes(t *testing.T) {
	cases := []struct {
		name string
		vol  Volume
		// wantIn are substrings the message must carry. Asserted rather than
		// merely checking err != nil because the message is the deliverable
		// here: a CI line that does not name the field and its legal values
		// sends the author to the schema source.
		wantIn []string
	}{
		{
			name:   "backup absent",
			vol:    Volume{Name: "vaultwarden-data", Quiesce: QuiesceStop},
			wantIn: []string{"vaultwarden-data", "backup", "no default", "critical|state|cache|bulk"},
		},
		{
			name:   "backup empty string",
			vol:    Volume{Name: "vaultwarden-data", Backup: "", Quiesce: QuiesceStop},
			wantIn: []string{"vaultwarden-data", "backup", "no default"},
		},
		{
			name:   "backup whitespace only",
			vol:    Volume{Name: "vaultwarden-data", Backup: "   ", Quiesce: QuiesceStop},
			wantIn: []string{"vaultwarden-data", "backup"},
		},
		{
			name:   "backup unknown value",
			vol:    Volume{Name: "vaultwarden-data", Backup: "archive", Quiesce: QuiesceStop},
			wantIn: []string{"vaultwarden-data", `"archive"`, "critical|state|cache|bulk"},
		},
		{
			name:   "backup right-looking but wrong case",
			vol:    Volume{Name: "vaultwarden-data", Backup: "Critical", Quiesce: QuiesceStop},
			wantIn: []string{"critical|state|cache|bulk"},
		},
		{
			name:   "quiesce absent",
			vol:    Volume{Name: "paperless-data", Backup: BackupState},
			wantIn: []string{"paperless-data", "quiesce", "no default", "none|stop|sqlite|postgres|mysql"},
		},
		{
			name:   "quiesce empty string",
			vol:    Volume{Name: "paperless-data", Backup: BackupState, Quiesce: ""},
			wantIn: []string{"paperless-data", "quiesce", "no default"},
		},
		{
			name:   "quiesce unknown value",
			vol:    Volume{Name: "paperless-data", Backup: BackupState, Quiesce: "mariadb"},
			wantIn: []string{"paperless-data", `"mariadb"`, "none|stop|sqlite|postgres|mysql"},
		},
		{
			name:   "no name to attach the classification to",
			vol:    Volume{Name: "  ", Backup: BackupState, Quiesce: QuiesceStop},
			wantIn: []string{"volumes[0]", "name is required"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTile(tileWithVolumes(tc.vol))
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message should carry %q, got: %v", want, err)
				}
			}
		})
	}
}

// A real tile has several volumes and the author forgets ONE of them. The
// message has to say which, or the author bisects their own tile.
func TestValidateTile_NamesTheUnclassifiedVolumeAmongMany(t *testing.T) {
	x := tileWithVolumes(
		Volume{Name: "immich-upload", Backup: BackupState, Quiesce: QuiesceStop},
		Volume{Name: "immich-db", Backup: BackupState, Quiesce: QuiescePostgres},
		Volume{Name: "immich-model-cache", Quiesce: QuiesceNone}, // no class
		Volume{Name: "immich-thumbs", Backup: BackupState, Quiesce: QuiesceStop},
	)
	err := ValidateTile(x)
	if err == nil {
		t.Fatal("expected rejection: immich-model-cache carries no backup class")
	}
	msg := err.Error()
	if !strings.Contains(msg, "immich-model-cache") {
		t.Errorf("message should name the offending volume, got: %v", msg)
	}
	if !strings.Contains(msg, "volumes[2]") {
		t.Errorf("message should give the offending index, got: %v", msg)
	}
	for _, innocent := range []string{"immich-upload", "immich-db", "immich-thumbs"} {
		if strings.Contains(msg, innocent) {
			t.Errorf("message should not implicate the classified volume %q, got: %v", innocent, msg)
		}
	}
}

func TestValidateTile_RejectsDuplicateVolumeNames(t *testing.T) {
	x := tileWithVolumes(
		Volume{Name: "romm-library", Backup: BackupBulk, Quiesce: QuiesceNone},
		Volume{Name: "romm-library", Backup: BackupState, Quiesce: QuiesceMySQL},
	)
	err := ValidateTile(x)
	if err == nil {
		t.Fatal("expected rejection: two volumes share a name and contradict each other")
	}
	if !strings.Contains(err.Error(), "romm-library") {
		t.Errorf("message should name the duplicate, got: %v", err)
	}
}

// The one cross-field rule (§4.2 + §4.3): a cache volume is never copied, so a
// quiesce strategy on it describes work that never runs.
func TestValidateTile_CacheMustQuiesceNone(t *testing.T) {
	for _, strategy := range QuiesceStrategies {
		if strategy == QuiesceNone {
			continue
		}
		t.Run(strategy, func(t *testing.T) {
			x := tileWithVolumes(Volume{Name: "jellyfin-cache", Backup: BackupCache, Quiesce: strategy})
			err := ValidateTile(x)
			if err == nil {
				t.Fatalf("expected rejection: cache with quiesce %q", strategy)
			}
			if !strings.Contains(err.Error(), "jellyfin-cache") || !strings.Contains(err.Error(), QuiesceNone) {
				t.Errorf("message should name the volume and the fix, got: %v", err)
			}
		})
	}
}

// bulk is deliberately NOT constrained the same way. §4.3 observes that today's
// bulk volumes take none; that is how the catalog came out, not a property of
// the class, and a bulk volume IS copied once its app opts in.
func TestValidateTile_BulkMayDeclareAnyQuiesce(t *testing.T) {
	for _, strategy := range QuiesceStrategies {
		t.Run(strategy, func(t *testing.T) {
			x := tileWithVolumes(Volume{Name: "jellyfin-media", Backup: BackupBulk, Quiesce: strategy})
			if err := ValidateTile(x); err != nil {
				t.Fatalf("bulk with quiesce %q should be accepted, got %v", strategy, err)
			}
		})
	}
}

// A preview tile ships no compose and never reaches ValidateTileSafety, so if
// this check lived there a preview tile's volumes would go unchecked until the
// day it flipped to available — the #162 mistake, repeated.
func TestValidateTile_PreviewTileVolumesAreCheckedToo(t *testing.T) {
	x := tileWithVolumes(Volume{Name: "vaultwarden-data", Quiesce: QuiesceStop})
	x.Status = StatusPreview
	x.ComposeYAML = ""
	if err := ValidateTile(x); err == nil {
		t.Fatal("a preview tile with an unclassified volume should be refused")
	}
}

// The wire shape, pinned. #293 authors JSON against these exact keys in another
// repo, so a rename here is a silent break there.
func TestVolume_JSONShape(t *testing.T) {
	var tile Tile
	raw := `{"volumes":[{"name":"vaultwarden-data","backup":"critical","quiesce":"stop"}]}`
	if err := json.Unmarshal([]byte(raw), &tile); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(tile.Volumes) != 1 {
		t.Fatalf("want 1 volume, got %d", len(tile.Volumes))
	}
	got := tile.Volumes[0]
	if got.Name != "vaultwarden-data" || got.Backup != BackupCritical || got.Quiesce != QuiesceStop {
		t.Fatalf("decoded %+v", got)
	}

	// A tile with nothing to declare must not emit an empty array into every
	// published bundle — the bundle is signed over its bytes.
	out, err := json.Marshal(okTile())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "volumes") {
		t.Fatalf("a tile with no volumes should omit the field entirely, got %s", out)
	}
}

// The vocabularies and their membership sets are one source of truth, so a
// value the validator accepts is always a value some message offers.
func TestClosedVocabulariesAgreeWithTheirSets(t *testing.T) {
	if len(ValidBackupClass) != len(BackupClasses) {
		t.Fatalf("ValidBackupClass has %d entries for %d classes", len(ValidBackupClass), len(BackupClasses))
	}
	for _, c := range BackupClasses {
		if !ValidBackupClass[c] {
			t.Errorf("class %q is listed but not accepted", c)
		}
	}
	if len(ValidQuiesce) != len(QuiesceStrategies) {
		t.Fatalf("ValidQuiesce has %d entries for %d strategies", len(ValidQuiesce), len(QuiesceStrategies))
	}
	for _, s := range QuiesceStrategies {
		if !ValidQuiesce[s] {
			t.Errorf("strategy %q is listed but not accepted", s)
		}
	}
}

// The bundle path applies the same rules and reports the tile, so an
// unclassified volume cannot reach a cluster through the tolerant reader
// either.
func TestBundle_RefusesATileWithAnUnclassifiedVolume(t *testing.T) {
	bt := BundleTile{
		Tile:    tileWithVolumes(Volume{Name: "actual-data", Backup: BackupState}),
		Compose: "services: {}",
		Safety:  okFacts(),
	}
	b := Bundle{SchemaVersion: BundleSchemaVersion, Version: 1, Tiles: []BundleTile{bt}}
	if err := b.Validate(); err == nil {
		t.Fatal("strict parse should refuse a tile with an unclassified volume")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, rejected, err := ParseFetchedBundle(raw)
	if err == nil {
		t.Fatal("a bundle whose only tile is refused is not a catalog")
	}
	if len(rejected) != 1 || rejected[0].ID != "uptime-kuma" {
		t.Fatalf("want the tile reported as rejected, got %+v", rejected)
	}
	if !strings.Contains(rejected[0].Reason, "actual-data") {
		t.Errorf("rejection reason should name the volume, got %q", rejected[0].Reason)
	}
}
