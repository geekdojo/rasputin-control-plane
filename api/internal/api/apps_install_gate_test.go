package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// design/storage.md §4.4's install-time gate (#299), through the route: a
// tile with a `critical` volume is held with a 409 while backups are
// unconfigured unless the body acknowledges it; with the acknowledgement it
// installs and the app carries who acknowledged and when; a configured
// cluster asks nothing; a tile with only `state` volumes asks nothing.

// gateTileBundle is a live catalog with two available tiles: vaultwarden,
// whose one volume is critical, and jellyfin, whose volumes are state and
// cache — the two sides of the gate.
func gateTileBundle(version int) tileschema.Bundle {
	// An AVAILABLE live tile must pass the bundle's own gates: a compose
	// with a digest-pinned image, declared in its safety facts.
	installable := func(bt tileschema.BundleTile, name string, volumes []tileschema.Volume) tileschema.BundleTile {
		image := "e/" + bt.Tile.ID + ":1@sha256:" + strings.Repeat("a", 64)
		bt.Tile.Name = name
		bt.Tile.Status = ""
		bt.Tile.Volumes = volumes
		bt.Compose = "services:\n  x:\n    image: " + image + "\n"
		bt.Tile.ComposeYAML = bt.Compose
		bt.Safety = tileschema.SafetyFacts{Images: []string{image}}
		return bt
	}
	b := oneTileBundle(version, "vaultwarden")
	b.Tiles[0] = installable(b.Tiles[0], "Vaultwarden", []tileschema.Volume{
		{Name: "vaultwarden-data", Backup: tileschema.BackupCritical, Quiesce: tileschema.QuiesceStop},
	})
	b.Tiles = append(b.Tiles, installable(oneTileBundle(version, "jellyfin").Tiles[0], "Jellyfin", []tileschema.Volume{
		{Name: "jellyfin-config", Backup: tileschema.BackupState, Quiesce: tileschema.QuiesceStop},
		{Name: "jellyfin-cache", Backup: tileschema.BackupCache, Quiesce: tileschema.QuiesceNone},
	}))
	return b
}

// gateFixture wires the live catalog, a backup ledger and the per-app
// derivation the gate asks — the same wiring main does.
func gateFixture(t *testing.T) (*apiFixture, *http.Cookie, *storage.Store) {
	t.Helper()
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	cat, err := catalogsync.New(t.TempDir(), stubVerifier{}, gateTileBundle(7))
	if err != nil {
		t.Fatalf("catalog store: %v", err)
	}
	f.srv.SetCatalogSync(cat, nil)
	backup, err := storage.OpenStore(f.ctx, filepath.Join(t.TempDir(), "backup.db"))
	if err != nil {
		t.Fatalf("backup store: %v", err)
	}
	t.Cleanup(func() { _ = backup.Close() })
	f.srv.SetBackupStore(backup)
	f.srv.SetBackupStates(storage.NewBackupStates(backup, f.jobsStore, f.appsStore, cat, f.setupSvc.Store(), true))
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "n1", Role: proto.RoleCompute, Hostname: "n1.test", Architecture: "arm64", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	return f, cookie, backup
}

func claimTarget(t *testing.T, backup *storage.Store) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC()
	if err := backup.CreatePending(ctx, "claim-1", "n1", "/dev/sda", "usb", now); err != nil {
		t.Fatal(err)
	}
	if err := backup.MarkClaimed(ctx, "claim-1", storage.ClaimResult{PartUUID: "pu-1", At: now}); err != nil {
		t.Fatal(err)
	}
}

func TestInstallGate_CriticalTileUnconfiguredIsHeldWithoutAcknowledgement(t *testing.T) {
	f, cookie, _ := gateFixture(t)

	w := f.do(t, http.MethodPost, "/api/catalog/vaultwarden/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("install without acknowledgement: want 409, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"Vaultwarden", "vaultwarden-data", "no backup target is claimed", "acknowledgeNoBackup"} {
		if !strings.Contains(body, want) {
			t.Errorf("409 body %q does not say %q", body, want)
		}
	}
	// Nothing was installed.
	if all, _ := f.appsStore.List(f.ctx); len(all) != 0 {
		t.Errorf("a held install must not create the app; apps = %d", len(all))
	}

	// The schedule off is the other half of unconfigured — same hold.
	claimTarget(t, f.srv.backup)
	if _, err := storage.SetBackupSchedule(f.ctx, f.setupSvc.Store(), storage.BackupSchedule{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	w = f.do(t, http.MethodPost, "/api/catalog/vaultwarden/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "turned off") {
		t.Errorf("schedule off: want 409 naming the schedule, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestInstallGate_AcknowledgedInstallProceedsAndIsRecorded(t *testing.T) {
	f, cookie, _ := gateFixture(t)

	w := f.do(t, http.MethodPost, "/api/catalog/vaultwarden/install", `{"targetNode":"n1","acknowledgeNoBackup":true}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("acknowledged install: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var created apps.App
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.BackupAck == nil {
		t.Fatalf("created app carries no backupAck: %s", w.Body.String())
	}
	if created.BackupAck.By != "alice" {
		t.Errorf("backupAck.by = %q, want the authenticated user's name", created.BackupAck.By)
	}
	if time.Since(created.BackupAck.At) > time.Minute {
		t.Errorf("backupAck.at = %s, want the install time", created.BackupAck.At)
	}
	if strings.Contains(w.Body.String(), "test-cookie-token") {
		t.Errorf("the session token must never appear on the app row: %s", w.Body.String())
	}

	// It rides the row, and the row's derived state is the nag, not OVERDUE.
	w = f.do(t, http.MethodGet, "/api/apps", "", cookie)
	var rows []struct {
		apps.App
		Backup *proto.AppBackupState `json:"backup"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("list: %v %s", err, w.Body.String())
	}
	if rows[0].BackupAck == nil || rows[0].BackupAck.By != "alice" {
		t.Errorf("list row backupAck = %+v", rows[0].BackupAck)
	}
	if rows[0].Backup == nil || rows[0].Backup.State != proto.AppBackupUnconfigured || rows[0].Backup.Class != tileschema.BackupCritical {
		t.Errorf("list row backup = %+v, want unconfigured/critical", rows[0].Backup)
	}
	w = f.do(t, http.MethodGet, "/api/apps/"+created.ID, "", cookie)
	if !strings.Contains(w.Body.String(), `"by":"alice"`) {
		t.Errorf("GET /api/apps/{id} must carry the acknowledgement: %s", w.Body.String())
	}
}

func TestInstallGate_NoGateWhenConfigured(t *testing.T) {
	f, cookie, backup := gateFixture(t)
	claimTarget(t, backup)

	// No acknowledgement needed — and one sent anyway records nothing,
	// because there was nothing to acknowledge.
	w := f.do(t, http.MethodPost, "/api/catalog/vaultwarden/install", `{"targetNode":"n1","acknowledgeNoBackup":true}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("configured install: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "backupAck") {
		t.Errorf("a configured cluster records no acknowledgement: %s", w.Body.String())
	}
}

func TestInstallGate_StateOnlyTileIsNotGated(t *testing.T) {
	f, cookie, _ := gateFixture(t)

	w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("state-only tile with no target: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "backupAck") {
		t.Errorf("a state-only tile is not asked and records nothing: %s", w.Body.String())
	}
}

// A custom-compose app has no tile and so no classification: nothing for
// the gate to judge, and POST /api/apps is unchanged.
func TestInstallGate_CustomComposeIsNotGated(t *testing.T) {
	f, cookie, _ := gateFixture(t)
	w := f.do(t, http.MethodPost, "/api/apps", `{"name":"mine","composeYaml":"services: {}","targetNode":"n1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("custom app: want 201, got %d (%s)", w.Code, w.Body.String())
	}
}
