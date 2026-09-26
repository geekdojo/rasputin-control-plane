package apps

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Server-enforced consent on a catalog upgrade that raises the app's privilege
// tier (auth-methodology §9 dec 12, geekdojo/geekdojo-brain#522): the pure
// decision, the record it leaves on the row, and the saga refusing a raise that
// no request consented to — whoever submitted the job.

// hostTrustingTile is upgradeTile declaring the top tier.
func hostTrustingTile(compose string) tileschema.Tile {
	t := upgradeTile(compose)
	t.Privilege = &tileschema.Privilege{
		Tier:   tileschema.TierHostTrusting,
		Grants: []string{tileschema.GrantPrivileged},
		Why:    "talks to USB radios",
	}
	return t
}

func elevatedTile(compose string) tileschema.Tile {
	t := upgradeTile(compose)
	t.Privilege = &tileschema.Privilege{
		Tier:   tileschema.TierElevated,
		Grants: []string{tileschema.GrantHostNetwork},
		Why:    "discovers devices",
	}
	return t
}

func TestUpgradePrivilege_RaisesOnlyWhenTheRankGoesUp(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		target    tileschema.Tile
		raises    bool
		wantTier  string
	}{
		{"routine to host-trusting", tileschema.TierRoutine, hostTrustingTile(composeV2), true, tileschema.TierHostTrusting},
		{"routine to elevated", tileschema.TierRoutine, elevatedTile(composeV2), true, tileschema.TierElevated},
		{"elevated to host-trusting", tileschema.TierElevated, hostTrustingTile(composeV2), true, tileschema.TierHostTrusting},
		{"host-trusting to routine", tileschema.TierHostTrusting, upgradeTile(composeV2), false, tileschema.TierRoutine},
		{"host-trusting to host-trusting", tileschema.TierHostTrusting, hostTrustingTile(composeV2), false, tileschema.TierHostTrusting},
		{"routine to routine", tileschema.TierRoutine, upgradeTile(composeV2), false, tileschema.TierRoutine},
		// Not recorded: an install from before the tier was stored. Read as
		// routine, so anything above it asks once.
		{"unrecorded to elevated", "", elevatedTile(composeV2), true, tileschema.TierElevated},
		{"unrecorded to routine", "", upgradeTile(composeV2), false, tileschema.TierRoutine},
	}
	for _, c := range cases {
		app := installedApp("a")
		app.PrivilegeTier = c.installed
		got := UpgradePrivilege(app, c.target)
		if got.Raises != c.raises {
			t.Errorf("%s: Raises = %v, want %v", c.name, got.Raises, c.raises)
		}
		if got.FromTier != c.installed {
			t.Errorf("%s: FromTier = %q, want %q", c.name, got.FromTier, c.installed)
		}
		if got.Privilege.Tier != c.wantTier {
			t.Errorf("%s: target tier = %q, want %q (resolved, never empty)", c.name, got.Privilege.Tier, c.wantTier)
		}
	}
}

// The gate the saga applies, against what the row records.
func TestCheckUpgradeConsent(t *testing.T) {
	target := UpgradeTarget{Tile: hostTrustingTile(composeV2), CatalogVersion: 2}
	ack := func(tier, compose string) *PrivilegeAck {
		return &PrivilegeAck{At: time.Now(), By: "bryce", What: PrivilegeConsent{
			FromTier: tileschema.TierRoutine, Tier: tier, CatalogVersion: 2, ComposeSHA256: ComposeHash(compose),
		}}
	}
	cases := []struct {
		name      string
		installed string
		ack       *PrivilegeAck
		target    UpgradeTarget
		wantErr   bool
	}{
		{"raise with no consent", tileschema.TierRoutine, nil, target, true},
		{"raise with consent to this compose", tileschema.TierRoutine, ack(tileschema.TierHostTrusting, composeV2), target, false},
		{"raise with consent to another compose", tileschema.TierRoutine, ack(tileschema.TierHostTrusting, composeV1), target, true},
		{"raise with consent to a lower tier", tileschema.TierRoutine, ack(tileschema.TierElevated, composeV2), target, true},
		{"equal tier needs none", tileschema.TierHostTrusting, nil, target, false},
		{"lowering needs none", tileschema.TierHostTrusting, nil, UpgradeTarget{Tile: upgradeTile(composeV2), CatalogVersion: 2}, false},
	}
	for _, c := range cases {
		app := installedApp("a")
		app.PrivilegeTier = c.installed
		app.PrivilegeAck = c.ack
		err := CheckUpgradeConsent(app, c.target)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErr)
		}
		if err != nil && !errors.Is(err, ErrPrivilegeConsentRequired) {
			t.Errorf("%s: err = %v, want ErrPrivilegeConsentRequired", c.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "HOST-TRUSTING") {
			t.Errorf("%s: refusal %q does not name the tier it needs", c.name, err)
		}
	}
}

// The consent record: who, when, and exactly what was accepted.
func TestStore_RecordPrivilegeAckRoundTrips(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	app := installedApp("a")
	app.PrivilegeTier = tileschema.TierRoutine
	if err := s.Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	want := PrivilegeAck{At: at, By: "bryce", What: PrivilegeConsent{
		FromTier: tileschema.TierRoutine, Tier: tileschema.TierHostTrusting,
		DockerSocket: true, Grants: []string{"docker-socket", "privileged"},
		CatalogVersion: 9, ComposeSHA256: ComposeHash(composeV2),
	}}
	if err := s.RecordPrivilegeAck(ctx, "a", ComposeHash(composeV1), want); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, "a")
	if got.PrivilegeAck == nil || !reflect.DeepEqual(*got.PrivilegeAck, want) {
		t.Fatalf("recorded ack = %+v, want %+v", got.PrivilegeAck, want)
	}
	if got.PrivilegeTier != tileschema.TierRoutine || got.ComposeYAML != composeV1 {
		t.Error("recording consent changed what is installed")
	}

	// Conditional on the compose the caller read, like every compose write.
	if err := s.RecordPrivilegeAck(ctx, "a", "stale", want); !errors.Is(err, ErrComposeChanged) {
		t.Errorf("stale hash: err = %v, want ErrComposeChanged", err)
	}
	if err := s.RecordPrivilegeAck(ctx, "ghost", ComposeHash(composeV1), want); err == nil {
		t.Error("an unknown app recorded consent")
	}
}

// The tier travels with the compose: install records it, an upgrade replaces
// it and keeps the old one beside the previous compose, a revert swaps them,
// and a custom edit has none.
func TestStore_PrivilegeTierFollowsTheCompose(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	app := installedApp("a")
	app.PrivilegeTier = tileschema.TierRoutine
	if err := s.Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, "a"); got.PrivilegeTier != tileschema.TierRoutine {
		t.Fatalf("installed tier = %q", got.PrivilegeTier)
	}

	up := UpgradeTarget{Tile: hostTrustingTile(composeV2), CatalogVersion: 2}.ComposeUpgrade()
	if up.PrivilegeTier != tileschema.TierHostTrusting {
		t.Fatalf("ComposeUpgrade tier = %q", up.PrivilegeTier)
	}
	if err := s.UpgradeCompose(ctx, "a", ComposeHash(composeV1), up, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, "a")
	if got.PrivilegeTier != tileschema.TierHostTrusting || got.PreviousPrivilegeTier != tileschema.TierRoutine {
		t.Fatalf("after upgrade: tier=%q previous=%q", got.PrivilegeTier, got.PreviousPrivilegeTier)
	}

	if err := s.RevertCompose(ctx, "a", ComposeHash(composeV2), composeV1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(ctx, "a")
	if got.PrivilegeTier != tileschema.TierRoutine || got.PreviousPrivilegeTier != tileschema.TierHostTrusting {
		t.Fatalf("after revert: tier=%q previous=%q", got.PrivilegeTier, got.PreviousPrivilegeTier)
	}

	custom := makeApp("c", "mine")
	if err := s.Create(ctx, custom); err != nil {
		t.Fatal(err)
	}
	if err := s.EditCompose(ctx, "c", ComposeHash(custom.ComposeYAML), "services: {b: {}}\n", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, "c"); got.PrivilegeTier != "" {
		t.Errorf("a custom app has a tier: %q", got.PrivilegeTier)
	}
}

// The saga is the gate, not the handler: POST /api/jobs can submit app.upgrade
// with nothing but an app id, and a raise nobody consented to must stop before
// the node is asked anything or the row is marked.
func TestUpgradeSaga_RefusesARaiseWithNoRecordedConsent(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID) // installed with no recorded tier: routine
	pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	got := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	lookup := lookupOf(hostTrustingTile(composeV2), 2)

	step, err := runUpgrade(t, store, inv, nc, lookup, testAppID)
	if !errors.Is(err, ErrPrivilegeConsentRequired) || step != "pull" {
		t.Fatalf("want the pull step to refuse the raise, got step=%q err=%v", step, err)
	}
	select {
	case cmd := <-got:
		t.Fatalf("an unconsented raise reached the node: %+v", cmd)
	case cmd := <-pulls:
		t.Fatalf("an unconsented raise asked the node to pull: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	row, _ := store.Get(ctx, testAppID)
	if row.ComposeYAML != composeV1 || row.LastStatus != proto.AppStatusRunning {
		t.Fatalf("a refused raise touched the row: status=%s", row.LastStatus)
	}

	// Consent to exactly that compose lets the same job through, and the row
	// then records the tier it now runs at.
	if err := store.RecordPrivilegeAck(ctx, testAppID, row.ComposeSHA256, PrivilegeAck{
		At: time.Now().UTC(), By: "bryce",
		What: PrivilegeConsent{FromTier: "", Tier: tileschema.TierHostTrusting, CatalogVersion: 2, ComposeSHA256: ComposeHash(composeV2)},
	}); err != nil {
		t.Fatal(err)
	}
	if step, err := runUpgrade(t, store, inv, nc, lookup, testAppID); err != nil {
		t.Fatalf("consented upgrade failed at %s: %v", step, err)
	}
	receiveWithin(t, got, "the consented upgrade never deployed")
	row, _ = store.Get(ctx, testAppID)
	if row.ComposeYAML != composeV2 || row.PrivilegeTier != tileschema.TierHostTrusting {
		t.Errorf("after the consented upgrade: tier=%q compose=%q", row.PrivilegeTier, row.ComposeYAML)
	}
}
