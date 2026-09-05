package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The per-app decision table (design/storage.md §4.4, #298), executed.
//
// Every case is one app against a weekly cadence — the default, whose grace is
// a quarter of a week (42h), so the age limit is 8d 18h. The attempts are hand-
// built records of what the ledger would hold, newest first, exactly as
// BackupStates.attempts returns them.

const (
	stateAppID = "app-im"
	stateWeek  = 7 * 24 * time.Hour
)

var stateNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func stateVolumes(class string, names ...string) []PlannedVolume {
	out := make([]PlannedVolume, 0, len(names))
	for _, n := range names {
		out = append(out, PlannedVolume{AppID: stateAppID, AppName: "immich", NodeID: "n-compute", Volume: n, Class: class})
	}
	return out
}

// reportWith builds a fan-out record naming the app's volumes: captured, or
// failed with the reason.
func reportWith(captured []string, failed map[string]string) *AppVolumeReport {
	var recs []VolumeRecord
	for _, v := range captured {
		recs = append(recs, VolumeRecord{App: "immich", AppID: stateAppID, Node: "n-compute", Volume: v, Class: tileschema.BackupState, Captured: true})
	}
	for v, why := range failed {
		recs = append(recs, VolumeRecord{App: "immich", AppID: stateAppID, Node: "n-compute", Volume: v, Class: tileschema.BackupState, Failed: true, Reason: why})
	}
	// Another app's record is always in a real report; it must be ignored.
	recs = append(recs, VolumeRecord{App: "vaultwarden", AppID: "app-vw", Node: "n-backup", Volume: "vaultwarden-data", Class: tileschema.BackupCritical, Captured: true})
	rep := NewAppVolumeReport(AppEnumeration{AppsInstalled: 2, AppsResolved: 2}, recs, 2)
	return &rep
}

func success(ago time.Duration) backupAttempt {
	return backupAttempt{JobID: "ok-" + ago.String(), At: stateNow.Add(-ago), Status: RunSucceeded, HasGeneration: true, Report: reportWith([]string{"immich-upload"}, nil)}
}

func offNode(ago time.Duration) backupAttempt {
	return backupAttempt{JobID: "off-" + ago.String(), At: stateNow.Add(-ago), Status: RunFailed, HasGeneration: true,
		Report: reportWith(nil, map[string]string{"immich-upload": "node n-compute is OFFLINE: no agent answered the staging request on the bus"})}
}

func baseInput(attempts ...backupAttempt) backupStateInput {
	return backupStateInput{
		AppID: stateAppID, AppName: "immich", InstalledAt: stateNow.Add(-30 * 24 * time.Hour),
		Volumes:    stateVolumes(tileschema.BackupState, "immich-upload"),
		Configured: true, Cadence: stateWeek, Attempts: attempts,
	}
}

func TestBackupGrace(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		stateWeek:           42 * time.Hour, // a quarter of a week
		24 * time.Hour:      6 * time.Hour,  // a quarter of a day is under the floor
		time.Hour:           6 * time.Hour,
		30 * 24 * time.Hour: 180 * time.Hour,
	}
	for cadence, want := range cases {
		if got := BackupGrace(cadence); got != want {
			t.Errorf("BackupGrace(%s) = %s, want %s", cadence, got, want)
		}
	}
}

func TestDeriveBackupState(t *testing.T) {
	limit := stateWeek + BackupGrace(stateWeek) // 8d 18h

	cases := []struct {
		name     string
		in       backupStateInput
		want     proto.AppBackupStateKind
		class    string
		reason   []string
		noReason []string
		success  *time.Duration // expected LastSuccessAt as "ago", nil = absent
		since    *time.Time     // expected OverdueSince, nil = absent
	}{
		{
			name: "ok: captured inside the cadence", in: baseInput(success(2 * time.Hour)),
			want: proto.AppBackupOK, class: "state", success: dur(2 * time.Hour),
		},
		{
			name: "ok: inside the grace is still ok", in: baseInput(success(limit - time.Minute)),
			want: proto.AppBackupOK, success: dur(limit - time.Minute),
		},
		{
			name: "overdue by age: one minute past cadence plus grace", in: baseInput(success(limit + time.Minute)),
			want: proto.AppBackupOverdue, reason: []string{"past the 168h0m0s cadence", "42h0m0s grace"},
			success: dur(limit + time.Minute), since: tp(stateNow.Add(-(limit + time.Minute)).Add(limit)),
		},
		{
			name: "overdue by last failure, however fresh the success before it",
			in:   baseInput(offNode(time.Hour), success(3*time.Hour)),
			want: proto.AppBackupOverdue, reason: []string{"most recent backup attempt FAILED", "immich-upload: node n-compute is OFFLINE"},
			success: dur(3 * time.Hour), since: tp(stateNow.Add(-time.Hour)),
		},
		{
			name: "a run that failed before the fan-out is a failure for every app",
			in: baseInput(backupAttempt{At: stateNow.Add(-time.Hour), Status: RunFailed, Error: "the backup target (partUuid x) is not attached to n-backup — it was unplugged"},
				success(3*time.Hour)),
			want: proto.AppBackupOverdue, reason: []string{"failed before reaching this app", "unplugged"}, success: dur(3 * time.Hour),
		},
		{
			name: "a run that failed for ANOTHER app's volume is a success for this one",
			in: baseInput(backupAttempt{At: stateNow.Add(-time.Hour), Status: RunFailed, HasGeneration: true,
				Report: reportWith([]string{"immich-upload"}, nil)}),
			want: proto.AppBackupOK, success: dur(time.Hour),
		},
		{
			name: "a generation that never landed is not a success",
			in: baseInput(backupAttempt{At: stateNow.Add(-time.Hour), Status: RunFailed, HasGeneration: false,
				Report: reportWith([]string{"immich-upload"}, nil), Error: "backup write rpc to n-backup: timeout"}),
			want: proto.AppBackupOverdue, reason: []string{"never wrote its generation"},
		},
		{
			name: "a generation missing one of two volumes is not a success",
			in: func() backupStateInput {
				in := baseInput(success(time.Hour))
				in.Volumes = stateVolumes(tileschema.BackupState, "immich-upload", "immich-db")
				return in
			}(),
			want: proto.AppBackupOverdue, reason: []string{"does not hold immich-db"},
		},
		{
			name: "never: installed inside the grace, no run yet",
			in: func() backupStateInput {
				in := baseInput()
				in.InstalledAt = stateNow.Add(-2 * 24 * time.Hour)
				return in
			}(),
			want: proto.AppBackupNever, reason: []string{"not backed up yet", "installed 2d ago"},
		},
		{
			name: "never: a run from before the install says nothing about it",
			in: func() backupStateInput {
				in := baseInput(success(3 * 24 * time.Hour))
				in.InstalledAt = stateNow.Add(-2 * 24 * time.Hour)
				return in
			}(),
			want: proto.AppBackupNever,
		},
		{
			name: "never: a run whose report does not mention the app says nothing about it",
			in: func() backupStateInput {
				in := baseInput(backupAttempt{At: stateNow.Add(-time.Hour), Status: RunSucceeded, HasGeneration: true,
					Report: reportWith(nil, nil)})
				in.AppID = "app-new"
				in.InstalledAt = stateNow.Add(-2 * time.Hour)
				return in
			}(),
			want: proto.AppBackupNever,
		},
		{
			name: "overdue: never backed up and installed longer than cadence plus grace",
			in: func() backupStateInput {
				in := baseInput()
				in.InstalledAt = stateNow.Add(-(limit + time.Minute))
				return in
			}(),
			want: proto.AppBackupOverdue, reason: []string{"never backed up", "no generation has ever captured"},
			since: tp(stateNow.Add(-(limit + time.Minute)).Add(limit)),
		},
		{
			name: "unconfigured: no target, even with a failed attempt on record",
			in: func() backupStateInput {
				in := baseInput(offNode(time.Hour))
				in.Configured = false
				in.UnconfiguredReason = "no backup target is claimed"
				return in
			}(),
			want: proto.AppBackupUnconfigured, reason: []string{"no backup target is claimed"}, noReason: []string{"OVERDUE", "FAILED"},
		},
		{
			name: "unconfigured: schedule off, even when stale",
			in: func() backupStateInput {
				in := baseInput(success(30 * 24 * time.Hour))
				in.Configured = false
				in.UnconfiguredReason = "scheduled backups are turned off"
				return in
			}(),
			want: proto.AppBackupUnconfigured, success: dur(30 * 24 * time.Hour),
		},
		{
			name: "none: cache/bulk only is never overdue, whatever the ledger says",
			in: func() backupStateInput {
				in := baseInput(offNode(time.Hour))
				in.Volumes = nil
				in.NoneReason = "every volume is cache or bulk"
				return in
			}(),
			want: proto.AppBackupNone, class: "", reason: []string{"cache or bulk"},
		},
		{
			name: "class: any critical volume makes the app critical",
			in: func() backupStateInput {
				in := baseInput(success(time.Hour))
				in.Volumes = append(stateVolumes(tileschema.BackupState, "immich-upload"), stateVolumes(tileschema.BackupCritical, "immich-upload")...)
				return in
			}(),
			want: proto.AppBackupOK, class: "critical", success: dur(time.Hour),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveBackupState(tc.in, stateNow)
			if got.State != tc.want {
				t.Fatalf("state = %s (%s), want %s", got.State, got.Reason, tc.want)
			}
			if tc.class != "" || tc.want == proto.AppBackupNone {
				if got.Class != tc.class {
					t.Errorf("class = %q, want %q", got.Class, tc.class)
				}
			}
			for _, w := range tc.reason {
				if !strings.Contains(got.Reason, w) {
					t.Errorf("reason %q does not say %q", got.Reason, w)
				}
			}
			for _, w := range tc.noReason {
				if strings.Contains(got.Reason, w) {
					t.Errorf("reason %q must not say %q", got.Reason, w)
				}
			}
			switch {
			case tc.success == nil && got.LastSuccessAt != nil:
				t.Errorf("lastSuccessAt = %s, want none", got.LastSuccessAt)
			case tc.success != nil && got.LastSuccessAt == nil:
				t.Errorf("lastSuccessAt absent, want %s ago", *tc.success)
			case tc.success != nil && !got.LastSuccessAt.Equal(stateNow.Add(-*tc.success)):
				t.Errorf("lastSuccessAt = %s, want %s", got.LastSuccessAt, stateNow.Add(-*tc.success))
			}
			if tc.since != nil {
				if got.OverdueSince == nil || !got.OverdueSince.Equal(*tc.since) {
					t.Errorf("overdueSince = %v, want %s", got.OverdueSince, *tc.since)
				}
			}
			if tc.want != proto.AppBackupOverdue && got.OverdueSince != nil {
				t.Errorf("overdueSince = %s on a %s state", got.OverdueSince, got.State)
			}
			if got.Overdue() != (tc.want == proto.AppBackupOverdue) {
				t.Errorf("Overdue() = %v for %s", got.Overdue(), got.State)
			}
		})
	}
}

func dur(d time.Duration) *time.Duration { return &d }
func tp(t time.Time) *time.Time          { return &t }

// TestFailedAppsGroupsByApp: the report's failed records, grouped per app with
// each app's reason, `critical` first — the structured form of the terminal
// error the Tasks page renders per app.
func TestFailedAppsGroupsByApp(t *testing.T) {
	rep := NewAppVolumeReport(AppEnumeration{AppsInstalled: 3, AppsResolved: 3}, []VolumeRecord{
		{App: "immich", AppID: "app-im", Node: "n-compute", Volume: "immich-upload", Class: "state", Failed: true, Reason: "node n-compute is OFFLINE"},
		{App: "immich", AppID: "app-im", Node: "n-compute", Volume: "immich-db", Class: "state", Failed: true, Reason: "node n-compute is OFFLINE"},
		{App: "paperless", AppID: "app-pl", Node: "n-backup", Volume: "paperless-data", Class: "state", Captured: true},
		{App: "vaultwarden", AppID: "app-vw", Node: "n-backup", Volume: "vaultwarden-data", Class: "critical", Failed: true, Reason: "n-backup refused to stage it (busy): x"},
		{App: "romm", AppID: "app-rm", Node: "n-b", Volume: "romm-db", Class: "state", Failed: true, Reason: "upload did not land"},
		{App: "romm", AppID: "app-rm", Node: "n-b", Volume: "romm-assets", Class: "state", Failed: true, Reason: "budget exhausted"},
	}, 2)
	got := rep.FailedApps()
	if len(got) != 3 {
		t.Fatalf("FailedApps = %+v, want 3 apps", got)
	}
	if got[0].App != "vaultwarden" || got[0].Class != "critical" {
		t.Errorf("first = %+v; critical goes first", got[0])
	}
	if got[1].App != "immich" || len(got[1].Volumes) != 2 || got[1].Reason != "node n-compute is OFFLINE" || got[1].Node != "n-compute" {
		t.Errorf("immich = %+v; two volumes, one reason stated once", got[1])
	}
	if got[2].App != "romm" || got[2].Reason != "upload did not land; budget exhausted" {
		t.Errorf("romm = %+v; two different reasons joined", got[2])
	}

	msg := failedVolumesMessage(got, rep.Failed)
	for _, want := range []string{"BACKUP FAILED FOR 3 APPS", "\n  • vaultwarden on n-backup: vaultwarden/vaultwarden-data — n-backup refused",
		"\n  • immich on n-compute: immich/immich-upload, immich/immich-db — node n-compute is OFFLINE", "romm/romm-db", "§4.4"} {
		if !strings.Contains(msg, want) {
			t.Errorf("terminal message lacks %q:\n%s", want, msg)
		}
	}
	// One app reads as one app, and the fallback with no grouping still
	// names the volumes.
	if one := failedVolumesMessage(got[:1], nil); !strings.HasPrefix(one, "BACKUP FAILED FOR APP vaultwarden") {
		t.Errorf("single-app message = %q", one)
	}
	if flat := failedVolumesMessage(nil, []string{"a/b", "c/d"}); !strings.Contains(flat, "APP VOLUMES a/b, c/d") {
		t.Errorf("flat fallback = %q", flat)
	}
}
