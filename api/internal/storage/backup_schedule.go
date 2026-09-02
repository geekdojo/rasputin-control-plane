package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// design/storage.md §4.1's cadence: "Default cadence weekly, overridable per
// installation", plus the on-demand "Back up now" that has no cadence at all.
//
// # Why the schedule is an ELAPSED-TIME rule and not a calendar
//
// The gate below asks one question: has it been at least `Every` since the last
// SUCCESSFUL run? Not "is it Sunday at 3 a.m.". Two reasons, and the second is
// the load-bearing one.
//
// First, the api's scheduler is an interval ticker with an in-memory schedule
// (see scheduler.go's own header) — there is no cron, and adding one to serve
// one entry would be the wrong shape of change.
//
// Second, and this is the property that matters: an elapsed-time rule CATCHES
// UP. A calendar rule fires at a moment, and an appliance that was powered off,
// mid-update, or booted five minutes after the window simply misses that week —
// silently, because nothing failed. The elapsed rule notices on the next check
// that eight days have passed and runs. For a home appliance that is turned off
// for a fortnight's holiday, that difference is the whole feature.
//
// The cost, stated plainly: the run happens at whatever hour the previous one
// finished, drifting forward. §4.1's "weekly 3 a.m." intent is therefore
// approximated rather than met, and a time-of-day window is future work — it
// belongs with the alerting slice (#298) that also wants to know when a backup
// SHOULD have happened.
//
// # Where the setting lives
//
// In the settings table alongside every other operator preference, under the
// `backup.` prefix that table's convention reserves for a subsystem. Read on
// every gate check rather than cached, so a change takes effect on the next
// tick instead of on the next api restart — a backup cadence change is not
// worth an outage.

// KeyBackupSchedule is the settings key holding the operator's cadence
// override. Absent means the default.
const KeyBackupSchedule = "backup.schedule"

// DefaultBackupCadence is §4.1's default: weekly.
const DefaultBackupCadence = 7 * 24 * time.Hour

// MinBackupCadence is the floor an override may set.
//
// An hour, and it is a guard rather than a preference: every run is a FULL
// (§4.1), stages a copy of the identity set on the partition §5's budget table
// is about, and writes a generation to a disk that retains four. A cadence of
// minutes would keep the appliance permanently staging and would cycle the
// retained set so fast that four generations covered under an hour of history —
// which is the opposite of what §4.4's retention is for.
const MinBackupCadence = time.Hour

// MaxBackupCadence is the ceiling: a year. Past that the setting is indis-
// tinguishable from "off", and if an operator wants backups off they should be
// able to say so in words rather than by typing a large number.
const MaxBackupCadence = 365 * 24 * time.Hour

// BackupSchedule is the operator's cadence choice.
type BackupSchedule struct {
	// Enabled is the operator's on/off switch for the SCHEDULE only. False
	// stops the weekly run; "Back up now" still works, and §4.4's loudness is
	// unaffected — a disabled schedule is a thing the UI must show, not a thing
	// that makes the absence of backups quiet.
	Enabled bool `json:"enabled"`
	// Every is the cadence, as a Go duration string ("168h"). Empty means
	// DefaultBackupCadence.
	Every string `json:"every,omitempty"`
}

// ErrInvalidCadence rejects a cadence outside the bounds above.
var ErrInvalidCadence = fmt.Errorf("backup cadence must be a duration between %s and %s", MinBackupCadence, MaxBackupCadence)

// Interval resolves the schedule's cadence, falling back to the default for an
// empty or unparseable value.
//
// Falls back rather than erroring, deliberately: this is called from the
// scheduler's gate, and a corrupt settings value must not be able to turn
// backups off. A bad value that read as "never" would be an outage nobody sees
// until they need a restore. SetBackupSchedule is where a bad value is refused.
func (s BackupSchedule) Interval() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s.Every))
	if err != nil || d < MinBackupCadence || d > MaxBackupCadence {
		return DefaultBackupCadence
	}
	return d
}

// ValidateBackupSchedule checks an operator-supplied schedule.
func ValidateBackupSchedule(s BackupSchedule) (BackupSchedule, error) {
	s.Every = strings.TrimSpace(s.Every)
	if s.Every == "" {
		s.Every = DefaultBackupCadence.String()
		return s, nil
	}
	d, err := time.ParseDuration(s.Every)
	if err != nil {
		return BackupSchedule{}, fmt.Errorf("%w: %v", ErrInvalidCadence, err)
	}
	if d < MinBackupCadence || d > MaxBackupCadence {
		return BackupSchedule{}, ErrInvalidCadence
	}
	s.Every = d.String()
	return s, nil
}

// ScheduleSettings is the slice of the settings store this package needs. An
// interface rather than a *setup.Store so api/internal/storage does not import
// api/internal/setup — a dependency it has no other reason to have, and one
// that would point the wrong way for a package the setup wizard may later want
// to read from.
type ScheduleSettings interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// GetBackupSchedule reads the operator's choice, or the default when unset.
//
// The default has Enabled TRUE. §4.1 makes the weekly run the product's
// behaviour, not an opt-in — and §4.6 records why the alternative is
// unacceptable: an appliance whose owner believes it is backing up and is not
// is worse than one with no backup at all. An operator turning it off is a
// decision they make; it is not a state they can arrive at by never having
// looked at the setting.
func GetBackupSchedule(ctx context.Context, st ScheduleSettings, defaultEnabled bool) (BackupSchedule, error) {
	if st == nil {
		return BackupSchedule{Enabled: defaultEnabled, Every: DefaultBackupCadence.String()}, nil
	}
	raw, err := st.Get(ctx, KeyBackupSchedule)
	if err != nil {
		return BackupSchedule{}, err
	}
	if strings.TrimSpace(raw) == "" {
		return BackupSchedule{Enabled: defaultEnabled, Every: DefaultBackupCadence.String()}, nil
	}
	var s BackupSchedule
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return BackupSchedule{}, fmt.Errorf("corrupt %s value: %w", KeyBackupSchedule, err)
	}
	if strings.TrimSpace(s.Every) == "" {
		s.Every = DefaultBackupCadence.String()
	}
	return s, nil
}

// SetBackupSchedule validates and persists the operator's choice.
func SetBackupSchedule(ctx context.Context, st ScheduleSettings, s BackupSchedule) (BackupSchedule, error) {
	if st == nil {
		return BackupSchedule{}, errors.New("no settings store: this api cannot persist a backup schedule")
	}
	v, err := ValidateBackupSchedule(s)
	if err != nil {
		return BackupSchedule{}, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return BackupSchedule{}, err
	}
	if err := st.Set(ctx, KeyBackupSchedule, string(raw)); err != nil {
		return BackupSchedule{}, err
	}
	return v, nil
}

// DueFunc builds the scheduler gate for backup.run.
//
// The gate answers "has it been at least `Every` since the last SUCCESS?", and
// every branch of it is a decision worth naming:
//
//   - schedule disabled → not due, and the reason says so, so a log reader can
//     tell a disabled schedule from a broken one;
//   - a run already in flight → not due, because the saga's own step 1 would
//     refuse it and a refused job in the feed every check interval is noise
//     that would bury the failures §4.4 wants visible;
//   - no successful run EVER → DUE. A fresh installation with a claimed target
//     should get its first backup on the next check rather than a week later;
//   - a settings read that fails → not due, with the error as the reason. A
//     scheduler cannot decide what a failed policy lookup means, and firing
//     anyway would submit a job the policy might have forbidden.
func DueFunc(store *Store, st ScheduleSettings, defaultEnabled bool) func(context.Context) (bool, string) {
	return func(ctx context.Context) (bool, string) {
		sched, err := GetBackupSchedule(ctx, st, defaultEnabled)
		if err != nil {
			return false, fmt.Sprintf("could not read the backup schedule: %v", err)
		}
		if !sched.Enabled {
			return false, "the backup schedule is turned off"
		}
		running, err := store.ListRunning(ctx)
		if err != nil {
			return false, fmt.Sprintf("could not read in-flight runs: %v", err)
		}
		if len(running) > 0 {
			return false, fmt.Sprintf("a backup is already running (job %s)", running[0].JobID)
		}
		last, err := store.LastSuccess(ctx)
		if err != nil {
			return false, fmt.Sprintf("could not read the last successful run: %v", err)
		}
		every := sched.Interval()
		if last == nil || last.FinishedAt == nil {
			return true, "no backup has ever succeeded on this installation"
		}
		since := time.Since(*last.FinishedAt)
		if since < every {
			return false, ""
		}
		return true, fmt.Sprintf("the last successful backup was %s ago (cadence %s)", since.Truncate(time.Minute), every)
	}
}
