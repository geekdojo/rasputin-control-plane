package converge

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
)

// RealmIDKey is the setting holding the realm's id, recorded at arming. A
// realm whose id differs is not the one this cluster armed.
const RealmIDKey = "identity.realm_id"

// ArmDeps is everything an Armer needs. NewArmer refuses an incomplete one.
type ArmDeps struct {
	Admin    Admin
	Settings Settings
	// Realm is the realm armed: rasputin.
	Realm string
	// Path is the armed marker (/var/lib/rasputin/identity/armed).
	// CreateArmed creates it once, never replacing it, and fails with
	// fs.ErrExist when it is there (atrest.CreateSecretFile). Stat reads
	// whether it is there (os.Stat).
	Path        string
	CreateArmed func(path string, data []byte) error
	Stat        func(path string) (fs.FileInfo, error)
	Log         *slog.Logger
}

// Armer runs identity.arm: it records the realm's id and creates the armed
// marker. The OS's stage step removes the staged realm import at Keycloak's
// next start once the marker is present (rasputin-os
// identity-stage-import.sh); until then Keycloak's IGNORE_EXISTING import
// skips the existing realm (platform.md §4.1).
type Armer struct {
	d   ArmDeps
	log *slog.Logger
}

// NewArmer checks d and returns an Armer. It does no I/O.
func NewArmer(d ArmDeps) (*Armer, error) {
	if d.Admin == nil || d.Settings == nil || d.CreateArmed == nil || d.Stat == nil || d.Log == nil {
		return nil, errors.New("converge: an arm collaborator is nil")
	}
	if d.Realm == "" || d.Path == "" {
		return nil, errors.New("converge: ArmDeps.Realm or Path is empty")
	}
	return &Armer{d: d, log: d.Log.With("component", "identity")}, nil
}

const (
	errArmRead     = stepError("The sign-in realm could not be read, so it was not armed.")
	errArmSettings = stepError("The recorded sign-in realm id could not be read or stored, so the realm was not fully armed.")
	errArmOther    = stepError("The sign-in realm is not the one this cluster recorded, so it was not armed.")
	errArmMarker   = stepError("The sign-in realm's armed marker could not be created.")
)

// Run is RunJob outside a job.
func (a *Armer) Run(ctx context.Context) error { return a.RunJob(ctx, "") }

// RunJob reads the realm's id, creates the armed marker unless it is there,
// and then records the id when none is recorded. A recorded id that differs
// is refused, and nothing is written.
func (a *Armer) RunJob(ctx context.Context, jobID string) error {
	fail := func(e stepError, msg string, err error) error {
		attrs := []slog.Attr{slog.String("event", "identity.arm.failed"), slog.String("job_id", jobID)}
		if err != nil {
			attrs = append(attrs, slog.String("err", err.Error()))
		}
		a.log.LogAttrs(ctx, slog.LevelError, msg, attrs...)
		return e
	}
	var realm struct {
		ID string `json:"id"`
	}
	if _, err := a.d.Admin.Admin(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(a.d.Realm), nil, &realm); err != nil {
		return fail(errArmRead, "The sign-in realm could not be read for arming.", err)
	}
	if realm.ID == "" {
		return fail(errArmRead, "The sign-in realm answered no id.", nil)
	}
	recorded, err := a.d.Settings.Get(ctx, RealmIDKey)
	if err != nil {
		return fail(errArmSettings, "The recorded sign-in realm id could not be read.", err)
	}
	if recorded != "" && recorded != realm.ID {
		return fail(errArmOther, "The sign-in realm's id differs from the recorded one; nothing was armed.", nil)
	}
	if err := a.d.CreateArmed(a.d.Path, []byte(realm.ID+"\n")); err != nil && !errors.Is(err, fs.ErrExist) {
		return fail(errArmMarker, "The armed marker could not be created.", err)
	}
	if recorded == "" {
		if err := a.d.Settings.Set(ctx, RealmIDKey, realm.ID); err != nil {
			return fail(errArmSettings, "The sign-in realm id could not be recorded.", err)
		}
	}
	a.log.LogAttrs(ctx, slog.LevelInfo, "The sign-in realm is armed.",
		slog.String("event", "identity.arm.armed"), slog.String("job_id", jobID))
	return nil
}

// Pending reports whether arming is due: no realm id recorded, or the marker
// absent. A read that fails is an error.
func (a *Armer) Pending(ctx context.Context) (bool, error) {
	recorded, err := a.d.Settings.Get(ctx, RealmIDKey)
	if err != nil {
		return false, err
	}
	if recorded == "" {
		return true, nil
	}
	_, err = a.d.Stat(a.d.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, err
	}
	return false, nil
}
