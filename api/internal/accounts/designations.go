package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
)

// Reason is why an account holds a designation.
type Reason string

// The reasons (geekdojo/geekdojo-brain#990). first_admin is the first-run
// claim's; moved is Identity 5.1's moved operator; reset is Identity 4.10's;
// repair is the break-glass repair's (#321); grant is any privileged grant
// to an account that does not yet hold a second step and recovery codes
// (C3).
const (
	ReasonFirstAdmin Reason = "first_admin"
	ReasonMoved      Reason = "moved"
	ReasonReset      Reason = "reset"
	ReasonRepair     Reason = "repair"
	ReasonPrivileged Reason = "grant" // a privileged grant (C3)
)

var reasons = []Reason{ReasonFirstAdmin, ReasonMoved, ReasonReset, ReasonRepair, ReasonPrivileged}

// Designation is a role an account will hold once its setup is complete
// (C29): a console role, app access, gear administration, or any of them.
// accounts.grant_designated_role grants it and then clears it.
type Designation struct {
	Sub string
	// ConsoleRole is admin, operator or viewer; "" for none.
	ConsoleRole string
	// AppRole is the app access; "" for none.
	AppRole AppLevel
	// Network is gear-admin, the network grant added to those held; "" for
	// none (geekdojo/geekdojo-brain#994).
	Network   string
	Reason    Reason
	CreatedAt time.Time
}

// Level is one field of a designation: the console role, the app access or
// the network grant.
type Level string

// The levels.
const (
	LevelConsole Level = "console"
	LevelApp     Level = "app"
	LevelNetwork Level = "network"
)

// designationsSchema is the designations table in rasputin.db.
const designationsSchema = `
CREATE TABLE IF NOT EXISTS designations (
    sub          TEXT PRIMARY KEY,         -- the identity service's subject
    console_role TEXT NOT NULL,            -- admin, operator, viewer or ''
    app_role     TEXT NOT NULL,            -- admin, user or ''
    reason       TEXT NOT NULL,            -- first_admin, moved, reset, repair or grant
    created_at   INTEGER NOT NULL          -- unix milliseconds
);
`

// designationsUpgrade adds the network column to a table #990 created
// (geekdojo/geekdojo-brain#994). It runs on every open; on a table that has
// the column it fails with "duplicate column name", which is expected.
const designationsUpgrade = `ALTER TABLE designations ADD COLUMN network TEXT NOT NULL DEFAULT ''`

// Designations is the model service over the designations table: one row
// per designated account. Its callers are the first-run claim
// (DesignateFirstAdmin, in the claim's transaction), the grant workflow and
// its observer, the waiting count, and Identity 5.1, 4.10, 4.12 and #321's
// re-designations (Designate).
type Designations struct {
	db  *sql.DB
	now func() time.Time
}

// OpenDesignations opens the table in the database at dbPath, creating it
// when absent.
func OpenDesignations(ctx context.Context, dbPath string, now func() time.Time) (*Designations, error) {
	if now == nil {
		return nil, errors.New("accounts: OpenDesignations: now is nil")
	}
	db, err := dbutil.Open(ctx, dbPath, designationsSchema, "designations")
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, designationsUpgrade); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		_ = db.Close()
		return nil, fmt.Errorf("designations: upgrade the schema: %w", err)
	}
	return &Designations{db: db, now: now}, nil
}

// Close closes the database.
func (d *Designations) Close() error { return d.db.Close() }

// consoleRank and appRank order the roles, so an upsert keeps the higher.
func consoleRank(role string) (int, bool) {
	switch role {
	case "":
		return 0, true
	case string(authz.Viewer):
		return 1, true
	case string(authz.Operator):
		return 2, true
	case string(authz.Admin):
		return 3, true
	}
	return 0, false
}

func networkRank(grant string) (int, bool) {
	switch grant {
	case "":
		return 0, true
	case authz.NetworkGearAdmin:
		return 1, true
	}
	return 0, false
}

func appRank(level AppLevel) (int, bool) {
	switch level {
	case "":
		return 0, true
	case AppUser:
		return 1, true
	case AppAdmin:
		return 2, true
	}
	return 0, false
}

// Valid reports whether x names an account, known roles (at least one) and
// a known reason.
func (x Designation) Valid() error {
	cr, okC := consoleRank(x.ConsoleRole)
	ar, okA := appRank(x.AppRole)
	nr, okN := networkRank(x.Network)
	switch {
	case x.Sub == "":
		return errors.New("accounts: a designation names no account")
	case !okC || !okA || !okN:
		return errors.New("accounts: a designation names an unknown role")
	case cr == 0 && ar == 0 && nr == 0:
		return errors.New("accounts: a designation names no role")
	}
	for _, r := range reasons {
		if x.Reason == r {
			return nil
		}
	}
	return errors.New("accounts: a designation names an unknown reason")
}

// Designate records x, in a transaction of its own.
func (d *Designations) Designate(ctx context.Context, x Designation) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("accounts: designate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := d.DesignateTx(ctx, tx, x); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("accounts: designate: %w", err)
	}
	return nil
}

// DesignateTx records x inside tx, a transaction on the same database. An
// account already designated keeps the higher of each field, its first
// created_at, and takes x's reason when x raises one. This is the system's
// re-designation (the first-run claim, a reset, a repair, removing second
// steps); an administrator's choice replaces its field instead (Choose,
// F-994-02).
func (d *Designations) DesignateTx(ctx context.Context, tx *sql.Tx, x Designation) error {
	if tx == nil {
		return errors.New("accounts: designate: no transaction")
	}
	if err := x.Valid(); err != nil {
		return err
	}
	old, found, err := get(ctx, tx, x.Sub)
	if err != nil {
		return err
	}
	created := d.now().UTC()
	if found {
		created = old.CreatedAt
		oc, _ := consoleRank(old.ConsoleRole)
		nc, _ := consoleRank(x.ConsoleRole)
		oa, _ := appRank(old.AppRole)
		na, _ := appRank(x.AppRole)
		on, _ := networkRank(old.Network)
		nn, _ := networkRank(x.Network)
		if nc <= oc && na <= oa && nn <= on {
			x.Reason = old.Reason
		}
		if nc < oc {
			x.ConsoleRole = old.ConsoleRole
		}
		if na < oa {
			x.AppRole = old.AppRole
		}
		if nn < on {
			x.Network = old.Network
		}
	}
	return put(ctx, tx, x, created)
}

// execer is the part of *sql.DB and *sql.Tx a write needs.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// put writes x's row as it is.
func put(ctx context.Context, e execer, x Designation, created time.Time) error {
	if _, err := e.ExecContext(ctx, `
        INSERT INTO designations (sub, console_role, app_role, network, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (sub) DO UPDATE SET console_role = excluded.console_role, app_role = excluded.app_role,
            network = excluded.network, reason = excluded.reason, created_at = excluded.created_at`,
		x.Sub, x.ConsoleRole, string(x.AppRole), x.Network, string(x.Reason), created.UnixMilli()); err != nil {
		return fmt.Errorf("accounts: designate: %w", err)
	}
	return nil
}

// set is x with level's field set to value.
func (x Designation) set(level Level, value string) (Designation, error) {
	switch level {
	case LevelConsole:
		x.ConsoleRole = value
	case LevelApp:
		x.AppRole = AppLevel(value)
	case LevelNetwork:
		x.Network = value
	default:
		return Designation{}, fmt.Errorf("accounts: unknown designation level %q", level)
	}
	return x, nil
}

// Choose records an administrator's choice for sub: level's field becomes
// value, whatever it held, so the latest choice wins (F-994-02). The other
// fields, the reason and created_at of a row already there are kept; a new
// row's reason is grant.
func (d *Designations) Choose(ctx context.Context, sub string, level Level, value string) error {
	if value == "" {
		return errors.New("accounts: choose a designation: no value; withdraw it instead")
	}
	return d.change(ctx, sub, func(x Designation, found bool) (Designation, bool, error) {
		if !found {
			x = Designation{Sub: sub, Reason: ReasonPrivileged}
		}
		x, err := x.set(level, value)
		if err == nil {
			err = x.Valid()
		}
		return x, true, err
	})
}

// Withdraw empties level's field of sub's designation, and deletes the row
// when no field is left. An account with no designation has nothing to
// withdraw.
func (d *Designations) Withdraw(ctx context.Context, sub string, level Level) error {
	return d.change(ctx, sub, func(x Designation, found bool) (Designation, bool, error) {
		if !found {
			return x, false, nil
		}
		x, err := x.set(level, "")
		return x, true, err
	})
}

// change reads sub's row in a transaction, lets edit decide the new row,
// and writes it, or deletes it when it holds no field.
func (d *Designations) change(ctx context.Context, sub string, edit func(x Designation, found bool) (Designation, bool, error)) error {
	if sub == "" {
		return errors.New("accounts: change a designation: no account id")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("accounts: change a designation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	old, found, err := get(ctx, tx, sub)
	if err != nil {
		return err
	}
	x, write, err := edit(old, found)
	switch {
	case err != nil:
		return err
	case !write:
		return nil
	case x.ConsoleRole == "" && x.AppRole == "" && x.Network == "":
		if _, err := tx.ExecContext(ctx, `DELETE FROM designations WHERE sub = ?`, sub); err != nil {
			return fmt.Errorf("accounts: change a designation: %w", err)
		}
	default:
		created := old.CreatedAt
		if !found {
			created = d.now().UTC()
		}
		if err := put(ctx, tx, x, created); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("accounts: change a designation: %w", err)
	}
	return nil
}

// DesignateFirstAdmin is the first-run claim's designation, inside the
// claim's transaction (auth.Designator): console role admin and app access
// admin, reason first_admin.
func (d *Designations) DesignateFirstAdmin(ctx context.Context, tx *sql.Tx, sub string) error {
	return d.DesignateTx(ctx, tx, Designation{Sub: sub, ConsoleRole: string(authz.Admin), AppRole: AppAdmin, Reason: ReasonFirstAdmin})
}

// queryer is the part of *sql.DB and *sql.Tx a read needs.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func get(ctx context.Context, q queryer, sub string) (Designation, bool, error) {
	var (
		x       Designation
		app, rs string
		created int64
	)
	err := q.QueryRowContext(ctx, `SELECT sub, console_role, app_role, network, reason, created_at FROM designations WHERE sub = ?`, sub).
		Scan(&x.Sub, &x.ConsoleRole, &app, &x.Network, &rs, &created)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Designation{}, false, nil
	case err != nil:
		return Designation{}, false, fmt.Errorf("accounts: read a designation: %w", err)
	}
	x.AppRole, x.Reason, x.CreatedAt = AppLevel(app), Reason(rs), time.UnixMilli(created).UTC()
	return x, true, nil
}

// Get returns sub's designation, and false when it has none. The row is
// returned as stored; a caller that acts on it checks Valid.
func (d *Designations) Get(ctx context.Context, sub string) (Designation, bool, error) {
	return get(ctx, d.db, sub)
}

// List returns every designation, by account id.
func (d *Designations) List(ctx context.Context) ([]Designation, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT sub, console_role, app_role, network, reason, created_at FROM designations ORDER BY sub`)
	if err != nil {
		return nil, fmt.Errorf("accounts: list designations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Designation
	for rows.Next() {
		var (
			x       Designation
			app, rs string
			created int64
		)
		if err := rows.Scan(&x.Sub, &x.ConsoleRole, &app, &x.Network, &rs, &created); err != nil {
			return nil, fmt.Errorf("accounts: list designations: %w", err)
		}
		x.AppRole, x.Reason, x.CreatedAt = AppLevel(app), Reason(rs), time.UnixMilli(created).UTC()
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("accounts: list designations: %w", err)
	}
	return out, nil
}

// Clear removes sub's designation. One already gone is cleared.
func (d *Designations) Clear(ctx context.Context, sub string) error {
	if sub == "" {
		return errors.New("accounts: clear a designation: no account id")
	}
	if _, err := d.db.ExecContext(ctx, `DELETE FROM designations WHERE sub = ?`, sub); err != nil {
		return fmt.Errorf("accounts: clear a designation: %w", err)
	}
	return nil
}
