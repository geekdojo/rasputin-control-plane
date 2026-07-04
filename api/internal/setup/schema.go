package setup

const schema = `
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);
`

// Keys used by the setup wizard. Other subsystems can write to this table
// too; the convention is dotted lowercase keys with a subsystem prefix
// ("setup.install_name", "ui.theme", etc.) to avoid collisions.
const (
	KeyInstallName       = "setup.install_name"
	KeyWizardCompletedAt = "setup.wizard_completed_at"
	// KeyMode holds the operator-chosen deployment topology (see mode.go).
	// Unlike every other wizard fact, this is a stored *intent* that can't
	// be derived from a subsystem probe — it's the single source of truth
	// every mode-gated subsystem (firewall apply, IDS, DHCP, mesh advertise,
	// UI SideNav) reads.
	KeyMode = "setup.mode"
)
