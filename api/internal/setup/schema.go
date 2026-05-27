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
)
