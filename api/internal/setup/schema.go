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
	// KeyObsEnabled holds the operator's observability opt-in. Same species
	// as KeyMode: a stored *intent*, not a derived fact — a stopped stack
	// is indistinguishable from one that was never meant to run, so no
	// probe can answer it. Seeded once from RASPUTIN_OBS_ENABLED so
	// existing dev runs keep working; after that an explicit operator
	// choice wins and is never re-seeded over, because two sources of
	// truth would disagree the moment someone used the UI toggle.
	// See wiki design/control-plane/observability-stack.md §3.8.
	KeyObsEnabled = "obs.enabled"
)
