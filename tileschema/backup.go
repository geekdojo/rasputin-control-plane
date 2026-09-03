package tileschema

import "strings"

// Backup classification and quiescing, storage.md §4.2 and §4.3.
//
// This file is the contract half of the 2026-08-23 revision that took backup
// from an opt-in checkbox per app to a DECLARED, schema-enforced property of
// every volume. The revision's own words for why the checkbox was wrong: a
// password vault whose backup is off by default is worse than no vault,
// because the user believes they have one.
//
// TWO ENUMS, TWO QUESTIONS. The class answers "is this worth keeping, and how
// badly" — a retention and consent question the owner has an opinion about.
// The strategy answers "what does it take to copy this consistently" — a
// storage-engine question the owner does not, and should not have to. They are
// declared side by side on the same volume because both are per-volume facts,
// and kept as separate fields because they are answerable by different people
// for different reasons.
//
// THERE IS NO DEFAULT FOR EITHER, DELIBERATELY (§4.2). A default is silently
// correct for the seventeen tiles where it does not matter and silently wrong
// for the one where it does — the same shape as a default only the bench ever
// exercises. So an absent field is a REFUSAL and not an inference: nothing here
// reads the volume's name, guesses from the class, or lets an empty string pass
// as a value. The one thing a validator can do that a reviewer cannot is refuse
// to proceed while a question is unanswered, and that is the whole of what this
// file does.
//
// WHY NO Requires CAPABILITY, unlike the privilege tiers (Decision 12d). The
// question that decides it is what an OLDER control plane does with a tile
// carrying these fields, and the answer is: it ignores them and backs up no app
// volumes — which is exactly what EVERY build does today, out loud. Every
// archive this build writes is stamped proto.BackupScopeIdentityOnly in its
// generation id, its manifest, the ledger and the UI, precisely so that
// "captures no app data" can never be mistaken for a full backup. An older
// reader therefore degrades to a state that is already named and already
// visible, not to a silent one, and Requires exists for silent degradation.
//
// The cost of the other choice is what settles it. Unlike privilege — where
// only the handful of non-routine tiles name the capability — nearly every tile
// in the catalog has a volume, so requiring it would have #293 publish a corpus
// that every cluster in the field refuses tile by tile until the whole bundle
// is refused for having nothing left in it. That is a catalog outage to
// communicate "these apps now say where their data lives".

// The four backup classes (§4.2). Stable machine strings: the catalog declares
// them, the backup job branches on them and the UI renders them, so changing
// one is a contract change and not a copy edit.
const (
	// BackupCritical is unrecoverable state whose STALENESS IS ITSELF HARMFUL
	// — secrets, credentials, keys. Always backed up, and not
	// user-disableable. vaultwarden-data is the archetype.
	BackupCritical = "critical"
	// BackupState is irreplaceable app state: always backed up by default,
	// but the owner may exclude it.
	BackupState = "state"
	// BackupCache is a regenerable index, queue or model cache. NEVER copied
	// — see the quiesce rule in ValidateTile for what that implies.
	BackupCache = "cache"
	// BackupBulk is a user media library, potentially terabytes. Opt-in per
	// app, because a weekly full of it is not a default anyone chose.
	BackupBulk = "bulk"
)

// BackupClasses is the closed vocabulary, in the order §4.2 presents it —
// roughly descending consequence-of-loss. Ordered because it is what error
// messages, and later the authoring docs, enumerate.
var BackupClasses = []string{BackupCritical, BackupState, BackupCache, BackupBulk}

// The five quiesce strategies (§4.3). The axis of variation is the storage
// ENGINE, not the app: classification deletes most of the engines before they
// become a problem, leaving three drivers across eighteen tiles.
const (
	// QuiesceNone is a plain copy — static config, or a volume nothing is
	// writing while the archive runs.
	QuiesceNone = "none"
	// QuiesceStop stops the service, copies, and restarts it. §4.3 makes this
	// the strategy of choice rather than a fallback: a clean shutdown is a
	// STRONGER consistency guarantee than a dump and requires the agent to
	// know nothing whatsoever about the engine.
	QuiesceStop = "stop"
	// QuiesceSQLite runs `sqlite3 .backup` against the declared DB paths with
	// the app still up.
	QuiesceSQLite = "sqlite"
	// QuiescePostgres runs pg_dump against the declared service.
	QuiescePostgres = "postgres"
	// QuiesceMySQL runs `mariadb-dump --single-transaction`.
	QuiesceMySQL = "mysql"
)

// QuiesceStrategies is the closed vocabulary, ordered cheapest-to-implement
// first — which is also the order §4.3 argues for choosing between them.
var QuiesceStrategies = []string{QuiesceNone, QuiesceStop, QuiesceSQLite, QuiescePostgres, QuiesceMySQL}

// ValidBackupClass and ValidQuiesce are the membership tests, DERIVED from the
// ordered slices above so the set a validator checks and the list an error
// message prints cannot drift apart. The failure that would cause is
// particularly nasty — a value the schema accepts but no message offers, or
// worse the reverse — and it is entirely avoidable by not writing the
// vocabulary down twice.
var (
	ValidBackupClass = closedSet(BackupClasses)
	ValidQuiesce     = closedSet(QuiesceStrategies)
)

func closedSet(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// Volume is one named data volume a tile declares, with the two facts the
// backup job needs to act on it.
//
// It is AUTHORED metadata and nothing derives it, which is the difference
// between this and Privilege. A compose file says a volume exists; it cannot
// say whether losing it costs the owner an afternoon or their password vault.
// That judgement is the tile author's, made once at authoring time, reviewed
// like any other line of the tile — and §4.2's insistence that it be mandatory
// is what stops it being made by accident at 3 a.m. by whatever the default was.
type Volume struct {
	// Name is the compose volume this classification applies to. Required, and
	// unique within the tile: a class attached to an ambiguous name is a class
	// attached to nothing.
	//
	// NOT constrained to a DNS label like Tile.ID. This value has to match what
	// the compose stack already calls the volume, and compose names legally
	// carry underscores; a shape rule here would refuse correct tiles in order
	// to enforce a convention no consumer of this field needs.
	Name string `json:"name"`

	// Backup is the class, from BackupClasses. Required, no default.
	Backup string `json:"backup"`

	// Quiesce is the strategy, from QuiesceStrategies. Required, no default —
	// including for the classes that are never copied, where the honest
	// declaration is an explicit "none" rather than an absent field that could
	// equally mean nobody thought about it.
	Quiesce string `json:"quiesce"`
}

// legalValues renders a closed vocabulary the way every other message in this
// package does, so "not one of a|b|c" reads identically wherever it appears.
func legalValues(values []string) string { return strings.Join(values, "|") }
