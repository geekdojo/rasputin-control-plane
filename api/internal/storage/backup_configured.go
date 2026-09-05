package storage

import "context"

// Configured answers the install-time gate's one question (design/storage.md
// §4.4, geekdojo/geekdojo-brain#299): is there anywhere for a backup to go,
// and is one scheduled? It is the same judgement AppBackupStates makes before
// it decides anything else — a claimed target AND a schedule that is on — so
// the gate an install is held at and the NO BACKUP TARGET nag the installed
// app then carries cannot disagree about what "configured" means. The reason
// is the derivation's own sentence, the one the app row's `backup.reason`
// carries, so the install dialog and the drawer say the same thing.
func (b *BackupStates) Configured(ctx context.Context) (configured bool, reason string, err error) {
	if b == nil || b.store == nil {
		// No ledger wired: the api cannot say. The rows say "unknown" for
		// the same reason (the backup field is absent), and a gate that
		// asserted "no target" here would be inventing a fact.
		return true, "", nil
	}
	configured, reason, _, err = b.configuration(ctx)
	return configured, reason, err
}
