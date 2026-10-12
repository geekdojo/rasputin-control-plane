package storeaudit

// jobError is an error whose text is a fixed sentence a person reads: the
// runner stores a failed step's err.Error() as the job's error and as the
// detail of its job-failed alert (jobs.Runner.run), so that text must be safe
// to show and written as a sentence (ERR-BOUNDARY, ERR-MESSAGE). It never
// carries a path or an OS error; those go to the injected logger, under the
// job's id. The string type follows the auth package's httpError precedent.
type jobError string

func (e jobError) Error() string { return string(e) }

// One sentence per failure, each describing that failure and no other
// (geekdojo/geekdojo-brain#799, the plan's Errors and logging table).
const (
	// errNotMoved: the live file could not be read, or linked aside, or its
	// old name could not be removed. Nothing was signalled.
	errNotMoved jobError = "The audit file could not be moved aside, so it was not rotated."
	// errRolledBack: the signal or the wait for the reopen failed, and the
	// copy was put back at the live path.
	errRolledBack jobError = "The secret store did not reopen its audit file, so the rotation was rolled back."
	// errRollbackFailed: the signal or the wait failed and the copy could not
	// be put back. The store keeps appending to the copy's inode.
	errRollbackFailed jobError = "The secret store did not reopen its audit file, and the rotation could not be rolled back. The store is still writing to a rotated copy."
	// errPruneFailed: a rotated copy the cap selected could not be removed.
	errPruneFailed jobError = "Old audit copies could not be removed, so the audit log is over its size cap."
	// errListFailed: the audit directory could not be listed, so neither the
	// next copy's number nor the copies to remove could be worked out.
	errListFailed jobError = "The audit copies could not be listed, so none were removed."
)
