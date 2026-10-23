package sealrotate

// jobError is an error whose text is a fixed sentence a person reads: the
// runner records a failed step's err.Error() as the job's error and as the
// detail of its job-failed alert, so the text is a sentence and carries no
// path, store text or key material (ERR-MESSAGE, LOG-SECRETS). The detail
// goes to the injected logger under the job's id. storeaudit's precedent.
type jobError string

func (e jobError) Error() string { return string(e) }

// The refusals. Each leaves every seal file as it was.
const (
	errNotOpenBao       jobError = "The seal key can be rotated only when this control plane runs its own secret store, so nothing was changed."
	errRestoreActive    jobError = "A restore is running, so the seal key was not rotated. Nothing was changed; start the rotation again once the restore finishes."
	errSealUnrecognised jobError = "The seal key files are not in a state a rotation recognises, so nothing was changed. The api log names the file and the defect."
	errStoreNotReady    jobError = "The secret store is not running and unsealed, so the seal key was not rotated. Nothing was changed."
	errBackupHolds      jobError = "A backup is capturing the secret store, so the seal key was not rotated. Nothing was changed; start the rotation again once the backup finishes."
	errAnotherRotation  jobError = "Another seal-key rotation is running, so this one did not start. Nothing was changed."
	errLoginDenied      jobError = "The secret store refused the rotation's login, so the seal key was not rotated. Nothing was changed."
	errLoginUnreachable jobError = "The secret store could not be reached to log in for the rotation, so the seal key was not rotated. Nothing was changed."
	// errNoKeyID and errNoKey fail the stage step before it writes anything
	// (F-830-07).
	errNoKeyID jobError = "A new seal key id could not be made, so the seal key was not rotated. Nothing was changed."
	errNoKey   jobError = "A new seal key could not be generated, so the seal key was not rotated. Nothing was changed."
)

// The failures after a write.
const (
	errStageWrite           jobError = "The new seal key could not be staged, so the seal key was not rotated. The staged key was removed and the old key is still in use."
	errStagedRolledBack     jobError = "The secret store did not open with the new seal key staged, so the rotation was rolled back and the old key is still in use."
	errStagedRollbackFailed jobError = "The secret store did not open with the new seal key staged, and the rotation could not be rolled back. Start the seal-key rotation again to finish it."
	errStagedResume         jobError = "The secret store did not open with the staged seal key, so the rotation could not be finished. Start the seal-key rotation again to finish it."
	errRewrapLogin          jobError = "The secret store refused the rotation's login, so the rotation stopped with both keys in place. Start the seal-key rotation again to finish it, and do not restart the node or the secret store until it has finished."
	errRewrap               jobError = "The secret store did not re-encrypt its root key under the new seal key, so the rotation stopped with both keys in place. Start the seal-key rotation again to finish it, and do not restart the node or the secret store until it has finished."
	errVerify               jobError = "The secret store did not open with the new seal key alone, so the rotation stopped before the old key was removed. Start the seal-key rotation again to finish it."
	errSettle               jobError = "The new seal key could not be made the only key, so the rotation stopped part way. Start the seal-key rotation again to finish it."
)

// The gate's refusals of a backup.
const (
	errBackupRotationIncomplete jobError = "A seal-key rotation has not finished, so this backup did not capture anything. Start the seal-key rotation again to finish it, then run the backup."
	errBackupSealUnreadable     jobError = "The seal key files could not be checked, so this backup did not capture anything. The api log names the defect."
)

// UpdateCopyRefused opens every sentence that refuses an OS update because
// the secret store could not be copied first (geekdojo/geekdojo-brain#800):
// the gate's below and storage.PreUpdateCopier's.
const UpdateCopyRefused = "The secret store could not be copied before this OS update, so the update was refused and nothing was installed."

// The gate's refusals of an OS update's pre-update copy, and of a rotation
// tried while that copy holds the gate (geekdojo/geekdojo-brain#800).
const (
	errUpdateRotationIncomplete jobError = UpdateCopyRefused + " A seal-key rotation has not finished: start the seal-key rotation again to finish it, then run the update again."
	errUpdateSealUnreadable     jobError = UpdateCopyRefused + " The seal key files could not be checked; the api log names the defect."
	errUpdateHolds              jobError = "An OS update is copying the secret store, so the seal key was not rotated. Nothing was changed; start the rotation again once the update's copy finishes."
)

// The gate's refusals of a restore (geekdojo/geekdojo-brain#765).
const (
	errRestoreRotation           jobError = "A seal-key rotation is running, so this restore did not start. Nothing was changed; start the restore again once the rotation finishes."
	errRestoreRotationIncomplete jobError = "A seal-key rotation has not finished, so this restore did not start. Nothing was changed; start the seal-key rotation again to finish it, then start the restore."
	errRestoreSealUnreadable     jobError = "The seal key files could not be checked, so this restore did not start. Nothing was changed; the api log names the defect."
)
