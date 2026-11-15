package identitystate

// State is the identity service's state as the api sees it
// (lifecycle.md §5.1).
type State string

// The states, and Ready. Every state but Ready, AppsPaused and HistoryBehind
// refuses console identity work (Blocks).
const (
	Ready State = "ready"
	// Starting: Keycloak's unit is activating (its ExecStartPost= waits for
	// /health/started), or active and /health/ready does not say UP.
	Starting State = "starting"
	// Upgrading: as Starting while activating, and the version marker
	// differs from the last version seen ready.
	Upgrading State = "upgrading"
	// Paused: a running job holds the quiesce and the service is not ready.
	Paused State = "paused"
	// DatabaseDown: the database unit is not running, or /health/ready names
	// its database check DOWN (capability row K-HEALTH).
	DatabaseDown State = "database-down"
	// Held: the version gate refused or failed, or the start hold refused a
	// start.
	Held State = "held"
	// OutOfMemory: the run the last exit record ends ran out of memory
	// (capability row K-OOMEXIT, or systemd's oom-kill), and the unit is not
	// active.
	OutOfMemory State = "out-of-memory"
	// Failed: the unit failed, or the last run ended other than by an
	// orderly stop or running out of memory.
	Failed State = "failed"
	// Unreachable: the unit is active, and the call was refused at TLS or
	// answered with something that is not the health JSON.
	Unreachable State = "unreachable"
	// Blank: the service's database started empty on a cluster that has
	// accounts (Identity 5.7).
	Blank State = "blank"
	// AppsPaused: app-tier secrets are not materialised yet (Identity 7.3).
	AppsPaused State = "apps-paused"
	// HistoryBehind: the last sign-in history drain failed (Identity 4.3).
	HistoryBehind State = "history-behind"
)

// Blocks reports whether the state refuses console identity work.
func (s State) Blocks() bool {
	switch s {
	case Ready, AppsPaused, HistoryBehind:
		return false
	}
	return true
}

// critical reports whether the state's alert is critical rather than a
// warning (lifecycle.md §5.1).
func (s State) critical() bool {
	switch s {
	case Starting, Upgrading, Paused, AppsPaused, HistoryBehind:
		return false
	}
	return true
}

// sentence is the state's §5.1 sentence: the alert's title, and the start of
// NotReadyError's text. It never names a vendor.
func (s State) sentence() string {
	switch s {
	case Starting:
		return "Sign-in is starting up."
	case Upgrading:
		return "Sign-in is being upgraded after an update. This can take a few minutes."
	case Paused:
		return "Sign-in is paused while the control plane copies its accounts."
	case DatabaseDown:
		return "Sign-in is unavailable because its database is not running."
	case Held:
		return "Sign-in is held stopped until its cause is fixed."
	case OutOfMemory:
		return "Sign-in stopped because the sign-in service ran out of memory. It restarts by itself."
	case Failed:
		return "Sign-in is unavailable because the sign-in service could not start."
	case Unreachable:
		return "Sign-in is unavailable because the control plane cannot reach its sign-in service securely."
	case Blank:
		return "Sign-in data is missing: the sign-in service's database started empty on a cluster that has accounts. Restore a backup."
	case AppsPaused:
		return "Sign-in to apps is paused until the secret store is ready."
	case HistoryBehind:
		return "Sign-in history is not being recorded."
	}
	return "Sign-in is not ready."
}
