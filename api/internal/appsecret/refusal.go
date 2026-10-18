package appsecret

// The stable codes a StoreSource refusal carries
// (geekdojo/geekdojo-brain#762).
const (
	// CodeStoreUnavailable: a store call made while resolving the compose
	// failed (sealed, unreachable, timed out, denied, or an answer the client
	// does not accept).
	CodeStoreUnavailable = "secret_store_unavailable"
	// CodeValueConflict: an entry created from the derived value reads back
	// as a different value.
	CodeValueConflict = "secret_value_conflict"
)

// Refusal is StoreSource's refusal of a compose: a fixed sentence a person
// reads and a stable code. The push step records it as it is (it satisfies
// apps' coded refusal), so the job's error is the sentence and never the
// store's own text, which goes to the log only. Unwrap returns the store
// error, so errors.Is still reaches its kind; the readiness Gate's
// audit-blocked probe relies on that to tell a client timeout.
type Refusal struct {
	code     string
	sentence string
	err      error
}

// Error is the sentence. It names no store, path, status or vendor.
func (r *Refusal) Error() string { return r.sentence }

// Code is the stable refusal code.
func (r *Refusal) Code() string { return r.code }

// Unwrap is the store error behind the refusal, or nil.
func (r *Refusal) Unwrap() error { return r.err }

// storeUnavailable is the refusal for a failed store call.
func storeUnavailable(err error) *Refusal {
	return &Refusal{code: CodeStoreUnavailable, err: err, sentence: "The secret store could not serve this app's secrets, " +
		"so the app was not deployed. Its running containers are unchanged; deploy the app again once the store is working. " +
		"The api log names the cause. Error code: " + CodeStoreUnavailable + "."}
}

// valueConflict is the refusal for a read-back that does not match.
func valueConflict() *Refusal {
	return &Refusal{code: CodeValueConflict, sentence: "A secret stored for this app does not match the value the control plane " +
		"derives for it, so the app was not deployed. Its running containers are unchanged. " +
		"The api log names the secret. Error code: " + CodeValueConflict + "."}
}
