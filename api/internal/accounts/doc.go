// Package accounts changes people's accounts at the identity service
// (geekdojo/geekdojo-brain#991, Identity 4.9, and the account kinds of
// Identity 4.10 and 4.12 that build on it).
//
// Users is the model service over the identity service's Admin API for one
// person's account. Revoker is the identity.revoke job: ending a person's
// access, in a fixed order, each step a recorded outcome. Access is the
// giving side of app access. RoleAccounts is what authz.RoleGuard reads
// accounts through. Identity 4.10's administrator reset is Resetter (the
// request's check), ResetAction (its fresh-sign-in action) and
// ResetPasswordWorkflow (accounts.reset_password), whose temporary password
// travels beside the job in Held, never in its spec.
//
// Every account change runs under the one accounts lock, which is not
// re-entrant. No log record, job-log line, step outcome or error sentence
// here carries a sign-in name, an email or an account id: an Admin API
// error names the account in its path, so only its status and kind are
// logged.
package accounts
