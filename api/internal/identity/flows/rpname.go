package flows

// rpName is the passkey relying-party name on every cluster (the
// 2026-11-23 decision under Bryce's delegation: the fixed word Rasputin).
// It is display text only: a passkey is scoped to its RP ID, never its name.
const rpName = "Rasputin"

// RPName is the passkey relying-party name both WebAuthn policies carry.
// It is the fixed word Rasputin for every input, and never empty, so
// Keycloak never resets a policy for a blank name.
func RPName(Inputs) string { return rpName }
