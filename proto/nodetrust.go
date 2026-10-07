package proto

// Node trust delivery (geekdojo/geekdojo-brain#741).
//
// The bundle a node trusts reaches it on a verb of its own, trust.install,
// rather than inside mesh.enroll: trust is not a mesh concern (the agent's
// HTTPS clients need it whether or not the node is on the tailnet), and
// re-delivering it through mesh.enroll re-ran `tailscale up --reset` on every
// refresh. The api's trust.converge sends it to every online node whose
// reported MetadataTrustFingerprint differs from the api's bundle.
//
// An agent that predates the verb has no subscription for it and draws no
// responder; for those, and only those, the api still carries the bundle in
// MeshEnrollCmd.LegacyTrustBundlePEM.

// TrustInstallVerb is the agent command that installs the node's trust
// bundle: rasputin.node.<id>.cmd.trust.install.
const TrustInstallVerb = "trust.install"

// TrustInstallSubject is the cmd subject for trust.install on nodeID.
func TrustInstallSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, TrustInstallVerb)
}

// TrustInstallCmd carries the bundle. Public material: CA certificates only.
type TrustInstallCmd struct {
	// BundlePEM is the concatenated CA certificates the node must trust.
	BundlePEM []byte `json:"bundlePem"`
}

// TrustInstallAck is the agent's answer.
//
// OK means the bundle is on disk AND every consumer that caches it
// (tailscaled) has reloaded it. A bundle that was written but not reloaded is
// OK=false, with Detail saying so, and the agent reports
// TrustFingerprintReloadPending until a later install reloads it.
type TrustInstallAck struct {
	NodeID string `json:"nodeId"`
	OK     bool   `json:"ok"`
	// Fingerprint is what the node reports now (TrustFingerprint of the file
	// it holds, or TrustFingerprintReloadPending).
	Fingerprint string `json:"fingerprint,omitempty"`
	// Changed is true when the file's content changed on this install.
	Changed bool   `json:"changed"`
	Detail  string `json:"detail,omitempty"`
}
