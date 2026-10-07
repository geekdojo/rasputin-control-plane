package tailscale

import "context"

// Backend is the small surface the agent uses to drive tailscale.
type Backend interface {
	// Name returns "tailscale" or "mock".
	Name() string
	// Enroll runs the equivalent of `tailscale up --login-server=... --auth-key=...`.
	Enroll(ctx context.Context, in EnrollInput) (Status, error)
	// Leave logs out and downs the daemon.
	Leave(ctx context.Context) error
	// Status fetches the current daemon state.
	Status(ctx context.Context) (Status, error)
	// TrustFingerprint is the fingerprint of the trust bundle the node holds
	// after an enroll, for the enroll ack.
	TrustFingerprint() string
	// ReloadTrust makes the daemon re-read the trust bundle (tailscaled
	// caches its cert pool at process start). nodetrust calls it after a
	// changed trust.install.
	ReloadTrust(ctx context.Context) error
}

// TrustInstaller is the node's trust bundle (nodetrust.Store), injected into
// the backends. They install through it only for a legacy mesh.enroll that
// carries a bundle from an api older than trust.install.
type TrustInstaller interface {
	Install(bundle []byte) (changed bool, err error)
	Fingerprint() string
}

// EnrollInput captures the parameters for a fresh `tailscale up`.
type EnrollInput struct {
	LoginServer     string
	AuthKey         string
	Hostname        string
	AdvertiseRoutes []string
	AcceptDNS       bool
	AcceptRoutes    bool
	// LegacyTrustBundlePEM, when non-empty, is the trust bundle an api that
	// predates trust.install carries in mesh.enroll; the backend installs it
	// (and restarts tailscaled if it changed) before `tailscale up`. A current
	// api sends the bundle on trust.install first and nothing here.
	LegacyTrustBundlePEM []byte
}

// Status is the small projection of `tailscale status --json` we care about.
type Status struct {
	Enrolled  bool     `json:"enrolled"`
	TailnetID string   `json:"tailnetId,omitempty"`
	TailnetIP string   `json:"tailnetIp,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	Routes    []string `json:"routes,omitempty"`
	PeerCount int      `json:"peerCount,omitempty"`
}
