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
}

// EnrollInput captures the parameters for a fresh `tailscale up`.
type EnrollInput struct {
	LoginServer     string
	AuthKey         string
	Hostname        string
	AdvertiseRoutes []string
	AcceptDNS       bool
	AcceptRoutes    bool
	// MeshCAPEM, when non-empty, is the per-installation Mesh CA root the
	// node must trust before tailscaled dials the self-hosted Headscale's
	// HTTPS leaf. The real backend installs it into tailscaled's trust
	// bundle (and restarts the daemon if the bundle changed) before
	// `tailscale up`. Empty for plain-HTTP dev or a publicly trusted cert.
	MeshCAPEM []byte
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
