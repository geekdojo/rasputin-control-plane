package setup

import (
	"context"
	"strings"
	"time"
)

// Step is one cell on the wizard's progress board. Done is derived live;
// callers should not cache it across requests.
type Step struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Done     bool   `json:"done"`
	Required bool   `json:"required"`
	Detail   string `json:"detail,omitempty"`
}

// State is the wizard's full snapshot. Returned by GET /api/setup/state.
type State struct {
	Steps           []Step     `json:"steps"`
	Completed       bool       `json:"completed"`
	CompletedAt     *time.Time `json:"completedAt,omitempty"`
	InstallName     string     `json:"installName"`
	HasUsers        bool       `json:"hasUsers"`
	TrustConfigured bool       `json:"trustConfigured"`
	MeshEnrolled    bool       `json:"meshEnrolled"`
	SelfNodeID      string     `json:"selfNodeId"`
	// Mode is the operator-chosen deployment topology ("" until picked).
	Mode Mode `json:"mode"`
	// FirewallCapable reports whether a firewall-capable node is registered,
	// i.e. whether the router / sub-segment modes are offerable. Lets the UI
	// pre-gate the choice (and show the "add a firewall node" upsell) instead
	// of surfacing a mode that would 412 on submit.
	FirewallCapable bool `json:"firewallCapable"`
}

// Probes is the small set of cross-subsystem queries the service uses to
// derive step state. Keeping it an interface (rather than importing each
// subsystem's Store) means main wires concrete probes — no import cycles
// and the setup package stays narrow.
type Probes struct {
	// HasUsers reports whether at least one operator passkey has been
	// registered.
	HasUsers func(ctx context.Context) (bool, error)
	// TrustConfigured reports whether the api was loaded with a real
	// root CA cert (vs. the dev-permissive fallback).
	TrustConfigured func() bool
	// MeshEnrolled reports whether the api's self node is recorded as a
	// Rasputin-kind device in the mesh tailnet.
	MeshEnrolled func(ctx context.Context, selfNodeID string) (bool, error)
	// HasFirewallNode reports whether a firewall-role node is registered in
	// inventory. Drives the deployment-mode hardware gate — the router and
	// sub-segment modes are only offerable when this is true.
	HasFirewallNode func(ctx context.Context) (bool, error)
}

// Service is the wizard coordinator. Constructed in main with the probes
// wired against concrete subsystems.
type Service struct {
	store      *Store
	probes     Probes
	selfNodeID string
}

func NewService(store *Store, probes Probes, selfNodeID string) *Service {
	return &Service{store: store, probes: probes, selfNodeID: selfNodeID}
}

// GetState computes the live wizard state. Cheap — one settings lookup
// plus three probe calls.
func (s *Service) GetState(ctx context.Context) (*State, error) {
	installName, err := s.store.Get(ctx, KeyInstallName)
	if err != nil {
		return nil, err
	}
	mode, err := s.store.Get(ctx, KeyMode)
	if err != nil {
		return nil, err
	}
	completedAt, _ := s.store.GetTime(ctx, KeyWizardCompletedAt)

	var hasUsers bool
	if s.probes.HasUsers != nil {
		hasUsers, _ = s.probes.HasUsers(ctx)
	}
	trustConfigured := false
	if s.probes.TrustConfigured != nil {
		trustConfigured = s.probes.TrustConfigured()
	}
	meshEnrolled := false
	if s.probes.MeshEnrolled != nil && s.selfNodeID != "" {
		meshEnrolled, _ = s.probes.MeshEnrolled(ctx, s.selfNodeID)
	}
	firewallCapable := false
	if s.probes.HasFirewallNode != nil {
		firewallCapable, _ = s.probes.HasFirewallNode(ctx)
	}

	steps := []Step{
		{
			ID:       "passkey",
			Title:    "Register a passkey",
			Done:     hasUsers,
			Required: true,
			Detail:   "At least one operator must register a passkey before the system can be administered.",
		},
		{
			ID:       "install_name",
			Title:    "Name your Rasputin",
			Done:     strings.TrimSpace(installName) != "",
			Required: true,
			Detail:   "A short human label for this installation. Used in the UI header and (later) as the mesh hostname prefix.",
		},
		{
			ID:       "deployment_mode",
			Title:    "Choose a deployment mode",
			Done:     Mode(mode).Valid(),
			Required: true,
			Detail:   "How Rasputin fits into your network. This changes which features run — pick the one that matches how you plugged it in.",
		},
		{
			ID:       "remote_access",
			Title:    "Set up remote access",
			Done:     meshEnrolled,
			Required: false,
			Detail:   "Enrolls the controlplane node into the private mesh so you can reach this UI from outside the LAN.",
		},
		{
			ID:       "trust",
			Title:    "Verify PKI trust",
			Done:     trustConfigured,
			Required: false,
			Detail:   "Confirms this system can verify that OS updates are authentic before installing them.",
		},
	}

	// Completed iff (a) all required steps are done AND (b) the operator
	// has explicitly clicked Finish (writes wizard_completed_at). The
	// second condition keeps "first hour" friendly — we don't quietly
	// flip the banner off just because required steps happened to all be
	// satisfied by env detection.
	allRequired := true
	for _, st := range steps {
		if st.Required && !st.Done {
			allRequired = false
			break
		}
	}
	completed := allRequired && completedAt != nil

	return &State{
		Steps:           steps,
		Completed:       completed,
		CompletedAt:     completedAt,
		InstallName:     installName,
		HasUsers:        hasUsers,
		TrustConfigured: trustConfigured,
		MeshEnrolled:    meshEnrolled,
		SelfNodeID:      s.selfNodeID,
		Mode:            Mode(mode),
		FirewallCapable: firewallCapable,
	}, nil
}

// SetMode persists the operator's deployment-mode choice. Rejects an
// unrecognised value (ErrInvalidMode), and enforces the hardware gate:
// router and sub-segment modes need a firewall-capable node (a Pi-only
// cluster can never firewall), so they return ErrModeNeedsFirewallNode when
// none is registered. LAN-peer is always allowed. The WAN-observation sanity
// check (router-vs-sub-segment) is a later, non-blocking reconcile — it does
// not gate this write.
func (s *Service) SetMode(ctx context.Context, mode string) error {
	m := Mode(mode)
	if !m.Valid() {
		return ErrInvalidMode
	}
	if m.RequiresFirewallNode() {
		capable := false
		if s.probes.HasFirewallNode != nil {
			ok, err := s.probes.HasFirewallNode(ctx)
			if err != nil {
				return err
			}
			capable = ok
		}
		if !capable {
			return ErrModeNeedsFirewallNode
		}
	}
	return s.store.Set(ctx, KeyMode, string(m))
}

// SetInstallName persists the operator-chosen label. Trims whitespace.
// Returns an error if the trimmed value is empty.
func (s *Service) SetInstallName(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrInstallNameEmpty
	}
	return s.store.Set(ctx, KeyInstallName, name)
}

// MarkCompleted records the wizard-completed timestamp. Callers should
// guard against pre-completion state by checking GetState first; this
// method writes unconditionally.
func (s *Service) MarkCompleted(ctx context.Context) error {
	return s.store.SetTime(ctx, KeyWizardCompletedAt, time.Now().UTC())
}

// SelfNodeID returns the configured self-node id so handlers can pass it
// into the mesh enrollment job's spec.
func (s *Service) SelfNodeID() string { return s.selfNodeID }
