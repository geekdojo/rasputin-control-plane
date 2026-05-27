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
			Detail:   "Confirms the OS-update root CA is installed at data/trust/root-ca.pem. Bundle signatures aren't verified without it.",
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
	}, nil
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
