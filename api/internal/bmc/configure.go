package bmc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ConfigureSpec is the spec body for a bmc.configure job
// (bmc-settings.md §4). Kind ""/"none" deconfigures — hard off.
type ConfigureSpec struct {
	Kind       string          `json:"kind"`
	HostNodeID string          `json:"hostNodeId,omitempty"`
	Config     json.RawMessage `json:"config,omitempty"`
	ConfigHash string          `json:"configHash,omitempty"`
}

// ConfigHash fingerprints a selection; the agent echoes and advertises
// it opaquely, and the registration reconcile compares it. secret is
// any write-only credential that rides outside the config blob (the
// bitscope unlock) — folding it in means rotating the secret triggers a
// re-push. The advertised value is a truncated one-way hash; a
// high-entropy secret is not recoverable from it (the factory-default
// unlock is public anyway).
func ConfigHash(kind string, config json.RawMessage, secret string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	h.Write([]byte{'\n'})
	h.Write(config)
	h.Write([]byte{'\n'})
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// RunningPowerJobsFn reports whether any bmc.power job is currently
// running — the configure validate step refuses to yank the bus out
// from under an in-flight hardware op.
type RunningPowerJobsFn func(ctx context.Context) (bool, error)

// ConfigureWorkflow delivers the operator's BMC selection to the host
// agent and records it in settings. The settings write happens in the
// record step — after a successful push — so config state and the job
// audit trail can't diverge (a failed push leaves settings untouched).
func ConfigureWorkflow(svc *Service, inv *inventory.Store, st *setup.Store, sessions *SessionManager, powerRunning RunningPowerJobsFn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "bmc.configure",
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: 3 * time.Second, Do: configureValidate(inv, sessions, powerRunning)},
			{Name: "push", Timeout: 15 * time.Second, Do: configurePush(st)},
			{Name: "record", Timeout: 3 * time.Second, Do: configureRecord(st)},
		},
	}
}

func parseConfigureSpec(raw json.RawMessage) (*ConfigureSpec, error) {
	var spec ConfigureSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if spec.Kind == "" {
		spec.Kind = "none"
	}
	if spec.HostNodeID == "" {
		return nil, errors.New("hostNodeId is required")
	}
	return &spec, nil
}

// ValidateSelection structurally validates a selection against the
// inventory: the kind must be supported+available (or none), and every
// referenced target must be a registered node. Deep per-driver checks
// (position format, device reachability) happen agent-side and come
// back as a typed nack — never a timeout.
func ValidateSelection(ctx context.Context, inv *inventory.Store, kind string, config json.RawMessage) error {
	if kind == "none" {
		return nil
	}
	if !proto.AvailableBMCBackend(kind) {
		return fmt.Errorf("backend %q is not an available selection", kind)
	}
	targets, err := selectionTargets(kind, config)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("selection has no targets")
	}
	seen := map[string]bool{}
	for _, id := range targets {
		if id == "" {
			return errors.New("selection has an empty target node id")
		}
		if seen[id] {
			return fmt.Errorf("duplicate target %q", id)
		}
		seen[id] = true
		n, err := inv.Get(ctx, id)
		if err != nil {
			return fmt.Errorf("inventory lookup %q: %w", id, err)
		}
		if n == nil {
			return fmt.Errorf("target %q is not a registered node", id)
		}
	}
	return nil
}

// injectJSONField returns raw with field set — used to attach the
// unlock to the bus command without it ever touching the job spec.
func injectJSONField(raw json.RawMessage, field, value string) (json.RawMessage, error) {
	m := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("config decode: %w", err)
		}
	}
	m[field] = value
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// selectionTargets extracts the referenced node-ids from a per-kind
// config blob.
func selectionTargets(kind string, config json.RawMessage) ([]string, error) {
	switch kind {
	case "mock":
		var sel struct {
			Targets []string `json:"targets"`
		}
		if len(config) > 0 {
			if err := json.Unmarshal(config, &sel); err != nil {
				return nil, fmt.Errorf("mock config: %w", err)
			}
		}
		return sel.Targets, nil
	case "bitscope":
		var sel struct {
			Targets []struct {
				Pos    string `json:"pos"`
				NodeID string `json:"node_id"`
			} `json:"targets"`
		}
		if err := json.Unmarshal(config, &sel); err != nil {
			return nil, fmt.Errorf("bitscope config: %w", err)
		}
		out := make([]string, 0, len(sel.Targets))
		for _, t := range sel.Targets {
			out = append(out, t.NodeID)
		}
		return out, nil
	case "turingpi":
		// Shape mirrors the agent's NewFromSelection case exactly — that
		// is the contract, and a mismatch here would validate cleanly and
		// then fail on the node.
		var sel struct {
			Endpoint    string `json:"endpoint"`
			User        string `json:"user"`
			Fingerprint string `json:"fingerprint,omitempty"`
			Insecure    bool   `json:"insecure_skip_verify,omitempty"`
			Targets     []struct {
				NodeID string `json:"node_id"`
				Slot   int    `json:"slot"`
			} `json:"targets"`
		}
		if err := json.Unmarshal(config, &sel); err != nil {
			return nil, fmt.Errorf("turingpi config: %w", err)
		}
		if strings.TrimSpace(sel.Endpoint) == "" {
			return nil, errors.New("turingpi config: endpoint is required")
		}
		if strings.TrimSpace(sel.User) == "" {
			return nil, errors.New("turingpi config: username is required (the BMC requires auth)")
		}
		// TLS has to be chosen explicitly, same rule the driver enforces:
		// the board's certificate is minted at the epoch and permanently
		// expired, so CA trust cannot work and a silent default would mean
		// silently unverified.
		if sel.Fingerprint == "" && !sel.Insecure {
			return nil, errors.New("turingpi config: pin the BMC certificate fingerprint, or explicitly accept any certificate")
		}
		seenSlot := map[int]string{}
		out := make([]string, 0, len(sel.Targets))
		for _, t := range sel.Targets {
			if t.Slot < 1 || t.Slot > 4 {
				return nil, fmt.Errorf("turingpi config: node %q has slot %d, want 1..4", t.NodeID, t.Slot)
			}
			if prev, dup := seenSlot[t.Slot]; dup {
				return nil, fmt.Errorf("turingpi config: nodes %q and %q both claim slot %d", prev, t.NodeID, t.Slot)
			}
			seenSlot[t.Slot] = t.NodeID
			out = append(out, t.NodeID)
		}
		return out, nil
	}
	return nil, fmt.Errorf("no config schema for backend %q", kind)
}

func configureValidate(inv *inventory.Store, sessions *SessionManager, powerRunning RunningPowerJobsFn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseConfigureSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		if err := ValidateSelection(sc.Ctx, inv, spec.Kind, spec.Config); err != nil {
			return nil, err
		}
		if spec.Kind != "none" {
			host, err := inv.Get(sc.Ctx, spec.HostNodeID)
			if err != nil {
				return nil, fmt.Errorf("host lookup: %w", err)
			}
			if host == nil {
				return nil, fmt.Errorf("host node %q is not registered", spec.HostNodeID)
			}
		}
		// Don't yank the bus mid-use (bmc-settings.md §8): the operator
		// closes the console / waits for the power job instead.
		if n := sessions.Active(); n > 0 {
			return nil, fmt.Errorf("%d SoL session(s) open — close the console before reconfiguring BMC", n)
		}
		if powerRunning != nil {
			running, err := powerRunning(sc.Ctx)
			if err != nil {
				return nil, fmt.Errorf("check running power jobs: %w", err)
			}
			if running {
				return nil, errors.New("a bmc.power job is running — retry when it finishes")
			}
		}
		sc.Log("info", fmt.Sprintf("bmc.configure kind=%s host=%s hash=%s", spec.Kind, spec.HostNodeID, spec.ConfigHash))
		return json.Marshal(spec)
	}
}

// configurePush delivers the selection to the host agent. The job spec
// deliberately carries NO secrets (job specs and step results are
// served unredacted by the jobs API and persist in the audit trail) —
// the bitscope unlock lives under its own settings key and is injected
// into the bus command here, at dispatch time only.
func configurePush(st *setup.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseConfigureSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		pushCfg := spec.Config
		if cred, ok := CredentialFor(spec.Kind); ok {
			secret, serr := st.Get(sc.Ctx, cred.SettingsKey)
			if serr != nil {
				return nil, fmt.Errorf("read %s credential: %w", spec.Kind, serr)
			}
			if secret != "" {
				pushCfg, err = injectJSONField(spec.Config, cred.Field, secret)
				if err != nil {
					return nil, err
				}
			}
		}
		cmd, _ := json.Marshal(proto.BMCConfigureCmd{
			Kind:       spec.Kind,
			Config:     pushCfg,
			ConfigHash: spec.ConfigHash,
		})
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.BMCConfigureSubject(spec.HostNodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("configure rpc to %s: %w", spec.HostNodeID, err)
		}
		var ack proto.BMCConfigureAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}
		if !ack.OK {
			return nil, fmt.Errorf("host refused: %s", ack.Detail)
		}
		sc.Log("info", fmt.Sprintf("applied on %s (hash=%s)", spec.HostNodeID, ack.ConfigHash))
		return json.Marshal(ack)
	}
}

func configureRecord(st *setup.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseConfigureSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		if spec.Kind == "none" {
			if err := st.Set(sc.Ctx, setup.KeyBMCBackend, ""); err != nil {
				return nil, err
			}
			if err := st.Set(sc.Ctx, setup.KeyBMCConfig, ""); err != nil {
				return nil, err
			}
			sc.Log("info", "bmc off — settings cleared")
			return json.Marshal(spec)
		}
		if err := st.Set(sc.Ctx, setup.KeyBMCBackend, spec.Kind); err != nil {
			return nil, err
		}
		if err := st.Set(sc.Ctx, setup.KeyBMCHostNode, spec.HostNodeID); err != nil {
			return nil, err
		}
		if err := st.Set(sc.Ctx, setup.KeyBMCConfig, string(spec.Config)); err != nil {
			return nil, err
		}
		sc.Log("info", "settings recorded")
		return json.Marshal(spec)
	}
}

// ── Per-kind credential handling ─────────────────────────────────────────
//
// Job specs and step results are served unredacted by the jobs API and
// persist in the audit trail, so no backend's credential may ride inside
// KeyBMCConfig or a job spec (security review, CP #34). Each kind that
// has one declares it here instead: the handler strips it into its own
// settings key on write, and the push step injects it into the bus
// command at dispatch time only.
//
// This started as `if kind == "bitscope"` in four places. Turing Pi made
// that a pattern rather than a special case, so it is a table now —
// adding the chassis backend later is one line, not another four-site
// edit that can be half-done.
type CredentialField struct {
	Field       string // JSON field in the config blob
	SettingsKey string // settings key it is stored under instead
}

var backendCredentials = map[string]CredentialField{
	"bitscope": {Field: "unlock", SettingsKey: setup.KeyBMCBitscopeUnlock},
	"turingpi": {Field: "pass", SettingsKey: setup.KeyBMCTuringPiPass},
}

// CredentialFor reports the credential field for a backend kind, if it
// has one. Kinds absent from the table (mock) carry no secret.
func CredentialFor(kind string) (CredentialField, bool) {
	c, ok := backendCredentials[kind]
	return c, ok
}

// StoredCredential returns the persisted credential for a kind, or ""
// when the kind has none. Used to fold the secret into ConfigHash so a
// rotation still re-pushes.
func StoredCredential(ctx context.Context, st *setup.Store, kind string) string {
	c, ok := CredentialFor(kind)
	if !ok {
		return ""
	}
	v, err := st.Get(ctx, c.SettingsKey)
	if err != nil {
		return ""
	}
	return v
}
