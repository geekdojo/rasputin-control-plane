package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// GET /api/firewall/intents
func (s *Server) handleListIntents(w http.ResponseWriter, r *http.Request) {
	intents, err := s.fw.ListIntents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if intents == nil {
		intents = []*firewall.Intent{}
	}
	writeJSON(w, http.StatusOK, intents)
}

// POST /api/firewall/intents
// Body: { "kind": "port_forward", "name": "minecraft", "enabled": true, "spec": {...} }
func (s *Server) handleCreateIntent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind    string          `json:"kind"`
		Name    string          `json:"name"`
		Enabled *bool           `json:"enabled"`
		Spec    json.RawMessage `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !proto.ValidFirewallIntentKind(proto.FirewallIntentKind(req.Kind)) {
		writeError(w, http.StatusBadRequest, "unsupported intent kind")
		return
	}
	if err := validateIntentSpec(req.Kind, req.Spec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	now := time.Now().UTC()
	intent := &firewall.Intent{
		ID:        ulid.Make().String(),
		Kind:      req.Kind,
		Name:      req.Name,
		Enabled:   enabled,
		Spec:      req.Spec,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.fw.CreateIntent(r.Context(), intent); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := enforceWANConfigInvariant(r.Context(), s.fw, intent); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, intent)
}

// enforceWANConfigInvariant disables any sibling wan_config rows when the
// just-written intent is an enabled wan_config. No-op for other kinds, for
// disabled wan_configs, and for the always-OK case where this is the only
// enabled wan_config in the table.
//
// Per firewall-integration.md §13, at most one wan_config can be enabled.
// Toggling ON one config implicitly toggles OFF the others — the "switch
// between ISP profiles" gesture. The api enforces this rather than asking
// users to manually disable the previous active config first.
func enforceWANConfigInvariant(ctx context.Context, fw wanInvariantStore, intent *firewall.Intent) error {
	if intent.Kind != string(proto.IntentWANConfig) || !intent.Enabled {
		return nil
	}
	if _, err := fw.DisableOtherWANConfigs(ctx, intent.ID); err != nil {
		return errors.New("disable other wan_configs: " + err.Error())
	}
	return nil
}

// wanInvariantStore is the slice of *firewall.Store the helper needs — kept
// narrow so tests can substitute a fake without depending on the full store.
type wanInvariantStore interface {
	DisableOtherWANConfigs(ctx context.Context, keepID string) (int64, error)
}

// PATCH /api/firewall/intents/{id}
// Body: optional fields { "name", "enabled", "spec" }.
func (s *Server) handleUpdateIntent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.fw.GetIntent(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "intent not found")
		return
	}
	var req struct {
		Name    *string          `json:"name"`
		Enabled *bool            `json:"enabled"`
		Spec    *json.RawMessage `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Spec != nil {
		if err := validateIntentSpec(existing.Kind, *req.Spec); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.Spec = *req.Spec
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := s.fw.UpdateIntent(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := enforceWANConfigInvariant(r.Context(), s.fw, existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

// DELETE /api/firewall/intents/{id}
func (s *Server) handleDeleteIntent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.fw.DeleteIntent(r.Context(), id); err != nil {
		if errors.Is(err, errNoRowsSentinel) || err.Error() == "sql: no rows in result set" {
			writeError(w, http.StatusNotFound, "intent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/firewall/state — returns the per-node state for every firewall
// node currently known to inventory (typically zero or one in v0).
func (s *Server) handleGetFirewallState(w http.ResponseWriter, r *http.Request) {
	fws, err := s.inv.ListByRole(r.Context(), proto.RoleFirewall)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Compute the pending status: hash of current enabled intents vs the
	// hash we last pushed (NodeState.IntentHash). One Compile covers every
	// firewall node since v0 supports exactly one — the compiled state is
	// identical across them.
	intents, err := s.fw.ListIntents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, pendingHash, err := firewall.Compile(intents)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "compile: "+err.Error())
		return
	}
	// A brand-new node has IntentHash="" but Compile(nil) produces a real
	// hash for the canonical empty-state map. Treat "" as equivalent to
	// the empty-state hash so an unpushed-and-empty firewall doesn't
	// paradoxically read as pending.
	_, emptyHash, _ := firewall.Compile(nil)
	out := make([]*firewall.NodeState, 0, len(fws))
	for _, n := range fws {
		st, err := s.fw.GetNodeState(r.Context(), n.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if st == nil {
			st = &firewall.NodeState{NodeID: n.ID}
		}
		effectivePushed := st.IntentHash
		if effectivePushed == "" {
			effectivePushed = emptyHash
		}
		st.Pending = effectivePushed != pendingHash
		out = append(out, st)
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/firewall/apply — kicks off a firewall.apply job and returns it.
func (s *Server) handleApplyFirewall(w http.ResponseWriter, r *http.Request) {
	j, err := s.runner.Submit(r.Context(), "firewall.apply", json.RawMessage("{}"), creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/firewall/reconcile — kicks off a firewall.reconcile job.
func (s *Server) handleReconcileFirewall(w http.ResponseWriter, r *http.Request) {
	j, err := s.runner.Submit(r.Context(), "firewall.reconcile", json.RawMessage("{}"), creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// validateIntentSpec checks a spec parses + is well-formed for the kind.
// Returns nil on success.
func validateIntentSpec(kind string, raw json.RawMessage) error {
	switch proto.FirewallIntentKind(kind) {
	case proto.IntentPortForward:
		var spec proto.PortForwardSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return errors.New("invalid port_forward spec: " + err.Error())
		}
		if spec.WanPort < 1 || spec.WanPort > 65535 {
			return errors.New("wanPort must be 1-65535")
		}
		if spec.LanPort < 1 || spec.LanPort > 65535 {
			return errors.New("lanPort must be 1-65535")
		}
		if spec.LanHost == "" {
			return errors.New("lanHost is required")
		}
		if spec.Protocol == "" {
			spec.Protocol = proto.ProtoTCP
		}
		switch spec.Protocol {
		case proto.ProtoTCP, proto.ProtoUDP, proto.ProtoTCPUDP:
		default:
			return errors.New("protocol must be tcp, udp, or tcpudp")
		}
		return nil
	case proto.IntentWANConfig:
		var spec proto.WANConfigSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return errors.New("invalid wan_config spec: " + err.Error())
		}
		return validateWANConfigSpec(spec)
	case proto.IntentFirewallRule:
		var spec proto.FirewallRuleSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return errors.New("invalid firewall_rule spec: " + err.Error())
		}
		if spec.Src == "" {
			return errors.New("src zone is required")
		}
		switch spec.Target {
		case proto.RuleTargetAccept, proto.RuleTargetReject, proto.RuleTargetDrop:
		case "":
			return errors.New("target is required")
		default:
			return errors.New("target must be accept, reject, or drop")
		}
		switch spec.Proto {
		case "", proto.RuleProtoAny, proto.RuleProtoTCP, proto.RuleProtoUDP, proto.RuleProtoTCPUDP, proto.RuleProtoICMP:
		default:
			return errors.New("proto must be any, tcp, udp, tcpudp, or icmp")
		}
		if err := validateIPOrCIDR("srcIp", spec.SrcIP); err != nil {
			return err
		}
		if err := validateIPOrCIDR("destIp", spec.DestIP); err != nil {
			return err
		}
		if err := validatePortOrRange("srcPort", spec.SrcPort); err != nil {
			return err
		}
		if err := validatePortOrRange("destPort", spec.DestPort); err != nil {
			return err
		}
		return nil
	}
	return errors.New("unsupported intent kind")
}

// validateWANConfigSpec enforces the protocol-specific required-fields
// contract documented on proto.WANConfigSpec. Fields outside the active
// protocol are silently accepted (they're saved as-is) — the compiler only
// emits the ones it cares about for the chosen Proto, so leaving extras
// lets users keep dormant ISP-A settings around while ISP-B is active.
func validateWANConfigSpec(spec proto.WANConfigSpec) error {
	switch spec.Proto {
	case proto.WANProtoDHCP:
		// Hostname is optional; no validation required beyond that.
	case proto.WANProtoStatic:
		if spec.IP == "" {
			return errors.New("static proto: ip is required (CIDR form, e.g. 203.0.113.5/24)")
		}
		if err := validateIPOrCIDR("ip", spec.IP); err != nil {
			return err
		}
		if spec.Gateway == "" {
			return errors.New("static proto: gateway is required")
		}
		if err := validateIPOrCIDR("gateway", spec.Gateway); err != nil {
			return err
		}
		for i, d := range spec.DNS {
			if err := validateIPOrCIDR("dns["+strconv.Itoa(i)+"]", d); err != nil {
				return err
			}
		}
	case proto.WANProtoPppoe:
		if spec.Username == "" {
			return errors.New("pppoe proto: username is required")
		}
		if spec.Secret == "" {
			return errors.New("pppoe proto: secret is required")
		}
	case "":
		return errors.New("proto is required (dhcp, static, or pppoe)")
	default:
		return errors.New("proto must be dhcp, static, or pppoe")
	}
	return nil
}

// validateIPOrCIDR accepts either a bare address ("10.0.0.5") or a prefix
// ("10.0.0.0/24"). Empty input is a no-op (the field is optional).
func validateIPOrCIDR(field, v string) error {
	if v == "" {
		return nil
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return nil
	}
	return errors.New(field + " must be a valid IP or CIDR")
}

// validatePortOrRange accepts either a single port ("443") or an inclusive
// range ("8000-8100"). Empty input is a no-op.
func validatePortOrRange(field, v string) error {
	if v == "" {
		return nil
	}
	parse := func(s string) (int, error) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return 0, errors.New(field + " must be 1-65535")
		}
		return n, nil
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		lo, err := parse(v[:i])
		if err != nil {
			return err
		}
		hi, err := parse(v[i+1:])
		if err != nil {
			return err
		}
		if hi < lo {
			return errors.New(field + " range must have low ≤ high")
		}
		return nil
	}
	_, err := parse(v)
	return err
}

// errNoRowsSentinel keeps the api package free of a direct database/sql
// dependency in the handler layer; we compare error strings as fallback.
var errNoRowsSentinel = errors.New("sql: no rows in result set")

// creator returns a stable string identifier for who created a job. Uses
// the authenticated user's name if available, falls back to "system".
func creator(r *http.Request) string {
	// Without importing auth here we'd need a re-exported helper; for v0
	// fall back to "user" — same default the older job handler uses.
	return "user"
}
