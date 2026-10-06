package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Fingerprinter computes a keyed fingerprint (credmac.Key does).
type Fingerprinter interface {
	Sum(purpose string, parts ...[]byte) string
}

// stateStore is the persistence Service needs. *Store satisfies it.
type stateStore interface {
	ListIntentsForCompile(ctx context.Context) ([]*Intent, map[string]secret.Value, error)
	GetNodeState(ctx context.Context, nodeID string) (*NodeState, error)
	UpdateAfterApply(ctx context.Context, nodeID, intentHash string, ts time.Time) error
	UpdateAfterReconcile(ctx context.Context, nodeID, observedHash string, ts time.Time) error
	AdoptIntentHash(ctx context.Context, nodeID, legacy, keyed string) (bool, error)
	ForgetIntentHash(ctx context.Context, nodeID, legacy string) (bool, error)
}

// statePurpose is the credmac purpose of a firewall state fingerprint.
const statePurpose = "firewall.state"

// Service holds the firewall's business rules over its store: what the
// desired state is, its keyed fingerprint, the drift rule, and how a reconcile
// records what the agent observed — including adopting a fingerprint an
// earlier release wrote (geekdojo/geekdojo-brain#827). The Store only
// persists.
//
// The fingerprint is computed here, in the api, for both sides: over the state
// the api compiles and over the state the agent reports. The agent still
// returns its own unkeyed hash, and the api reads it only to tell whether the
// agent could read its state and, once per node after an upgrade, whether a
// stored pre-upgrade hash still matches.
type Service struct {
	store     stateStore
	mac       Fingerprinter
	emptyHash string

	// onSealed, when set, is handed the observed WAN password as it is
	// sealed, so a test can see it destroyed. nil in production.
	onSealed func(secret.Value)
}

// NewService builds a Service over store, fingerprinting under mac. It refuses
// either one nil.
func NewService(store stateStore, mac Fingerprinter) (*Service, error) {
	if store == nil {
		return nil, errors.New("firewall: NewService needs a store; nil was passed")
	}
	if s, ok := store.(*Store); ok && s == nil {
		return nil, errors.New("firewall: NewService needs a store; nil was passed")
	}
	if mac == nil {
		return nil, errors.New("firewall: NewService needs a Fingerprinter; nil was passed")
	}
	svc := &Service{store: store, mac: mac}
	empty, err := Compile(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("firewall: compile the empty state: %w", err)
	}
	if svc.emptyHash, err = svc.fingerprint(empty); err != nil {
		return nil, fmt.Errorf("firewall: fingerprint the empty state: %w", err)
	}
	return svc, nil
}

// fingerprint is the keyed fingerprint of state, over its revealed JSON.
// encoding/json sorts map keys, so equivalent states fingerprint equal.
func (s *Service) fingerprint(state map[string]any) (string, error) {
	b, err := json.Marshal(revealState(state))
	if err != nil {
		return "", err
	}
	defer clear(b)
	return s.mac.Sum(statePurpose, b), nil
}

// EmptyHash is the fingerprint of the state with no intents: what an
// unapplied node's "" intent hash stands for.
func (s *Service) EmptyHash() string { return s.emptyHash }

// compiled is the desired state, its fingerprint and the secrets it holds.
type compiled struct {
	intents []*Intent
	state   map[string]any
	hash    string
	secrets map[string]secret.Value
}

// release destroys the secrets. Every holder of a compiled defers it.
func (c *compiled) release() { DestroySecrets(c.secrets) }

// compile lists the intents and their secrets, compiles them and fingerprints
// the result. On error nothing is held; otherwise the caller defers release.
func (s *Service) compile(ctx context.Context) (*compiled, error) {
	intents, secrets, err := s.store.ListIntentsForCompile(ctx)
	if err != nil {
		return nil, fmt.Errorf("list intents: %w", err)
	}
	c := &compiled{intents: intents, secrets: secrets}
	if c.state, err = Compile(intents, secrets); err != nil {
		c.release()
		return nil, fmt.Errorf("compile: %w", err)
	}
	if c.hash, err = s.fingerprint(c.state); err != nil {
		c.release()
		return nil, fmt.Errorf("fingerprint: %w", err)
	}
	return c, nil
}

// DesiredHash is the fingerprint of what an apply would push now.
func (s *Service) DesiredHash(ctx context.Context) (string, error) {
	c, err := s.compile(ctx)
	if err != nil {
		return "", err
	}
	defer c.release()
	return c.hash, nil
}

// pushed is the fingerprint a stored intent hash stands for. A never-applied
// node has intent_hash="", which stands for the empty state, so neither an
// unpushed-and-empty firewall reads as pending nor a factory-fresh node whose
// agent reports clean empty state reads as drift. Found on the first Mu + CWWK
// bench (2026-06-12): reconcile ran before any apply and the UI showed a drift
// banner on an untouched firewall.
func (s *Service) pushed(intentHash string) string {
	if intentHash == "" {
		return s.emptyHash
	}
	return intentHash
}

// NodeStates is the state of each of nodeIDs, in order, with the drift and
// pending rules applied. A node with nothing stored reads as a fresh node.
// Pending is the fingerprint of what an apply would push now against the one
// last pushed; one desired fingerprint covers every node, since v0 supports
// exactly one firewall. IntentHash is returned as stored.
func (s *Service) NodeStates(ctx context.Context, nodeIDs []string) ([]*NodeState, error) {
	desired, err := s.DesiredHash(ctx)
	if err != nil {
		return nil, fmt.Errorf("firewall: desired state: %w", err)
	}
	out := make([]*NodeState, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		ns, err := s.NodeState(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("firewall: node %s state: %w", id, err)
		}
		if ns == nil {
			ns = &NodeState{NodeID: id}
		}
		ns.Pending = s.pushed(ns.IntentHash) != desired
		out = append(out, ns)
	}
	return out, nil
}

// NodeState is nodeID's stored state with the drift rule applied, or nil when
// nothing is stored for it. IntentHash is returned as stored.
func (s *Service) NodeState(ctx context.Context, nodeID string) (*NodeState, error) {
	ns, err := s.store.GetNodeState(ctx, nodeID)
	if err != nil || ns == nil {
		return ns, err
	}
	effectiveIntent := s.pushed(ns.IntentHash)
	// Drift requires a PRIOR APPLY by definition — it means "the firewall
	// diverged from what we pushed," which presupposes we pushed something.
	// A never-applied node (LastApplied==nil) arrives with its factory/stock
	// OpenWrt config on disk (the ~9 default rules), which is non-empty and
	// won't match our intent — but that's not drift, it's "unmanaged / not
	// yet adopted." Reporting it as drift on a freshly-attached firewall is
	// alarming and wrong (Mu+CWWK bench, 2026-06-12): the node reads as
	// PENDING instead (operator has the seeded baseline rules to APPLY), and
	// genuine drift detection turns on only after the first apply — which
	// still correctly catches a later factory-reset-back-to-stock.
	ns.Drift = ns.LastApplied != nil && ns.ObservedHash != "" && ns.ObservedHash != effectiveIntent
	return ns, nil
}

// errAgentUnread refuses to settle a pre-upgrade intent hash when the agent
// could not read its own state: there is nothing to compare it with.
var errAgentUnread = errors.New("firewall: agent could not read its state; the pre-upgrade intent hash is kept for the next reconcile")

// observe records the agent's get reply for nodeID at ts and returns the
// observed fingerprint: the keyed fingerprint of the reported state, or ""
// when the agent could not read it (its Hash is then "").
//
// The reported WAN password is sealed into a secret.Value as the reply is
// decoded and destroyed when observe returns, on every path.
//
// A stored intent hash an earlier release wrote (non-empty, not keyed) is
// settled first, from the agent's own unkeyed hash, which is the same scheme:
// equal means the firewall is still as applied, and the keyed fingerprint of
// what it reports is adopted; different means it drifted before the upgrade,
// and the hash is forgotten, so the node reads as drifted until an operator
// applies. Both writes are compare-and-set, so a concurrent apply wins. No
// hash value is logged, and the unkeyed value is never written or returned.
func (s *Service) observe(ctx context.Context, nodeID string, data []byte, ts time.Time, logf func(level, msg string)) (string, error) {
	var ack proto.FirewallGetAck
	if err := json.Unmarshal(data, &ack); err != nil {
		return "", fmt.Errorf("decode ack: %w", err)
	}
	sealed := sealObservedSecret(ack.State)
	defer sealed.Destroy()
	if s.onSealed != nil {
		s.onSealed(sealed)
	}

	observed := ""
	if ack.Hash != "" {
		var err error
		if observed, err = s.fingerprint(ack.State); err != nil {
			return "", fmt.Errorf("firewall: fingerprint the observed state: %w", err)
		}
	}

	stored, err := s.store.GetNodeState(ctx, nodeID)
	if err != nil {
		return "", fmt.Errorf("firewall: read node state: %w", err)
	}
	if stored != nil && stored.IntentHash != "" && !credmac.IsKeyed(stored.IntentHash) {
		legacy := stored.IntentHash
		switch {
		case ack.Hash == "":
			return "", errAgentUnread
		case ack.Hash == legacy:
			changed, err := s.store.AdoptIntentHash(ctx, nodeID, legacy, observed)
			if err != nil {
				return "", fmt.Errorf("firewall: record reconcile state: %w", err)
			}
			if changed {
				logf("info", "adopted the applied state under the keyed fingerprint")
			}
		default:
			changed, err := s.store.ForgetIntentHash(ctx, nodeID, legacy)
			if err != nil {
				return "", fmt.Errorf("firewall: record reconcile state: %w", err)
			}
			if changed {
				logf("warn", "the firewall's state differed from the last apply before this upgrade; apply to adopt")
			}
		}
	}

	if err := s.store.UpdateAfterReconcile(ctx, nodeID, observed, ts); err != nil {
		return "", fmt.Errorf("firewall: record reconcile state: %w", err)
	}
	return observed, nil
}

// sealObservedSecret replaces the WAN password in an agent-reported state,
// when it is a string, with a secret.Value, and returns that Value (the zero
// Value when there is none). The caller destroys it. The state is changed in
// place, so from here on it renders the password as "[redacted]" and only
// revealState reads it.
func sealObservedSecret(state map[string]any) secret.Value {
	network, ok := state["network"].(map[string]any)
	if !ok {
		return secret.Value{}
	}
	wan, ok := network["wan"].(map[string]any)
	if !ok {
		return secret.Value{}
	}
	pw, ok := wan["password"].(string)
	if !ok {
		return secret.Value{}
	}
	v := secret.New([]byte(pw))
	wan["password"] = v
	return v
}
