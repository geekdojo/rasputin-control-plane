package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// baselineRule is the static description of one stock-equivalent firewall rule
// we seed when a firewall node first registers.
type baselineRule struct {
	name string
	spec proto.FirewallRuleSpec
}

// baselineRules is the IPv4 stock-equivalent input ruleset OpenWrt ships by
// default. The real UCI backend applies firewall rules by delete-and-recreate,
// which wipes the stock input rules on the first apply — so we re-materialize
// the load-bearing IPv4 ones as real, operator-visible, deletable intents
// ("honest about what's running"). They are created disabled-less (enabled) and
// pending; the operator (or the first apply) pushes them.
//
// IPv6 stock rules (Allow-DHCPv6, Allow-MLD, Allow-ICMPv6-Input/Forward) are
// deliberately OMITTED here: v1 is IPv4-only (locked decision, backlog W-1).
// They ride W-1 (IPv6 WAN support) and are tracked there, not silently missing.
var baselineRules = []baselineRule{
	{
		// CRITICAL: without this the WAN DHCP lease can fail to renew at
		// rebind (delayed, intermittent loss of WAN).
		name: "Allow-DHCP-Renew",
		spec: proto.FirewallRuleSpec{
			Src:      "wan",
			Proto:    proto.RuleProtoUDP,
			DestPort: "68",
			Target:   proto.RuleTargetAccept,
		},
	},
	{
		// Stock filters to echo-request via icmp_type; our schema has no
		// icmp_type field, so this accepts all ICMP from wan — acceptable and
		// arguably friendlier. No icmp_type plumbing added on purpose.
		name: "Allow-Ping",
		spec: proto.FirewallRuleSpec{
			Src:    "wan",
			Proto:  proto.RuleProtoICMP,
			Target: proto.RuleTargetAccept,
		},
	},
	{
		// Multicast / IPTV group management.
		name: "Allow-IGMP",
		spec: proto.FirewallRuleSpec{
			Src:    "wan",
			Proto:  proto.RuleProtoIGMP,
			Target: proto.RuleTargetAccept,
		},
	},
}

// baselineSeedKey is the CLUSTER-GLOBAL marker id under which the baseline is
// seeded at most once, ever. Firewall intents are global (one firewall per
// cluster — the table has no target_node_id), so the guard must be global too.
// Keying it on the node-id (the pre-2026-07-02 behaviour) re-seeded the baseline
// every time the firewall re-enrolled under a NEW node-id (rename / re-provision
// / a fresh firewall after the old one was removed), stacking duplicate rules —
// the bug this fixes. The key can't collide with a real node-id (node-ids never
// contain a leading underscore + parens shape below).
const baselineSeedKey = "_cluster_baseline_"

// SeedBaselineRules creates the stock-equivalent baseline firewall_rule intents
// exactly ONCE per cluster, ever. Safe to call on every firewall
// first-registration hook fire (and tolerant of double-fire / DB-reattach /
// node-id-change): the check-and-set on the cluster-global marker is
// transactional, so the rules are seeded at most once and — critically — a
// baseline rule the operator later DELETES does not resurrect, because the
// marker is never cleared.
//
// nodeID is used only for logging (the guard is cluster-global, not per-node).
//
// The seeded intents go through the normal CreateIntent path: enabled=true,
// kind=firewall_rule, so they appear in GET /api/firewall/intents and the rules
// table identically to user-created rules, starting as pending (NOT applied —
// the seeding hook never auto-applies; staying consistent with the explicit
// apply model is the honest UX).
//
// Returns the number of intents created (0 when already seeded). Errors are
// returned to the caller, which logs-and-swallows them — a seeding failure must
// never break node registration.
func SeedBaselineRules(ctx context.Context, store *Store, nodeID string) (int, error) {
	first, err := store.MarkBaselineSeeded(ctx, baselineSeedKey)
	if err != nil {
		return 0, fmt.Errorf("baseline marker: %w", err)
	}
	if !first {
		return 0, nil // cluster already seeded — never reseed.
	}
	// The global marker was just set for the first time — but a cluster seeded
	// under the OLD per-node scheme already HAS the baseline (possibly edited).
	// Detect that and adopt it: keep the global marker, seed nothing, so
	// upgrading never duplicates the baseline.
	if legacy, err := store.HasLegacyBaselineMarkers(ctx, baselineSeedKey); err != nil {
		return 0, fmt.Errorf("baseline legacy check: %w", err)
	} else if legacy {
		log.Printf("firewall: baseline already seeded under the legacy per-node scheme; adopting, not reseeding (trigger node %s)", nodeID)
		return 0, nil
	}

	now := time.Now().UTC()
	created := 0
	for _, br := range baselineRules {
		raw, err := json.Marshal(br.spec)
		if err != nil {
			return created, fmt.Errorf("marshal %s: %w", br.name, err)
		}
		in := &Intent{
			ID:        ulid.Make().String(),
			Kind:      string(proto.IntentFirewallRule),
			Name:      br.name,
			Enabled:   true,
			Spec:      raw,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := store.CreateIntent(ctx, in); err != nil {
			return created, fmt.Errorf("create %s: %w", br.name, err)
		}
		created++
	}
	log.Printf("firewall: seeded %d baseline rule(s) for firewall node %s", created, nodeID)
	return created, nil
}
