package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// dnsForwardName is the fixed display name of the CP-managed conditional-forward
// intent, stable so UpsertDNSForward finds its own row across restarts. It is
// operator-visible but CP-owned: the api's create/update handlers reject the
// dns_forward kind, and if it's deleted the next reconcile recreates it.
const dnsForwardName = "DNS-Forward-Internal"

// UpsertDNSForward reconciles the single CP-managed dns_forward intent to match
// (zone, target) when want is true, or removes it when want is false. It returns
// whether the intent set changed — a new CP IP, first creation, an enable, or a
// removal — so the caller can decide whether to auto-apply. It never creates a
// second dns_forward row: it adopts the first one it finds (there is at most one
// firewall per cluster, and intents are cluster-global).
func UpsertDNSForward(ctx context.Context, store *Store, zone, target string, want bool) (changed bool, err error) {
	intents, err := store.ListIntents(ctx)
	if err != nil {
		return false, fmt.Errorf("list intents: %w", err)
	}
	var existing *Intent
	for _, in := range intents {
		if proto.FirewallIntentKind(in.Kind) == proto.IntentDNSForward {
			existing = in
			break
		}
	}

	if !want {
		if existing == nil {
			return false, nil
		}
		if err := store.DeleteIntent(ctx, existing.ID); err != nil {
			return false, fmt.Errorf("delete dns_forward: %w", err)
		}
		return true, nil
	}

	raw, err := json.Marshal(proto.DNSForwardSpec{Zone: zone, Target: target})
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	if existing == nil {
		in := &Intent{
			ID:        ulid.Make().String(),
			Kind:      string(proto.IntentDNSForward),
			Name:      dnsForwardName,
			Enabled:   true,
			Spec:      raw,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := store.CreateIntent(ctx, in); err != nil {
			return false, fmt.Errorf("create dns_forward: %w", err)
		}
		return true, nil
	}

	// Already present — rewrite only if the zone/target or enabled state drifted
	// (this is what makes a CP-IP change propagate; an unchanged sweep is a no-op).
	var cur proto.DNSForwardSpec
	_ = json.Unmarshal(existing.Spec, &cur)
	if existing.Enabled && cur.Zone == zone && cur.Target == target {
		return false, nil
	}
	existing.Spec = raw
	existing.Enabled = true
	existing.UpdatedAt = now
	if err := store.UpdateIntent(ctx, existing); err != nil {
		return false, fmt.Errorf("update dns_forward: %w", err)
	}
	return true, nil
}

// DNSForwardConfig injects the CP-derived inputs the dns_forward reconcile needs.
// Zone is <cluster-id>.internal (empty if the box has no cluster id); Target is
// the control plane's current LAN IP (empty if unknown); Managed gates the whole
// thing to firewall-present modes (reuse the api's firewall Managed func).
type DNSForwardConfig struct {
	Zone    func() string
	Target  func() string
	Managed Managed
}

// DNSForwardWorkflow keeps the firewall's dnsmasq conditional-forward pointed at
// the control plane's current LAN IP with no operator action (ADR-0004 §10). On
// each tick it upserts the CP-managed dns_forward intent to the live IP and, when
// that changed, auto-submits a firewall.apply so the new target reaches the box —
// the one place the firewall's otherwise-explicit apply model is driven
// automatically, because a floating CP IP is infrastructure, not an operator
// edit. In a firewall-less mode it removes the intent instead. Never fatal.
func DNSForwardWorkflow(store *Store, runner *jobs.Runner, cfg DNSForwardConfig) jobs.Workflow {
	return jobs.Workflow{
		Kind: "firewall.dns_forward",
		Steps: []jobs.WorkflowStep{
			{Name: "reconcile_forward", Timeout: 5 * time.Second, Do: dnsForwardReconcile(store, runner, cfg)},
		},
	}
}

func dnsForwardReconcile(store *Store, runner *jobs.Runner, cfg DNSForwardConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		managed := true
		if cfg.Managed != nil {
			ok, err := cfg.Managed(sc.Ctx)
			if err != nil {
				return nil, fmt.Errorf("mode gate: %w", err)
			}
			managed = ok
		}
		zone, target := "", ""
		if cfg.Zone != nil {
			zone = cfg.Zone()
		}
		if cfg.Target != nil {
			target = cfg.Target()
		}
		// Want the forward only in a firewall mode and once we actually know the
		// zone and a LAN IP to point at.
		want := managed && zone != "" && target != ""

		changed, err := UpsertDNSForward(sc.Ctx, store, zone, target, want)
		if err != nil {
			return nil, err
		}
		if !changed {
			return json.Marshal(map[string]any{"changed": false, "want": want})
		}
		// The forward changed. When it's wanted, push it — auto-apply is the
		// zero-touch mechanism. When it's not (mode left a firewall mode) the
		// firewall is being idled anyway and apply is gated off, so skip it.
		applied := false
		if want && runner != nil {
			if _, err := runner.Submit(sc.Ctx, "firewall.apply", json.RawMessage(`{}`), "dns-forward-auto"); err != nil {
				sc.Log("warn", "dns_forward changed but auto-apply submit failed: "+err.Error())
			} else {
				applied = true
				sc.Log("info", fmt.Sprintf("dns_forward → %s/%s; auto-applying", zone, target))
			}
		} else {
			sc.Log("info", "dns_forward removed (firewall-less mode)")
		}
		return json.Marshal(map[string]any{"changed": true, "want": want, "applied": applied})
	}
}
