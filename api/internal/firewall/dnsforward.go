package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// dnsForwardName is the fixed display name of the CP-managed conditional-forward
// intent, stable so UpsertDNSForward finds its own row across restarts. It is
// operator-visible but CP-owned. The api's intent handlers do not refuse the
// dns_forward kind; instead an edit or delete of it re-submits
// firewall.dns_forward, which puts the row back to the control plane's address.
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
	// Inv locates the firewall node whose last successful apply the forward is
	// checked against. nil skips that check: only a changed forward applies.
	Inv *inventory.Store
}

// forwardUnapplied reports whether the CP-managed dns_forward intent was last
// written after the firewall's last successful apply — that is, whether the
// value the intent holds now has never been pushed to the box. Both are recorded
// timestamps (the intent's updated_at, the firewall's last_applied), so this is a
// comparison of facts, not a clock. With no single firewall node there is nothing
// an apply could reach, so it reports false.
func forwardUnapplied(ctx context.Context, store *Store, inv *inventory.Store) (bool, error) {
	fws, err := inv.ListByRole(ctx, proto.RoleFirewall)
	if err != nil {
		return false, fmt.Errorf("firewall node lookup: %w", err)
	}
	if len(fws) != 1 {
		return false, nil
	}
	intents, err := store.ListIntents(ctx)
	if err != nil {
		return false, fmt.Errorf("list intents: %w", err)
	}
	var forward *Intent
	for _, in := range intents {
		if proto.FirewallIntentKind(in.Kind) == proto.IntentDNSForward {
			forward = in
			break
		}
	}
	if forward == nil {
		return false, nil
	}
	state, err := store.GetNodeState(ctx, fws[0].ID)
	if err != nil {
		return false, fmt.Errorf("firewall state: %w", err)
	}
	if state == nil || state.LastApplied == nil {
		return true, nil
	}
	return forward.UpdatedAt.After(*state.LastApplied), nil
}

// DNSForwardWorkflow keeps the firewall's dnsmasq conditional-forward pointed at
// the control plane's current LAN IP with no operator action (ADR-0004 §10). Each
// run upserts the CP-managed dns_forward intent to the live IP and, when that
// changed — or when the forward's current value has never reached the firewall —
// auto-submits a firewall.apply so the new target reaches the box. That is the
// one place the firewall's otherwise-explicit apply model is driven
// automatically, because a floating CP IP is infrastructure, not an operator
// edit. In a firewall-less mode it removes the intent instead. Never fatal.
//
// It runs on facts, never on a timer (geekdojo/geekdojo-brain#431): the api
// submits it when its primary LAN address changes, when the firewall node's
// agent registers (every bus connect), and when the deployment mode changes.
// The "never reached the firewall" check is what makes the registration trigger
// sufficient: an address change made while the firewall was away updates the
// intent, its apply fails, and the run on the firewall's return finds the intent
// unchanged but unapplied, and pushes it.
func DNSForwardWorkflow(store *Store, runner *jobs.Runner, cfg DNSForwardConfig) jobs.Workflow {
	return jobs.Workflow{
		Kind: "firewall.dns_forward",
		Steps: []jobs.WorkflowStep{
			{
				Name:    "reconcile_forward",
				Timeout: 5 * time.Second,
				Retries: dnsForwardAttempts - 1,
				Do:      dnsForwardReconcile(store, runner, cfg),
			},
		},
	}
}

// dnsForwardAttempts bounds how often one firewall.dns_forward job runs its step
// before failing. The runner spaces the retries with its own backoff; nothing
// here, or anywhere, re-submits the job on a timer. After a job has exhausted
// its attempts the next fact — an address change, the firewall registering, a
// mode change, an edit to the forward — submits a fresh one.
//
// Retrying is safe because the step converges rather than acts. Everything that
// can fail comes before its one side effect: the mode read, the intent upsert
// (which adopts the existing row and rewrites it only on drift, so a repeat is a
// no-op), and the unapplied check. The side effect, submitting firewall.apply,
// is its last act and has no error return after it. An attempt that fails part
// way — say the upsert wrote the row and then errored — leaves the forward
// written but unapplied, and the retry's unapplied check submits the apply it
// never reached. The step does not push to the firewall itself: that is
// firewall.apply's push, a separate job this does not retry.
const dnsForwardAttempts = 3

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
		unapplied := false
		if !changed && want && cfg.Inv != nil {
			if unapplied, err = forwardUnapplied(sc.Ctx, store, cfg.Inv); err != nil {
				return nil, err
			}
		}
		if !changed && !unapplied {
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
				if changed {
					sc.Log("info", fmt.Sprintf("dns_forward → %s/%s; auto-applying", zone, target))
				} else {
					sc.Log("info", fmt.Sprintf("dns_forward %s/%s not yet applied to the firewall; auto-applying", zone, target))
				}
			}
		} else {
			sc.Log("info", "dns_forward removed (firewall-less mode)")
		}
		return json.Marshal(map[string]any{"changed": changed, "unapplied": unapplied, "want": want, "applied": applied})
	}
}
