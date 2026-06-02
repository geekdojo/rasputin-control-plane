package alerts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TestIngestWebhook_PersistsAndExposesViaRuleAlerts proves the
// end-to-end path: a vmalert-shaped POST → upsert → ruleAlerts() →
// /api/alerts merge.
func TestIngestWebhook_PersistsAndExposesViaRuleAlerts(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	svc := New(nil, nil, nil, nil, store, nil)

	payload := AlertmanagerWebhook{
		Version: "4", Status: "firing",
		Alerts: []AlertmanagerAlert{{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "HighCPU",
				"severity":  "warning",
				"nodeId":    "node-dev",
			},
			Annotations: map[string]string{
				"summary": "CPU at 92.4%",
			},
			StartsAt:    time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second),
			Fingerprint: "abc123",
		}},
	}
	body, _ := json.Marshal(payload)
	n, err := svc.IngestWebhook(ctx, body)
	if err != nil {
		t.Fatalf("IngestWebhook: %v", err)
	}
	if n != 1 {
		t.Fatalf("ingested %d, want 1", n)
	}
	alerts, err := svc.ruleAlerts(ctx)
	if err != nil {
		t.Fatalf("ruleAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("ruleAlerts returned %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Title != "HighCPU" {
		t.Errorf("title = %q", a.Title)
	}
	if a.Source != proto.AlertSourceRule {
		t.Errorf("source = %v, want rule", a.Source)
	}
	if a.Severity != proto.AlertWarn {
		t.Errorf("severity = %v, want warn", a.Severity)
	}
	if a.Detail != "CPU at 92.4%" {
		t.Errorf("detail = %q", a.Detail)
	}
	if a.RelatedKind != "node" || a.RelatedID != "node-dev" {
		t.Errorf("related = %s/%s, want node/node-dev", a.RelatedKind, a.RelatedID)
	}
}

func TestIngestWebhook_CriticalSeverityMappedToCrit(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	svc := New(nil, nil, nil, nil, store, nil)
	body, _ := json.Marshal(AlertmanagerWebhook{
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "NodeDown", "severity": "critical"},
			StartsAt:    time.Now().UTC(),
			Fingerprint: "f1",
		}},
	})
	if _, err := svc.IngestWebhook(ctx, body); err != nil {
		t.Fatalf("IngestWebhook: %v", err)
	}
	alerts, _ := svc.ruleAlerts(ctx)
	if len(alerts) != 1 || alerts[0].Severity != proto.AlertCrit {
		t.Fatalf("crit mapping failed: %+v", alerts)
	}
}

// TestIngestWebhook_NoStoreErrors confirms the service errors politely
// when no store is wired — keeps the failure surface explicit.
func TestIngestWebhook_NoStoreErrors(t *testing.T) {
	svc := New(nil, nil, nil, nil, nil, nil)
	if _, err := svc.IngestWebhook(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected error when no store wired")
	}
}

// TestIngestWebhook_FingerprintFallback proves we derive a stable
// fingerprint from labels when the payload doesn't carry one (older
// vmalert versions).
func TestIngestWebhook_FingerprintFallback(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	svc := New(nil, nil, nil, nil, store, nil)
	body, _ := json.Marshal(AlertmanagerWebhook{
		Alerts: []AlertmanagerAlert{{
			Status:   "firing",
			Labels:   map[string]string{"alertname": "A", "node": "n1"},
			StartsAt: time.Now().UTC(),
			// no Fingerprint
		}},
	})
	if _, err := svc.IngestWebhook(ctx, body); err != nil {
		t.Fatalf("IngestWebhook: %v", err)
	}
	alerts, _ := svc.ruleAlerts(ctx)
	if len(alerts) != 1 {
		t.Fatalf("ruleAlerts returned %d, want 1", len(alerts))
	}
	if alerts[0].ID == "" {
		t.Error("ID should be non-empty even without fingerprint")
	}
}

// TestIngestWebhook_Dedup confirms firing the same alert twice yields
// one row, not two.
func TestIngestWebhook_Dedup(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	svc := New(nil, nil, nil, nil, store, nil)
	payload := AlertmanagerWebhook{
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "X"},
			StartsAt:    time.Now().UTC(),
			Fingerprint: "same",
		}},
	}
	body, _ := json.Marshal(payload)
	_, _ = svc.IngestWebhook(ctx, body)
	_, _ = svc.IngestWebhook(ctx, body)
	alerts, _ := svc.ruleAlerts(ctx)
	if len(alerts) != 1 {
		t.Errorf("dedup failed: %d alerts after 2 identical fires", len(alerts))
	}
}
