package setup

import (
	"context"
	"testing"
)

func newDNSService(t *testing.T) *Service {
	t.Helper()
	return NewService(newStore(t), Probes{}, "cp-1", "test1.local", "test1")
}

func TestDNSForwarding_UnsetDefault(t *testing.T) {
	v, err := newDNSService(t).GetDNSForwarding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Enabled || v.Upstream != "" {
		t.Errorf("unset should be {disabled, auto}, got %+v", v)
	}
}

func TestDNSForwarding_RoundTripTrims(t *testing.T) {
	s := newDNSService(t)
	ctx := context.Background()
	got, err := s.SetDNSForwarding(ctx, DNSForwarding{Enabled: true, Upstream: "  9.9.9.9  "})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Upstream != "9.9.9.9" {
		t.Errorf("set should trim + persist, got %+v", got)
	}
	back, err := s.GetDNSForwarding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if back != got {
		t.Errorf("round-trip mismatch: set %+v got %+v", got, back)
	}
}

func TestDNSForwarding_BlankUpstreamIsAuto(t *testing.T) {
	got, err := newDNSService(t).SetDNSForwarding(context.Background(), DNSForwarding{Enabled: true, Upstream: "   "})
	if err != nil {
		t.Fatalf("blank upstream should be valid (auto): %v", err)
	}
	if got.Upstream != "" {
		t.Errorf("blank should normalize to auto, got %q", got.Upstream)
	}
}

func TestDNSForwarding_UpstreamValidation(t *testing.T) {
	s := newDNSService(t)
	ctx := context.Background()
	for _, ok := range []string{"1.2.3.4", "192.168.1.1:5353", "10.0.0.53"} {
		if _, err := s.SetDNSForwarding(ctx, DNSForwarding{Enabled: true, Upstream: ok}); err != nil {
			t.Errorf("upstream %q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"2001:db8::1", "[::1]:53", "not-an-ip", "1.2.3.4:99999", "1.2.3.4:abc"} {
		if _, err := s.SetDNSForwarding(ctx, DNSForwarding{Enabled: true, Upstream: bad}); err == nil {
			t.Errorf("upstream %q should be rejected", bad)
		}
	}
}
