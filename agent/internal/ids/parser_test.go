package ids

import (
	"testing"
	"time"
)

// fixedNow returns a stable "now" so parseAlertTs's year-borrowing path
// is deterministic in tests.
func fixedNow() time.Time {
	return time.Date(2026, time.June, 8, 12, 0, 0, 0, time.UTC)
}

func TestParseAlertFast_TypicalET(t *testing.T) {
	// ET POLICY rule, classic IPv4+TCP shape — the most common alert form.
	line := `06/08-14:23:45.123456 [**] [1:2009582:5] ET POLICY HTTP traffic on port 443 (POST) [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.50:54321 -> 8.8.8.8:443`
	ev, ok, err := ParseAlertFast("node-fw", line, fixedNow)
	if err != nil || !ok {
		t.Fatalf("expected parse success; ok=%v err=%v", ok, err)
	}
	if ev.NodeID != "node-fw" {
		t.Errorf("NodeID: got %q want node-fw", ev.NodeID)
	}
	if ev.GID != 1 || ev.SID != 2009582 || ev.Rev != 5 {
		t.Errorf("gid:sid:rev = %d:%d:%d want 1:2009582:5", ev.GID, ev.SID, ev.Rev)
	}
	if ev.Message != "ET POLICY HTTP traffic on port 443 (POST)" {
		t.Errorf("Message %q unexpected", ev.Message)
	}
	if ev.Classification != "Potentially Bad Traffic" {
		t.Errorf("Classification %q unexpected", ev.Classification)
	}
	if ev.Priority != 2 {
		t.Errorf("Priority = %d want 2", ev.Priority)
	}
	if ev.Protocol != "TCP" {
		t.Errorf("Protocol %q want TCP", ev.Protocol)
	}
	if ev.SrcAddr != "192.168.1.50" || ev.SrcPort != 54321 {
		t.Errorf("src = %s:%d want 192.168.1.50:54321", ev.SrcAddr, ev.SrcPort)
	}
	if ev.DstAddr != "8.8.8.8" || ev.DstPort != 443 {
		t.Errorf("dst = %s:%d want 8.8.8.8:443", ev.DstAddr, ev.DstPort)
	}
	// Year-less ts borrows fixedNow's year (2026).
	if ev.Ts.Year() != 2026 || ev.Ts.Month() != time.June || ev.Ts.Day() != 8 {
		t.Errorf("ts year/month/day = %d-%d-%d want 2026-6-8", ev.Ts.Year(), ev.Ts.Month(), ev.Ts.Day())
	}
	if ev.Raw != line {
		t.Errorf("Raw didn't preserve the line verbatim")
	}
}

func TestParseAlertFast_NoClassificationNoPriority(t *testing.T) {
	// Some rules omit classtype/priority. Parser must not require them.
	line := `06/08-14:23:45.123456 [**] [1:1000001:1] CUSTOM rule sans extras [**] {TCP} 10.0.0.1:1 -> 10.0.0.2:2`
	ev, ok, err := ParseAlertFast("n", line, fixedNow)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.Classification != "" || ev.Priority != 0 {
		t.Errorf("missing class/prio should be zero values; got %q / %d", ev.Classification, ev.Priority)
	}
	if ev.Protocol != "TCP" || ev.SrcAddr != "10.0.0.1" || ev.DstAddr != "10.0.0.2" {
		t.Errorf("addr/proto parse degraded: %+v", ev)
	}
}

func TestParseAlertFast_IPv6Brackets(t *testing.T) {
	line := `06/08-14:23:45.123456 [**] [1:2:3] v6 test [**] [Classification: Misc] [Priority: 3] {TCP} [fe80::1]:443 -> [2001:db8::5]:80`
	ev, ok, err := ParseAlertFast("n", line, fixedNow)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.SrcAddr != "fe80::1" || ev.SrcPort != 443 {
		t.Errorf("v6 src = %s:%d want fe80::1:443", ev.SrcAddr, ev.SrcPort)
	}
	if ev.DstAddr != "2001:db8::5" || ev.DstPort != 80 {
		t.Errorf("v6 dst = %s:%d want 2001:db8::5:80", ev.DstAddr, ev.DstPort)
	}
}

func TestParseAlertFast_ICMPNoPort(t *testing.T) {
	line := `06/08-14:23:45.123456 [**] [1:1000:1] ICMP echo [**] [Classification: Misc] [Priority: 3] {ICMP} 192.168.1.1 -> 192.168.1.2`
	ev, ok, err := ParseAlertFast("n", line, fixedNow)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.Protocol != "ICMP" {
		t.Errorf("Protocol %q want ICMP", ev.Protocol)
	}
	if ev.SrcAddr != "192.168.1.1" || ev.SrcPort != 0 {
		t.Errorf("ICMP src should have no port; got %s:%d", ev.SrcAddr, ev.SrcPort)
	}
	if ev.DstAddr != "192.168.1.2" || ev.DstPort != 0 {
		t.Errorf("ICMP dst should have no port; got %s:%d", ev.DstAddr, ev.DstPort)
	}
}

func TestParseAlertFast_YearIncluded(t *testing.T) {
	// Snort can be configured to include the year — `output { alert_fast = { include_year = true } }`.
	line := `06/08/2025-14:23:45.123456 [**] [1:2:3] year test [**] [Classification: Misc] [Priority: 3] {TCP} 1.1.1.1:1 -> 2.2.2.2:2`
	ev, ok, err := ParseAlertFast("n", line, fixedNow)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.Ts.Year() != 2025 {
		t.Errorf("explicit year should win over fixedNow's 2026; got %d", ev.Ts.Year())
	}
}

func TestParseAlertFast_EmptyAndJunk(t *testing.T) {
	cases := []string{
		"",
		"\n",
		"-- snort starting --",
		"random log line no alert here",
		"06/08-14:23:45.xxxxxxxx [**] busted timestamp [**] {TCP} 1.1.1.1:1 -> 2.2.2.2:2", // malformed ts → regex doesn't match
	}
	for _, line := range cases {
		ev, ok, err := ParseAlertFast("n", line, fixedNow)
		if err != nil {
			t.Errorf("junk line should NOT error; line=%q err=%v", line, err)
		}
		if ok {
			t.Errorf("junk line should NOT parse as ok; line=%q got %+v", line, ev)
		}
	}
}

func TestParseAlertFast_PreservesRawNewlines(t *testing.T) {
	// Tailers commonly hand us lines with trailing \n; the parser should strip it.
	line := "06/08-14:23:45.123456 [**] [1:1:1] x [**] {TCP} 1.1.1.1:1 -> 2.2.2.2:2\n"
	ev, ok, _ := ParseAlertFast("n", line, fixedNow)
	if !ok {
		t.Fatal("should parse")
	}
	if got := ev.Raw[len(ev.Raw)-1]; got == '\n' {
		t.Error("Raw should have trailing newline stripped")
	}
}
