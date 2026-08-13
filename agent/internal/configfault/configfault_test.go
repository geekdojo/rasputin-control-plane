package configfault

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func captureLog(f func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	f()
	return buf.String()
}

// A healthy node must add nothing at all — no key in the registration metadata,
// no summary line. "No faults" and "an empty faults list" are different claims
// and the wire should only ever carry the first by saying nothing.
func TestSet_CleanNodeIsSilent(t *testing.T) {
	var s Set
	if s.Any() {
		t.Error("a fresh Set must report no faults")
	}
	if s.Metadata() != nil {
		t.Error("Metadata() must be nil on a clean node, not an empty slice — absence is the signal")
	}
	if s.Summary() != "" {
		t.Errorf("Summary() = %q, want empty", s.Summary())
	}
}

// ⚠️ THE PROPERTY THIS PACKAGE EXISTS FOR. Recording a fault must be
// inseparable from announcing it. The whole hazard being fixed is a node that
// quietly does something other than what node.env asked for, so a Reject that
// could happen without a log line would reintroduce it in a quieter form.
func TestSet_RejectAlwaysLogs(t *testing.T) {
	var s Set
	out := captureLog(func() {
		s.Reject("RASPUTIN_UPDATE_BACKEND", "racu", []string{"rauc", "openwrt-ab", "mock"},
			"OS updates are disabled on this node")
	})
	if out == "" {
		t.Fatal("Reject recorded a fault without logging it — a fault nobody can see is the bug, not the fix")
	}
	for _, want := range []string{
		"RASPUTIN_UPDATE_BACKEND",              // which knob
		"racu",                                 // what they typed
		"rauc",                                 // …and what would have worked
		"OS updates are disabled on this node", // what it COST them
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q does not mention %q", out, want)
		}
	}
	if !s.Any() {
		t.Error("the fault must also be recorded, not only logged")
	}
}

// The log has to say the agent kept running, or an operator reading it will go
// looking for a crash that did not happen.
func TestSet_RejectSaysTheAgentSurvived(t *testing.T) {
	var s Set
	out := captureLog(func() {
		s.Reject("RASPUTIN_BMC_BACKEND", "turingpi", []string{"none", "bitscope"}, "BMC is OFF on this node")
	})
	if !strings.Contains(out, "starting anyway") {
		t.Errorf("log %q must say the agent started anyway — the fix is that this is survivable", out)
	}
	if !strings.Contains(out, "node.env") {
		t.Errorf("log %q must name the file to edit", out)
	}
}

// Metadata is what carries the fault off the box. If this shape drifts, a node
// stays silent to the control plane while looking correct locally — the exact
// half-fix this package was written to avoid.
func TestSet_MetadataCarriesEveryField(t *testing.T) {
	var s Set
	_ = captureLog(func() {
		s.Reject("RASPUTIN_UCI_BACKEND", "uic", []string{"uci", "mock"}, "firewall configuration is disabled")
	})
	md := s.Metadata()
	if len(md) != 1 {
		t.Fatalf("Metadata() has %d entries, want 1", len(md))
	}
	got := md[0]
	if got["variable"] != "RASPUTIN_UCI_BACKEND" {
		t.Errorf("variable = %v", got["variable"])
	}
	if got["value"] != "uic" {
		t.Errorf("value = %v", got["value"])
	}
	if got["effect"] != "firewall configuration is disabled" {
		t.Errorf("effect = %v", got["effect"])
	}
	exp, ok := got["expected"].([]string)
	if !ok || len(exp) != 2 {
		t.Errorf("expected = %v, want the two valid options", got["expected"])
	}
}

func TestSet_MultipleFaultsAllSurvive(t *testing.T) {
	var s Set
	_ = captureLog(func() {
		s.Reject("A", "x", nil, "a broke")
		s.Reject("B", "y", nil, "b broke")
	})
	if len(s.List()) != 2 {
		t.Fatalf("List() has %d, want 2 — one bad value must not mask another", len(s.List()))
	}
	sum := s.Summary()
	if !strings.Contains(sum, "A") || !strings.Contains(sum, "B") || !strings.Contains(sum, "2") {
		t.Errorf("Summary() = %q, want the count and both variables", sum)
	}
}

// The rendering an operator actually reads. It must lead with the variable and
// end with the consequence — "unknown backend" is a fact about a string,
// "updates are disabled" is a fact about their fleet.
func TestFault_StringNamesTheKnobAndTheCost(t *testing.T) {
	f := Fault{
		Variable: "RASPUTIN_TAILSCALE_BACKEND",
		Value:    "tailscal",
		Expected: []string{"tailscale", "mock"},
		Effect:   "mesh join/leave is disabled on this node",
	}
	got := f.String()
	for _, want := range []string{"RASPUTIN_TAILSCALE_BACKEND", "tailscal", "tailscale|mock", "mesh join/leave is disabled"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}
