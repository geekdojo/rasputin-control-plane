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

// A fault with no Expected list must NOT print an empty "(expected )" clause.
// Expected is omitempty on the wire and the whole point of the parenthetical is
// to name the values that WOULD have worked — with none to name, the clause is
// noise that reads like a rendering bug. Guards the `len(f.Expected) > 0` gate:
// a boundary slip to `>= 0` (always true) would append "(expected )" here, and
// no other test exercises the empty-Expected path.
func TestFault_StringOmitsExpectedClauseWhenNoneGiven(t *testing.T) {
	f := Fault{
		Variable: "RASPUTIN_UPDATE_BACKEND",
		Value:    "racu",
		Expected: nil, // operator help lists nothing — omit the clause entirely
		Effect:   "OS updates are disabled on this node",
	}
	got := f.String()
	if strings.Contains(got, "expected") {
		t.Errorf("String() = %q, must not carry an '(expected ...)' clause when Expected is empty", got)
	}
	if strings.Contains(got, "(") {
		t.Errorf("String() = %q, must not open a parenthetical with nothing to put in it", got)
	}
	// The knob and the consequence must still be there.
	for _, want := range []string{"RASPUTIN_UPDATE_BACKEND", "racu", "OS updates are disabled on this node"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
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

// ⚠️ THE 2026-09-01 PROPERTY. Unavailable exists because a missing prerequisite
// used to become a mock, and a mock answers with fixture hardware. Like Reject,
// recording must be inseparable from announcing — a subsystem that disabled
// itself in silence is only marginally better than one that lied.
func TestSet_UnavailableAlwaysLogs(t *testing.T) {
	var s Set
	out := captureLog(func() {
		s.Unavailable("RASPUTIN_STORAGE_BACKEND", []string{"blockdev"}, "not on PATH: wipefs",
			"backup-target selection is disabled on this node")
	})
	if out == "" {
		t.Fatal("Unavailable recorded a fault without logging it — a fault nobody can see is the " +
			"failure this package exists to prevent")
	}
	for _, want := range []string{"RASPUTIN_STORAGE_BACKEND", "wipefs", "blockdev",
		"backup-target selection is disabled"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q does not mention %q", out, want)
		}
	}
	// The remedy differs from Reject's: nothing was typed wrong, so telling
	// the operator to correct node.env would send them looking for a typo
	// that does not exist. It must point at the missing prerequisite instead.
	if !strings.Contains(out, "No mock was substituted") {
		t.Errorf("log %q must say no mock was substituted — that is the guarantee being made", out)
	}
	if !s.Any() {
		t.Error("Unavailable must record the fault, not only log it")
	}
}

// Unavailable and Reject are different claims and must not read alike: one says
// "you asked for something that does not exist", the other "you asked for
// nothing and this machine cannot do it".
func TestFault_UnavailableReadsDifferentlyFromReject(t *testing.T) {
	unavailable := Fault{
		Variable: "RASPUTIN_STORAGE_BACKEND",
		Expected: []string{"blockdev"},
		Missing:  "not on PATH: wipefs",
		Effect:   "backup-target selection is disabled on this node",
	}
	got := unavailable.String()
	if strings.Contains(got, "is not recognised") {
		t.Errorf("Fault.String() = %q — an unavailable backend is not an unrecognised value; "+
			"the operator typed nothing", got)
	}
	for _, want := range []string{"RASPUTIN_STORAGE_BACKEND", "wipefs", "blockdev"} {
		if !strings.Contains(got, want) {
			t.Errorf("Fault.String() = %q does not mention %q", got, want)
		}
	}
	// A rejected value keeps its original wording — this change is additive.
	rejected := Fault{Variable: "RASPUTIN_UCI_BACKEND", Value: "uic",
		Expected: []string{"uci", "mock"}, Effect: "firewall configuration is disabled"}
	if !strings.Contains(rejected.String(), "is not recognised") {
		t.Errorf("Fault.String() for a rejected value = %q, want the unrecognised wording",
			rejected.String())
	}
}

// The fault has to leave the box, exactly as a rejected value does — the
// journal on an appliance is not a reporting channel. `missing` rides along so
// the control plane can say which tool to add; `effect` carries the same detail
// for consumers written before this field existed.
func TestSet_UnavailableMetadataCarriesMissing(t *testing.T) {
	var s Set
	captureLog(func() {
		s.Unavailable("RASPUTIN_TAILSCALE_BACKEND", []string{"tailscale"},
			"the tailscale CLI is not on PATH", "mesh join/leave is disabled on this node")
	})

	md := s.Metadata()
	if len(md) != 1 {
		t.Fatalf("Metadata() = %v, want one entry", md)
	}
	if md[0]["missing"] != "the tailscale CLI is not on PATH" {
		t.Errorf("metadata missing = %v, want the prerequisite", md[0]["missing"])
	}
	if md[0]["variable"] != "RASPUTIN_TAILSCALE_BACKEND" {
		t.Errorf("metadata variable = %v", md[0]["variable"])
	}
	// value stays empty: nothing was typed. Consumers distinguish the two
	// kinds by `missing`, not by guessing from an empty string.
	if md[0]["value"] != "" {
		t.Errorf("metadata value = %v, want empty for an unavailable backend", md[0]["value"])
	}

	// A rejected value must NOT grow the key — the shape older consumers were
	// written against stays byte-for-byte identical.
	var r Set
	captureLog(func() {
		r.Reject("RASPUTIN_UCI_BACKEND", "uic", []string{"uci", "mock"}, "firewall config disabled")
	})
	if _, ok := r.Metadata()[0]["missing"]; ok {
		t.Error("a rejected value must not carry a `missing` key")
	}
}
