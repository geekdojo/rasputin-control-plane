package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func bmcTestSetupStore(t *testing.T) *setup.Store {
	t.Helper()
	st, err := setup.OpenStore(context.Background(), filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatalf("setup store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSanitizeBMCConfig(t *testing.T) {
	// Non-bitscope passes through untouched.
	if got := sanitizeBMCConfig("mock", `{"targets":["a"]}`); string(got) != `{"targets":["a"]}` {
		t.Errorf("mock passthrough: %s", got)
	}
	// Legacy bitscope config with an embedded unlock: stripped + marked.
	got := sanitizeBMCConfig("bitscope", `{"dev":"/dev/serial0","unlock":"sekrit"}`)
	if strings.Contains(string(got), "sekrit") {
		t.Fatalf("unlock leaked: %s", got)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["unlockSet"] != true || m["dev"] != "/dev/serial0" {
		t.Errorf("sanitized: %v", m)
	}
	// Garbage never leaks raw bytes back.
	if got := sanitizeBMCConfig("bitscope", "not-json"); got != nil {
		t.Errorf("garbage: %s", got)
	}
}

func TestSetUnlockSet(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(setCredentialSet(json.RawMessage(`{"dev":"x"}`), "unlock"), &m); err != nil {
		t.Fatal(err)
	}
	if m["unlockSet"] != true || m["dev"] != "x" {
		t.Errorf("annotate: %v", m)
	}
	if err := json.Unmarshal(setCredentialSet(nil, "unlock"), &m); err != nil {
		t.Fatal(err)
	}
	if m["unlockSet"] != true {
		t.Errorf("annotate empty: %v", m)
	}
}

func TestStoreAndStripUnlock(t *testing.T) {
	ctx := context.Background()
	st := bmcTestSetupStore(t)

	// A typed unlock lands in its own key and never in the returned blob.
	out, err := storeAndStripCredential(ctx, st, bitscopeCred(), json.RawMessage(`{"dev":"/d","unlock":"newsecret","targets":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "newsecret") || strings.Contains(string(out), "unlock") {
		t.Fatalf("secret/field leaked into job-safe config: %s", out)
	}
	if v, _ := st.Get(ctx, setup.KeyBMCBitscopeUnlock); v != "newsecret" {
		t.Errorf("stored unlock: %q", v)
	}

	// Empty unlock keeps the stored secret.
	if _, err := storeAndStripCredential(ctx, st, bitscopeCred(), json.RawMessage(`{"dev":"/d","unlock":"","unlockSet":true}`)); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.Get(ctx, setup.KeyBMCBitscopeUnlock); v != "newsecret" {
		t.Errorf("empty unlock must keep stored secret, got %q", v)
	}

	// Bad JSON errors rather than passing through.
	if _, err := storeAndStripCredential(ctx, st, bitscopeCred(), json.RawMessage(`nope`)); err == nil {
		t.Error("bad json must error")
	}
}

// bitscopeCred is the bitscope credential descriptor, so the existing
// unlock tests keep exercising the exact behaviour they always did now
// that the strip/store path is table-driven rather than kind-hardcoded.
func bitscopeCred() bmc.CredentialField {
	c, ok := bmc.CredentialFor("bitscope")
	if !ok {
		panic("bitscope must declare a credential field")
	}
	return c
}

// Slot detection reads what each slot's getty prints; only the api can
// turn that into a Rasputin node id. The cases below are the real ones
// off the Turing Pi bench, 2026-07-28.
func TestMatchProbeSlotsAgainst(t *testing.T) {
	nodes := []*proto.Node{
		// The controlplane sets a transient hostname of "rasputin"
		// regardless of its node-id — the design assumed this would never
		// match and would fall through to the dropdown. It does match,
		// because inventory records that hostname, so matching on
		// hostname (not just id) auto-detects the controlplane too.
		{ID: "tp-cp1", Hostname: "rasputin", Role: proto.RoleControlPlane},
		{ID: "tp-n1", Hostname: "tp-n1", Role: proto.RoleCompute},
	}
	slots := []proto.BMCProbeSlot{
		{Slot: 1, Powered: true, Hostname: "rasputin"},
		{Slot: 2, Powered: true, Hostname: "tp-n1"},
		{Slot: 3, Powered: false, Detail: "slot is powered off"},
		{Slot: 4, Powered: true, Hostname: "somebody-elses-box"},
	}
	matchProbeSlotsAgainst(slots, nodes)

	if slots[0].NodeID != "tp-cp1" {
		t.Errorf("slot 1 (hostname rasputin) = %q, want tp-cp1 — the controlplane matches on hostname", slots[0].NodeID)
	}
	if slots[1].NodeID != "tp-n1" {
		t.Errorf("slot 2 = %q, want tp-n1", slots[1].NodeID)
	}
	if slots[2].NodeID != "" {
		t.Error("an unpowered slot has nothing to match and must stay unmapped")
	}
	// A hostname we do not recognise must NOT be guessed at — it may be a
	// node running something that is not Rasputin at all.
	if slots[3].NodeID != "" {
		t.Errorf("slot 4 = %q, want empty for an unknown hostname", slots[3].NodeID)
	}
	if !strings.Contains(slots[3].Detail, "somebody-elses-box") {
		t.Errorf("slot 4 detail should quote what the slot called itself; got %q", slots[3].Detail)
	}
}

// Two nodes answering to one hostname is ambiguous, and guessing would
// silently map a slot to the wrong machine — which then accepts power
// commands aimed at the other one.
func TestMatchProbeSlotsRefusesAmbiguousHostnames(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "a-1", Hostname: "rasputin"},
		{ID: "b-1", Hostname: "rasputin"},
	}
	slots := []proto.BMCProbeSlot{{Slot: 1, Powered: true, Hostname: "rasputin"}}
	matchProbeSlotsAgainst(slots, nodes)
	if slots[0].NodeID != "" {
		t.Errorf("ambiguous hostname matched %q — it must refuse and ask", slots[0].NodeID)
	}
	if !strings.Contains(slots[0].Detail, "more than one") {
		t.Errorf("detail should explain the ambiguity; got %q", slots[0].Detail)
	}
}

// An exact node-id always wins over a hostname that happens to collide.
func TestMatchProbeSlotsPrefersExactNodeID(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "tp-n1", Hostname: "something-else"},
		{ID: "other", Hostname: "tp-n1"},
	}
	slots := []proto.BMCProbeSlot{{Slot: 1, Powered: true, Hostname: "tp-n1"}}
	matchProbeSlotsAgainst(slots, nodes)
	if slots[0].NodeID != "tp-n1" {
		t.Errorf("got %q, want tp-n1 — an exact node-id match outranks a hostname match", slots[0].NodeID)
	}
}

// The password field is write-only, so it is blank every time Settings
// is reopened. A blank one must mean "use the stored password", the same
// as it does on the configure path — otherwise pressing DETECT BOARD on
// an already-configured cluster sends no credential, the slot reads get
// 401, and nothing populates. Reported from the bench 2026-07-29 as
// "still having to click DETECT BOARD twice, sometimes a few times".
func TestStoredCredentialBacksABlankProbePassword(t *testing.T) {
	ctx := context.Background()
	st := bmcTestSetupStore(t)

	// Nothing stored yet: a blank stays blank rather than inventing one.
	if got := bmc.StoredCredential(ctx, st, "turingpi"); got != "" {
		t.Errorf("with nothing stored, got %q, want empty", got)
	}
	// After a configure has saved one, the probe can fall back to it.
	if err := st.Set(ctx, setup.KeyBMCTuringPiPass, "s3cret"); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := bmc.StoredCredential(ctx, st, "turingpi"); got != "s3cret" {
		t.Errorf("got %q, want the stored password", got)
	}
	// Backends without a credential must not pick one up by accident.
	if got := bmc.StoredCredential(ctx, st, "mock"); got != "" {
		t.Errorf("mock has no credential; got %q", got)
	}
}
