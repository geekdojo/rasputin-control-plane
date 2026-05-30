package proto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Subject builders
// ============================================================================

func TestNodeSubjectBuilders(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"NodeCmdSubject", NodeCmdSubject("n1", "diag.ping"), "rasputin.node.n1.cmd.diag.ping"},
		{"NodeCmdFilter", NodeCmdFilter("n1"), "rasputin.node.n1.cmd.>"},
		{"NodeEvtSubject", NodeEvtSubject("n1", "registered"), "rasputin.node.n1.evt.registered"},
		{"NodeHeartbeatSubject", NodeHeartbeatSubject("n1"), "rasputin.node.n1.heartbeat"},
		{"NodeRegisteredSubject", NodeRegisteredSubject("n1"), "rasputin.node.n1.evt.registered"},
		{"NodeMetricsSubject", NodeMetricsSubject("n1"), "rasputin.node.n1.metrics"},
		{"JobEventsSubject", JobEventsSubject("j1"), "rasputin.job.j1.events"},
		{"JobLogSubject", JobLogSubject("j1"), "rasputin.job.j1.log"},
		{"InventoryChangedSubject", InventoryChangedSubject("n1", "added"), "rasputin.inventory.n1.added"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestAllFiltersAreConstants(t *testing.T) {
	// Regression canary: these filter strings are referenced from many places
	// in the api and UI. If anyone changes them in a refactor, they should
	// have to update this test, which will jog them into auditing all
	// subscribers too.
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"AllJobsFilter", AllJobsFilter, "rasputin.job.>"},
		{"AllInventoryFilter", AllInventoryFilter, "rasputin.inventory.>"},
		{"AllHeartbeatsFilter", AllHeartbeatsFilter, "rasputin.node.*.heartbeat"},
		{"AllMetricsFilter", AllMetricsFilter, "rasputin.node.*.metrics"},
		{"AllAppsFilter", AllAppsFilter, "rasputin.apps.>"},
		{"AllBMCChangesFilter", AllBMCChangesFilter, "rasputin.bmc.*.*"},
		{"AllFirewallChangesFilter", AllFirewallChangesFilter, "rasputin.firewall.>"},
		{"AllMeshChangesFilter", AllMeshChangesFilter, "rasputin.mesh.>"},
		{"AllUpdatesFilter", AllUpdatesFilter, "rasputin.updates.>"},
		{"AllUpdateProgressFilter", AllUpdateProgressFilter, "rasputin.node.*.evt.update.>"},
		{"AllSystemUpdatesFilter", AllSystemUpdatesFilter, "rasputin.updates.system.>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// ============================================================================
// Subsystem subject helpers
// ============================================================================

func TestAppSubjects(t *testing.T) {
	if got := AppDeploySubject("n1"); got != "rasputin.node.n1.cmd.docker.deploy" {
		t.Errorf("AppDeploySubject: %q", got)
	}
	if got := AppStopSubject("n1"); got != "rasputin.node.n1.cmd.docker.stop" {
		t.Errorf("AppStopSubject: %q", got)
	}
	if got := AppStatusSubject("n1"); got != "rasputin.node.n1.cmd.docker.status" {
		t.Errorf("AppStatusSubject: %q", got)
	}
	if got := AppChangeSubject("a1", AppDeployed); got != "rasputin.apps.a1.deployed" {
		t.Errorf("AppChangeSubject: %q", got)
	}
}

func TestBMCSubjects(t *testing.T) {
	if got := BMCPowerSubject("h1", BMCPowerOn); got != "rasputin.node.h1.cmd.bmc.power.on" {
		t.Errorf("BMCPowerSubject: %q", got)
	}
	if got := BMCSOLOpenSubject("h1"); got != "rasputin.node.h1.cmd.bmc.sol.open" {
		t.Errorf("BMCSOLOpenSubject: %q", got)
	}
	if got := BMCSOLCloseSubject("h1"); got != "rasputin.node.h1.cmd.bmc.sol.close" {
		t.Errorf("BMCSOLCloseSubject: %q", got)
	}
	if got := BMCSOLInSubject("s1"); got != "rasputin.bmc.sol.s1.in" {
		t.Errorf("BMCSOLInSubject: %q", got)
	}
	if got := BMCSOLOutSubject("s1"); got != "rasputin.bmc.sol.s1.out" {
		t.Errorf("BMCSOLOutSubject: %q", got)
	}
	if got := BMCChangeSubject("t1", BMCPoweredOn); got != "rasputin.bmc.t1.powered_on" {
		t.Errorf("BMCChangeSubject: %q", got)
	}
}

func TestFirewallSubjects(t *testing.T) {
	if got := FirewallApplySubject("n1"); got != "rasputin.node.n1.cmd.firewall.apply" {
		t.Errorf("FirewallApplySubject: %q", got)
	}
	if got := FirewallGetSubject("n1"); got != "rasputin.node.n1.cmd.firewall.get" {
		t.Errorf("FirewallGetSubject: %q", got)
	}
	if got := FirewallChangeSubject("n1", FirewallApplied); got != "rasputin.firewall.n1.applied" {
		t.Errorf("FirewallChangeSubject: %q", got)
	}
}

func TestMeshSubjects(t *testing.T) {
	if got := MeshEnrollSubject("n1"); got != "rasputin.node.n1.cmd.mesh.enroll" {
		t.Errorf("MeshEnrollSubject: %q", got)
	}
	if got := MeshLeaveSubject("n1"); got != "rasputin.node.n1.cmd.mesh.leave" {
		t.Errorf("MeshLeaveSubject: %q", got)
	}
	if got := MeshStatusSubject("n1"); got != "rasputin.node.n1.cmd.mesh.status" {
		t.Errorf("MeshStatusSubject: %q", got)
	}
	if got := MeshChangeSubject("n1", MeshApplied); got != "rasputin.mesh.n1.applied" {
		t.Errorf("MeshChangeSubject: %q", got)
	}
	if got := MeshChangeSubject("global", MeshInSync); got != "rasputin.mesh.global.in_sync" {
		t.Errorf("MeshChangeSubject(global): %q", got)
	}
}

func TestUpdateSubjects(t *testing.T) {
	cases := map[string]string{
		UpdatePrecheckSubject("n1"):                          "rasputin.node.n1.cmd.update.precheck",
		UpdateDownloadSubject("n1"):                          "rasputin.node.n1.cmd.update.download",
		UpdateInstallSubject("n1"):                           "rasputin.node.n1.cmd.update.install",
		UpdateRebootSubject("n1"):                            "rasputin.node.n1.cmd.update.reboot",
		UpdateMarkGoodSubject("n1"):                          "rasputin.node.n1.cmd.update.mark-good",
		UpdateMarkBadSubject("n1"):                           "rasputin.node.n1.cmd.update.mark-bad",
		UpdateDownloadProgressSubject("n1"):                  "rasputin.node.n1.evt.update.download.progress",
		UpdateInstallProgressSubject("n1"):                   "rasputin.node.n1.evt.update.install.progress",
		UpdateChangeSubject("n1", UpdateStarted):             "rasputin.updates.n1.started",
		SystemUpdateChangeSubject("p1", SystemUpdatePlanned): "rasputin.updates.system.p1.planned",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("subject mismatch: got %q want %q", got, want)
		}
	}
}

// Regression: BMC routing is keyed on the BMC host, but the target node id is
// in the body — the subject must not contain the target id. This is a Locked
// architectural decision (see bmc.go top-of-file comment) and any subject
// builder that smuggles the target into the wire path will break the saga.
func TestBMCPowerSubjectDoesNotContainTarget(t *testing.T) {
	s := BMCPowerSubject("bmc-host-id", BMCPowerOn)
	if strings.Contains(s, "target") {
		t.Errorf("BMC subject must not encode the target node id, got %q", s)
	}
	// The subject must mention the BMC host, not the target.
	if !strings.Contains(s, "bmc-host-id") {
		t.Errorf("BMC subject should encode the host id, got %q", s)
	}
}

// ============================================================================
// Validators
// ============================================================================

func TestValidRole(t *testing.T) {
	for _, r := range AllRoles {
		if !ValidRole(r) {
			t.Errorf("AllRoles entry %q should be valid", r)
		}
	}
	if ValidRole(NodeRole("nonsense")) {
		t.Error("nonsense role should not validate")
	}
	if ValidRole("") {
		t.Error("empty role should not validate")
	}
}

func TestValidBMCPowerVerb(t *testing.T) {
	for _, v := range AllBMCPowerVerbs {
		if !ValidBMCPowerVerb(v) {
			t.Errorf("AllBMCPowerVerbs entry %q should be valid", v)
		}
	}
	if ValidBMCPowerVerb(BMCPowerVerb("delete")) {
		t.Error("'delete' is not a valid BMC verb")
	}
}

func TestValidFirewallIntentKind(t *testing.T) {
	for _, k := range AllFirewallIntentKinds {
		if !ValidFirewallIntentKind(k) {
			t.Errorf("AllFirewallIntentKinds entry %q should be valid", k)
		}
	}
	if ValidFirewallIntentKind(FirewallIntentKind("nope")) {
		t.Error("unknown intent kind should not validate")
	}
}

func TestValidMeshIntentKind(t *testing.T) {
	for _, k := range AllMeshIntentKinds {
		if !ValidMeshIntentKind(k) {
			t.Errorf("AllMeshIntentKinds entry %q should be valid", k)
		}
	}
	if ValidMeshIntentKind(MeshIntentKind("dns_record")) {
		t.Error("dns_record is not a supported intent kind")
	}
}

// ============================================================================
// JSON round-trips — verify the wire shape stays stable
// ============================================================================

func TestNodeRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := Node{
		ID:           "cp-1",
		Role:         RoleControlPlane,
		Hostname:     "cp-1.local",
		AgentVersion: "0.1.0",
		Capabilities: []string{"bmc", "docker"},
		Metadata:     map[string]any{"arch": "arm64"},
		FirstSeen:    now.Add(-time.Hour),
		LastSeen:     now,
		Status:       StatusOnline,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Spot-check key tag is camelCase.
	if !strings.Contains(string(b), `"agentVersion"`) {
		t.Errorf("expected camelCase agentVersion in %s", string(b))
	}
	var out Node
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ID != in.ID || out.Role != in.Role || out.Status != in.Status {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}
	if !out.LastSeen.Equal(in.LastSeen) {
		t.Errorf("timestamps drift: got %v want %v", out.LastSeen, in.LastSeen)
	}
}

func TestAlertRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := Alert{
		ID:          "node-offline:n1",
		Severity:    AlertCrit,
		Source:      AlertSourceNode,
		Title:       "n1 offline",
		Detail:      "silent for 2h",
		Since:       now,
		RelatedKind: "node",
		RelatedID:   "n1",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Alert
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestJobEventRoundTrip(t *testing.T) {
	stepData, _ := json.Marshal(StepEventData{Seq: 1, Name: "verify", Attempt: 1})
	now := time.Now().UTC().Truncate(time.Second)
	in := JobEvent{
		Type:  JobStepStarted,
		JobID: "j-123",
		Ts:    now,
		Data:  stepData,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out JobEvent
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Type != in.Type || out.JobID != in.JobID {
		t.Errorf("type/id mismatch: got %+v want %+v", out, in)
	}
	var got StepEventData
	if err := json.Unmarshal(out.Data, &got); err != nil {
		t.Fatalf("unmarshal step data: %v", err)
	}
	if got.Seq != 1 || got.Name != "verify" {
		t.Errorf("step data lost: %+v", got)
	}
}

func TestMetricsEvtRoundTrip(t *testing.T) {
	in := MetricsEvt{
		NodeID: "n1",
		Ts:     time.Now().UTC().Truncate(time.Second),
		Metrics: map[string]float64{
			MetricCPUPercent:    42.5,
			MetricMemUsedBytes:  1 << 20,
			MetricMemTotalBytes: 1 << 30,
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out MetricsEvt
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.NodeID != in.NodeID {
		t.Errorf("node id lost: %q vs %q", out.NodeID, in.NodeID)
	}
	if out.Metrics[MetricCPUPercent] != 42.5 {
		t.Errorf("cpu metric lost: %v", out.Metrics)
	}
}

func TestBMCPowerAckRoundTrip(t *testing.T) {
	in := BMCPowerAck{OK: true, State: BMCStateOn, Detail: "powered on"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"ok":true`) {
		t.Errorf("expected ok:true in payload, got %s", string(b))
	}
	var out BMCPowerAck
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}
}

func TestUpdatePrecheckAckRoundTrip(t *testing.T) {
	in := UpdatePrecheckAck{
		OK:             true,
		ActiveSlot:     SlotA,
		InactiveSlot:   SlotB,
		CurrentVersion: "1.2.3",
		AvailableBytes: 1 << 30,
		Backend:        "mock",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out UpdatePrecheckAck
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestSystemUpdateChangeEvtRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := SystemUpdateChangeEvt{
		ParentJobID: "p-1",
		Change:      SystemUpdateCompleted,
		Counts:      &SystemUpdateCounts{Total: 3, Succeeded: 3},
		Ts:          now,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out SystemUpdateChangeEvt
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ParentJobID != in.ParentJobID || out.Change != in.Change {
		t.Errorf("change mismatch: %+v vs %+v", out, in)
	}
	if out.Counts == nil || out.Counts.Total != 3 || out.Counts.Succeeded != 3 {
		t.Errorf("counts lost: %+v", out.Counts)
	}
}

func TestHeartbeatEvtRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := HeartbeatEvt{
		NodeID:       "n1",
		Uptime:       "1h2m3s",
		AgentVersion: "0.1.0",
		Ts:           now,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out HeartbeatEvt
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch: %+v vs %+v", out, in)
	}
}

func TestInventoryChangeEvtRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := InventoryChangeEvt{
		Change: InventoryAdded,
		Node:   Node{ID: "n1", Role: RoleCompute, Status: StatusOnline, FirstSeen: now, LastSeen: now},
		Ts:     now,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out InventoryChangeEvt
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Change != in.Change || out.Node.ID != in.Node.ID {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}

func TestBundleManifestRoundTrip(t *testing.T) {
	in := BundleManifest{
		Version:      "1.2.3",
		Compatible:   "rasputin-pi5-cm5",
		Architecture: "arm64",
		SHA256:       strings.Repeat("a", 64),
		SizeBytes:    100 * 1 << 20,
		SignedBy:     "rasputin-release",
		SlotImages:   []string{"rootfs.0", "rootfs.1"},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out BundleManifest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Version != in.Version || out.SHA256 != in.SHA256 {
		t.Errorf("round-trip mismatch: %+v", out)
	}
	if len(out.SlotImages) != 2 {
		t.Errorf("slot images lost: %v", out.SlotImages)
	}
}
