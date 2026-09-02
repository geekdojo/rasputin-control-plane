package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server and returns a connected client.
// Both shut down on test cleanup. Same harness as the updater's handler tests.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	ns, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatalf("nats new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready in 2s")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func requestInto[T any](t *testing.T, nc *nats.Conn, subj string, cmd any, out *T) {
	t.Helper()
	payload, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg, err := nc.Request(subj, payload, 5*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subj, err)
	}
	if err := json.Unmarshal(msg.Data, out); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
}

func registered(t *testing.T) (*nats.Conn, *MockBackend, string) {
	t.Helper()
	nc := startNATS(t)
	m := newTestMock(t, defaultMockMachine())
	// A real staging directory, because the backup write verb reads a file out
	// of it. Empty would disable that verb, which would make every backup
	// handler case here assert the disabled path instead of the real one.
	stagingRoot := t.TempDir()
	subs, err := RegisterHandlers(nc, "node-1", m, stagingRoot)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	return nc, m, stagingRoot
}

func TestHandlers_EnumerateOverTheBus(t *testing.T) {
	nc, _, _ := registered(t)
	var ack proto.StorageEnumerateAck
	requestInto(t, nc, proto.StorageEnumerateSubject("node-1"), proto.StorageEnumerateCmd{}, &ack)

	if !ack.OK || ack.Backend != "mock" {
		t.Fatalf("ack = %+v", ack)
	}
	if len(ack.Candidates) != 3 {
		t.Fatalf("candidates = %d, want 3", len(ack.Candidates))
	}
	var protected int
	for _, c := range ack.Candidates {
		if c.Protected {
			protected++
			if c.ProtectedReason == "" {
				t.Error("a protected candidate crossed the wire with no reason")
			}
		}
		if c.Fingerprint == "" {
			t.Errorf("%s crossed the wire with no fingerprint — nothing could then be claimed", c.DevicePath)
		}
	}
	if protected != 1 {
		t.Errorf("protected candidates = %d, want exactly the boot disk", protected)
	}
}

func TestHandlers_ClaimRefusalsCarryTheirCode(t *testing.T) {
	nc, m, _ := registered(t)
	list := enumerate(t, m)
	boot := candidateBySerial(t, list, "SN-BOOT-0001")
	spare := candidateBySerial(t, list, "SN-SPARE-0002")

	cases := []struct {
		name string
		cmd  proto.StorageClaimCmd
		want proto.StorageRefusal
	}{
		{"the boot disk", proto.StorageClaimCmd{DevicePath: boot.DevicePath, Fingerprint: boot.Fingerprint}, proto.StorageRefusalProtected},
		{"a stale fingerprint", proto.StorageClaimCmd{DevicePath: spare.DevicePath, Fingerprint: "stale"}, proto.StorageRefusalFingerprintMismatch},
		{"no fingerprint", proto.StorageClaimCmd{DevicePath: spare.DevicePath}, proto.StorageRefusalFingerprintMismatch},
		{"an absent device", proto.StorageClaimCmd{DevicePath: "/dev/nvme9n1", Fingerprint: "x"}, proto.StorageRefusalDeviceAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ack proto.StorageClaimAck
			requestInto(t, nc, proto.StorageClaimSubject("node-1"), tc.cmd, &ack)
			if ack.OK {
				t.Fatalf("claim succeeded: %+v", ack)
			}
			if ack.Refusal != tc.want {
				t.Errorf("refusal = %q, want %q (detail: %s)", ack.Refusal, tc.want, ack.Detail)
			}
			if ack.Detail == "" {
				t.Error("a refusal with no detail — the operator is told no and not why")
			}
		})
	}
	// Nothing was formatted by any of that.
	assertUnformatted(t, m, "SN-BOOT-0001", 3)
	assertUnformatted(t, m, "SN-SPARE-0002", 0)
}

func TestHandlers_ClaimHappyPathStampsClusterAndKeyID(t *testing.T) {
	nc, m, _ := registered(t)
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

	var ack proto.StorageClaimAck
	requestInto(t, nc, proto.StorageClaimSubject("node-1"), proto.StorageClaimCmd{
		DevicePath:  spare.DevicePath,
		Fingerprint: spare.Fingerprint,
		Label:       "weekly archive",
		ClusterID:   "bitscope",
		KeyID:       "key-7",
	}, &ack)

	if !ack.OK {
		t.Fatalf("claim failed: %+v", ack)
	}
	if ack.PartUUID == "" || ack.MountPath == "" {
		t.Fatalf("ack is missing the target: %+v", ack)
	}
	if ack.BackupSet == nil {
		t.Fatal("no backup set in the ack")
	}
	if ack.BackupSet.ClusterID != "bitscope" || ack.BackupSet.KeyID != "key-7" {
		t.Errorf("cluster/key id not stamped: %+v", ack.BackupSet)
	}
	if ack.Refusal != "" {
		t.Errorf("a successful claim carries refusal %q", ack.Refusal)
	}

	// The whole ack, as JSON, must not contain anything secret. §4.6's private
	// key never enters the job ledger, and the ack is what the saga records.
	// (The PUBLIC key may appear inside BackupSet and is not on this list — it
	// is the one piece of key material that is meant to travel in clear.)
	b, err := json.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"passphrase", "recoveryCode", "dataKey", "privateKey", "wrappedKey"} {
		if containsFold(string(b), forbidden) {
			t.Errorf("the claim ack contains %q: %s", forbidden, b)
		}
	}
}

func TestHandlers_MountAndInspect(t *testing.T) {
	nc, m, _ := registered(t)
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	claim, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	var mount proto.StorageMountAck
	requestInto(t, nc, proto.StorageMountSubject("node-1"), proto.StorageMountCmd{PartUUID: claim.PartUUID}, &mount)
	if !mount.OK || mount.MountPath != claim.MountPath {
		t.Fatalf("mount ack = %+v", mount)
	}

	var inspect proto.StorageInspectAck
	requestInto(t, nc, proto.StorageInspectSubject("node-1"), proto.StorageInspectCmd{PartUUID: claim.PartUUID}, &inspect)
	if !inspect.OK || !inspect.Present {
		t.Fatalf("inspect ack = %+v", inspect)
	}
	if inspect.FSLabel != proto.StorageBackupLabel {
		t.Errorf("fs label = %q", inspect.FSLabel)
	}

	// A partition of the boot disk is refused even by the read-only verbs.
	var refused proto.StorageMountAck
	requestInto(t, nc, proto.StorageMountSubject("node-1"), proto.StorageMountCmd{PartUUID: "boot-data-0001"}, &refused)
	if refused.OK || refused.Refusal != proto.StorageRefusalProtected {
		t.Errorf("mounting the persistent partition was not refused as protected: %+v", refused)
	}
}

// A malformed destructive command is refused at the boundary rather than
// unmarshalled into a zero value and pushed one layer down.
func TestHandlers_MalformedClaimIsRefused(t *testing.T) {
	nc, m, _ := registered(t)
	msg, err := nc.Request(proto.StorageClaimSubject("node-1"), []byte("{not json"), 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.StorageClaimAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if ack.OK || ack.Refusal != proto.StorageRefusalBackendError {
		t.Errorf("ack = %+v", ack)
	}
	assertUnformatted(t, m, "SN-SPARE-0002", 0)
}

// Enumerate failing must come back as a refusal, not a dropped request — a
// request that times out is indistinguishable from an offline node.
func TestHandlers_EnumerateFailureStillAnswers(t *testing.T) {
	t.Setenv("RASPUTIN_STORAGE_FAIL_MODE", "enumerate")
	nc, _, _ := registered(t)
	var ack proto.StorageEnumerateAck
	requestInto(t, nc, proto.StorageEnumerateSubject("node-1"), proto.StorageEnumerateCmd{}, &ack)
	if ack.OK {
		t.Fatal("enumerate reported OK with the failure injected")
	}
	if ack.Detail == "" || ack.Backend != "mock" {
		t.Errorf("ack = %+v", ack)
	}
}

func TestRefusalFor(t *testing.T) {
	cases := []struct {
		err  error
		want proto.StorageRefusal
	}{
		{nil, ""},
		{ErrProtected, proto.StorageRefusalProtected},
		{fmt.Errorf("wrapped: %w", ErrProtected), proto.StorageRefusalProtected},
		{ErrFingerprintMismatch, proto.StorageRefusalFingerprintMismatch},
		{ErrNoFingerprint, proto.StorageRefusalFingerprintMismatch},
		{ErrDeviceAbsent, proto.StorageRefusalDeviceAbsent},
		{ErrNotWholeDisk, proto.StorageRefusalNotWholeDisk},
		{ErrNotFound, proto.StorageRefusalNotFound},
		{errors.New("mkfs blew up"), proto.StorageRefusalBackendError},
	}
	for _, tc := range cases {
		if got := refusalFor(tc.err); got != tc.want {
			t.Errorf("refusalFor(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func containsFold(hay, needle string) bool {
	h, n := []rune(hay), []rune(needle)
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		match := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
