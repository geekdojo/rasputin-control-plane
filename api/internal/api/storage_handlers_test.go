package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

const storageTestNode = "n-backup"

func storageTestNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// storageTestServer builds the smallest Server the backup routes need: the
// ledger, a runner with the claim workflow registered, and a bus.
func storageTestServer(t *testing.T) (*Server, *storage.Store, *nats.Conn) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")

	backupStore, err := storage.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("storage OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = backupStore.Close() })
	jobStore, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("jobs OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })
	inv, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	if err := inv.Insert(ctx, &proto.Node{
		ID: storageTestNode, Role: proto.RoleCompute, Hostname: "backup.test",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}

	nc := storageTestNATS(t)
	runner := jobs.NewRunner(jobStore, nc)
	runner.Register(storage.ClaimWorkflow(backupStore, inv, storage.Config{ClusterID: "home1"}))
	t.Cleanup(runner.Wait)

	return &Server{store: jobStore, runner: runner, backup: backupStore, nc: nc}, backupStore, nc
}

func postClaim(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/backup/targets", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleClaimBackupTarget(rec, req)
	return rec
}

// §4.6: the job spec is persisted into the jobs ledger and rendered in the
// Tasks view, so anything a caller can smuggle into it is published. The
// handler builds the spec from a typed request and decodes with
// DisallowUnknownFields, so a body carrying a private key is REFUSED rather
// than quietly stored.
//
// Both spellings are checked: `dataKey` was the symmetric era's name for it and
// `privateKey` is this one's. Neither is a declared field and neither ever will
// be — the point of the 2026-09-02 amendment is that there is no secret for the
// api to hold at all.
func TestClaimBackupTarget_RefusesAnUnknownFieldSuchAsAPlaintextKey(t *testing.T) {
	for _, field := range []string{"dataKey", "privateKey"} {
		t.Run(field, func(t *testing.T) {
			s, _, _ := storageTestServer(t)
			rec := postClaim(t, s, `{"nodeId":"`+storageTestNode+`","devicePath":"/dev/sdb","fingerprint":"fp","`+field+`":"THE-ACTUAL-SECRET"}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "THE-ACTUAL-SECRET") {
				t.Errorf("the refusal echoed the value back: %s", rec.Body.String())
			}
			list, err := s.store.ListJobs(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListJobs: %v", err)
			}
			if len(list) != 0 {
				t.Errorf("a refused body must not create a job, got %d", len(list))
			}
		})
	}
}

func TestClaimBackupTarget_RejectsAnIncompleteSpecBeforeCreatingAJob(t *testing.T) {
	s, _, _ := storageTestServer(t)
	rec := postClaim(t, s, `{"nodeId":"`+storageTestNode+`","devicePath":"/dev/sdb"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "fingerprint is required") {
		t.Errorf("body = %s", rec.Body.String())
	}
	list, _ := s.store.ListJobs(context.Background(), 10)
	if len(list) != 0 {
		t.Errorf("want no job, got %d — an operator should get the reason, not a job that exists only to fail", len(list))
	}
}

func TestClaimBackupTarget_SubmitsTheSaga(t *testing.T) {
	s, _, nc := storageTestServer(t)
	// A refusing agent keeps the test to the handler's job: submit and return.
	sub, err := nc.Subscribe(proto.StorageEnumerateSubject(storageTestNode), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageEnumerateAck{OK: true, Backend: "mock", Ts: time.Now().UTC()})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	rec := postClaim(t, s, `{"nodeId":"`+storageTestNode+`","devicePath":"/dev/sdb","fingerprint":"fp","label":"backup disk"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var j jobs.Job
	if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if j.Kind != storage.ClaimJobKind {
		t.Errorf("kind = %q, want %q", j.Kind, storage.ClaimJobKind)
	}
}

func TestBackupRoutes_503WithoutALedger(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleListBackupTargets(rec, httptest.NewRequest(http.MethodGet, "/api/backup/targets", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("list status = %d, want 503", rec.Code)
	}
	rec = postClaim(t, s, `{}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("claim status = %d, want 503", rec.Code)
	}
}

func TestListBackupTargets_RendersTheLedgerWithoutKeyMaterial(t *testing.T) {
	s, store, _ := storageTestServer(t)
	ctx := context.Background()
	if err := store.CreatePending(ctx, "j1", storageTestNode, "/dev/sdb", "disk", time.Now().UTC()); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	if err := store.MarkClaimed(ctx, "j1", storage.ClaimResult{
		PartUUID: "pu-1", MountPath: "/mnt/backup", FSType: "ext4",
		Key: &storage.ArchiveKey{
			KeyID: "k1", WrappedByPassphrase: "SENTINEL-WRAPPED",
			WrappedByRecoveryCode: "SENTINEL-RECOVERY",
		},
		At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("MarkClaimed: %v", err)
	}

	rec := httptest.NewRecorder()
	s.handleListBackupTargets(rec, httptest.NewRequest(http.MethodGet, "/api/backup/targets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "pu-1") || !strings.Contains(body, `"hasWrappedKeys":true`) {
		t.Errorf("body should name the target and say encryption is configured: %s", body)
	}
	for _, sentinel := range []string{"SENTINEL-WRAPPED", "SENTINEL-RECOVERY"} {
		if strings.Contains(body, sentinel) {
			t.Errorf("the listing carries wrapped key material: %s", body)
		}
	}
}

func TestListBackupCandidates_NeedsANode(t *testing.T) {
	s, _, _ := storageTestServer(t)
	rec := httptest.NewRecorder()
	s.handleListBackupCandidates(rec, httptest.NewRequest(http.MethodGet, "/api/backup/candidates", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when there is no nodeId and no self node", rec.Code)
	}
}

// The picker's enumeration is a plain read-only RPC, with no job behind it —
// the operator cannot choose from a list only a running job could produce.
// Protected disks are RETURNED rather than filtered: an operator who sees two
// disks should be told which one is the boot medium, not shown a list with a
// silent hole in it.
func TestListBackupCandidates_ReturnsProtectedDisksToo(t *testing.T) {
	s, _, nc := storageTestServer(t)
	sub, err := nc.Subscribe(proto.StorageEnumerateSubject(storageTestNode), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageEnumerateAck{
			OK: true, Backend: "blockdev", Ts: time.Now().UTC(),
			Candidates: []proto.StorageCandidate{
				{DevicePath: "/dev/sdb", Fingerprint: "fp-b", SizeBytes: 1 << 40},
				{
					DevicePath: "/dev/nvme0n1", Fingerprint: "fp-boot",
					Protected: true, ProtectedReason: "holds the mounted persistent partition",
				},
			},
		})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	rec := httptest.NewRecorder()
	s.handleListBackupCandidates(rec, httptest.NewRequest(http.MethodGet, "/api/backup/candidates?nodeId="+storageTestNode, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	var ack proto.StorageEnumerateAck
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(ack.Candidates) != 2 {
		t.Fatalf("want both disks listed, got %d", len(ack.Candidates))
	}
	if !ack.Candidates[1].Protected || ack.Candidates[1].ProtectedReason == "" {
		t.Error("the protected disk must arrive with its reason attached")
	}
}

// §4.8's wipe is reachable only by echoing back the token the picker published
// for that disk — so the picker has to publish one, and it must publish one
// ONLY where a wipe is a legitimate choice. A UI handed no token has nothing to
// put in the field and therefore no wipe control to render, which is the
// fail-closed half of the design.
func TestListBackupCandidates_MintsAWipeTokenOnlyForAWipeableDisk(t *testing.T) {
	s, _, nc := storageTestServer(t)
	set := &proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion, ClusterID: "home1",
		PartUUID: "pu-existing", Label: "the archive", Generations: 4,
		CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	}
	cands := []proto.StorageCandidate{
		// A blank disk: an ordinary claim already formats it, so a second,
		// destructive-sounding choice would be an invention.
		{DevicePath: "/dev/sdb", Fingerprint: "fp-b", SizeBytes: 1 << 40},
		// Carries an archive: this is the disk the wipe verb exists for.
		{DevicePath: "/dev/sdc", Fingerprint: "fp-c", SizeBytes: 2 << 40, HasBackupSet: true, BackupSet: set},
		// Announces an archive whose marker could not be read — the disk that
		// could previously be neither adopted nor formatted.
		{DevicePath: "/dev/sdd", Fingerprint: "fp-d", SizeBytes: 2 << 40, HasBackupSet: true},
		// The boot medium. Never, under any confirmation.
		{
			DevicePath: "/dev/nvme0n1", Fingerprint: "fp-boot", HasBackupSet: true, BackupSet: set,
			Protected: true, ProtectedReason: "holds the mounted persistent partition",
		},
	}
	sub, err := nc.Subscribe(proto.StorageEnumerateSubject(storageTestNode), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageEnumerateAck{
			OK: true, Backend: "blockdev", Ts: time.Now().UTC(), Candidates: cands,
		})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	rec := httptest.NewRecorder()
	s.handleListBackupCandidates(rec, httptest.NewRequest(http.MethodGet, "/api/backup/candidates?nodeId="+storageTestNode, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	var got struct {
		Candidates []struct {
			DevicePath string `json:"devicePath"`
			Protected  bool   `json:"protected"`
			WipeToken  string `json:"wipeToken"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Candidates) != len(cands) {
		t.Fatalf("want every disk listed, got %d", len(got.Candidates))
	}
	wantToken := map[string]bool{"/dev/sdb": false, "/dev/sdc": true, "/dev/sdd": true, "/dev/nvme0n1": false}
	for i, c := range got.Candidates {
		if (c.WipeToken != "") != wantToken[c.DevicePath] {
			t.Errorf("%s: wipeToken = %q, want minted = %v", c.DevicePath, c.WipeToken, wantToken[c.DevicePath])
		}
		// And the token published is exactly the one the saga will re-derive
		// from live hardware. A picker that published a different one would
		// refuse every wipe an operator confirmed.
		if want := storage.CandidateWipeToken(&cands[i]); c.WipeToken != want {
			t.Errorf("%s: wipeToken = %q, want %q", c.DevicePath, c.WipeToken, want)
		}
	}
}

// The picker's list must still carry everything the agent reported — the
// decoration adds a field, it does not replace the shape.
func TestListBackupCandidates_DecorationPreservesTheAgentsFields(t *testing.T) {
	s, _, nc := storageTestServer(t)
	sub, err := nc.Subscribe(proto.StorageEnumerateSubject(storageTestNode), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageEnumerateAck{
			OK: true, Backend: "blockdev", Ts: time.Now().UTC(),
			Candidates: []proto.StorageCandidate{{
				DevicePath: "/dev/sdc", Model: "Samsung T7", Serial: "S1234", WWN: "0x5001",
				SizeBytes: 2 << 40, Transport: proto.StorageTransportUSB, Removable: true,
				Fingerprint: "fp-c", IdentityWeak: true,
				Partitions: []proto.StoragePartition{{DevicePath: "/dev/sdc1", FSType: "ext4", SizeBytes: 1 << 40}},
			}},
		})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	rec := httptest.NewRecorder()
	s.handleListBackupCandidates(rec, httptest.NewRequest(http.MethodGet, "/api/backup/candidates?nodeId="+storageTestNode, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	// Decoded through the WIRE type, which is what an existing reader uses.
	var ack proto.StorageEnumerateAck
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatalf("decode as the agent's ack: %v", err)
	}
	if len(ack.Candidates) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(ack.Candidates))
	}
	c := ack.Candidates[0]
	if c.Model != "Samsung T7" || c.Serial != "S1234" || c.WWN != "0x5001" ||
		c.Transport != proto.StorageTransportUSB || !c.Removable || !c.IdentityWeak ||
		c.Fingerprint != "fp-c" || len(c.Partitions) != 1 {
		t.Errorf("the decoration dropped fields the picker renders: %+v", c)
	}
	if !ack.OK || ack.Backend != "blockdev" || ack.Ts.IsZero() {
		t.Errorf("the envelope lost fields: ok=%v backend=%q ts=%v", ack.OK, ack.Backend, ack.Ts)
	}
}

// Absent or contradictory confirmation is refused at the door, with no job
// created — never resolved into one choice or the other.
func TestClaimBackupTarget_RefusesAnUnconfirmedOrContradictoryWipe(t *testing.T) {
	cases := []struct {
		name, body, wantErr string
	}{
		{
			name:    "a wipe with no token",
			body:    `{"nodeId":"` + storageTestNode + `","devicePath":"/dev/sdb","fingerprint":"fp","wipe":{}}`,
			wantErr: "wipe.token is required",
		},
		{
			name:    "a wipe whose token is only whitespace",
			body:    `{"nodeId":"` + storageTestNode + `","devicePath":"/dev/sdb","fingerprint":"fp","wipe":{"token":"   "}}`,
			wantErr: "wipe.token is required",
		},
		{
			name:    "adopt and wipe at once",
			body:    `{"nodeId":"` + storageTestNode + `","devicePath":"/dev/sdb","fingerprint":"fp","adopt":true,"wipe":{"token":"wipe-abc"}}`,
			wantErr: "opposite choices",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := storageTestServer(t)
			rec := postClaim(t, s, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantErr) {
				t.Errorf("body = %s, want it to mention %q", rec.Body.String(), tc.wantErr)
			}
			list, _ := s.store.ListJobs(context.Background(), 10)
			if len(list) != 0 {
				t.Errorf("a refused confirmation must not create a job, got %d", len(list))
			}
		})
	}
}

func TestListBackupCandidates_SurfacesAnAgentRefusal(t *testing.T) {
	s, _, nc := storageTestServer(t)
	sub, err := nc.Subscribe(proto.StorageEnumerateSubject(storageTestNode), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageEnumerateAck{
			OK: false, Backend: "blockdev",
			Refusal: proto.StorageRefusalBackendError, Detail: "lsblk: not found",
		})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	rec := httptest.NewRecorder()
	s.handleListBackupCandidates(rec, httptest.NewRequest(http.MethodGet, "/api/backup/candidates?nodeId="+storageTestNode, nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "lsblk: not found") {
		t.Errorf("the agent's own detail should reach the operator: %s", rec.Body.String())
	}
}
