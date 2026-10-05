package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// restoreCmdAgent answers every BackupRestoreVolumeCmd on subject and hands
// the decoded command to the test.
func restoreCmdAgent(t *testing.T, nc *nats.Conn, subject string) <-chan proto.BackupRestoreVolumeCmd {
	t.Helper()
	got := make(chan proto.BackupRestoreVolumeCmd, 4)
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
		var cmd proto.BackupRestoreVolumeCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		ack, _ := json.Marshal(proto.BackupRestoreVolumeAck{OK: true})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got
}

// TC-825-40: the backup.restore_app restore credential is a secret.Value from
// RestoreEgress.Mint to the command. The node receives a credential the egress
// endpoint accepts for the planned member, and the held Value is empty once
// sendRestoreVolume returns.
func TestSendRestoreVolume_CredentialReachesTheCommandAndIsDestroyed(t *testing.T) {
	r := newEgressRig(t)
	r.arm(mustSHA(r.sealed))
	nc := startNATS(t)
	const subject = "test.restore.volume"
	cmds := restoreCmdAgent(t, nc, subject)

	var held secret.Value
	var heldBytes string
	cfg := RestoreAppConfig{Egress: r.egress, heldCredential: func(v secret.Value) {
		held = v
		heldBytes = string(v.Reveal())
	}}
	tgt := restoreAppTarget{AppID: "app-1", AppName: "vaultwarden", NodeID: "n-compute", GenerationID: r.genID, RestoreID: "restore-1"}
	plan := RestoreVolumePlan{Member: r.member, Volume: "vaultwarden-data", SHA256: mustSHA(r.plain), SizeBytes: uint64(len(r.plain))}
	sc := &jobs.StepCtx{Ctx: context.Background(), JobID: "job-restore", NATS: nc, Log: func(string, string) {}}

	if _, err := sendRestoreVolume(sc, cfg, tgt, plan, subject); err != nil {
		t.Fatalf("sendRestoreVolume: %v", err)
	}
	var cmd proto.BackupRestoreVolumeCmd
	select {
	case cmd = <-cmds:
	case <-time.After(2 * time.Second):
		t.Fatal("the node never received the restore command")
	}
	if cmd.Credential == "" || cmd.Credential != heldBytes {
		t.Fatalf("the command's credential is not the one minted (got %d bytes, minted %d)", len(cmd.Credential), len(heldBytes))
	}
	// It is a live restore credential for exactly this member.
	got, _, err := r.fetch(cmd.Credential)
	if err != nil {
		t.Fatalf("the egress endpoint refused the credential the node was sent: %v", err)
	}
	if string(got) != string(r.plain) {
		t.Fatal("the credential did not stream the planned member")
	}
	if held.Len() != 0 {
		t.Errorf("the minted credential still holds %d bytes after sendRestoreVolume returned; it must be destroyed", held.Len())
	}
}

// TC-825-40: every refusal from RestoreEgress.Mint is an error with the zero
// Value, and sendRestoreVolume turns the reachable ones into errRestoreMint
// with nothing sent. A grant that is not for restore cannot come out of
// sendRestoreVolume, which always asks for UseRestore, so that row is held on
// Mint alone.
func TestRestoreEgressMint_RefusalsReturnAZeroValueAndSendNothing(t *testing.T) {
	r := newEgressRig(t)
	r.arm(mustSHA(r.sealed))
	planned := backupxfer.Grant{Generation: r.genID, Member: r.member, NodeID: "n-compute", JobID: "job-restore", MaxBytes: 1 << 20, Use: backupxfer.UseRestore}

	notForRestore := planned
	notForRestore.Use = ""
	unplanned := planned
	unplanned.Member = proto.BackupMemberPath("paperless", "paperless-data")

	var unconfigured *RestoreEgress
	for _, c := range []struct {
		why    string
		egress *RestoreEgress
		grant  backupxfer.Grant
	}{
		{"an unconfigured egress", unconfigured, planned},
		{"a grant that is not for restore", r.egress, notForRestore},
		{"an unplanned member", r.egress, unplanned},
	} {
		v, err := c.egress.Mint(c.grant, time.Minute)
		if err == nil {
			t.Errorf("%s: Mint issued a credential", c.why)
		}
		if v.Len() != 0 {
			t.Errorf("%s: Mint returned %d bytes beside its error, want the zero Value", c.why, v.Len())
		}
	}

	nc := startNATS(t)
	const subject = "test.restore.volume.refused"
	cmds := restoreCmdAgent(t, nc, subject)
	sc := &jobs.StepCtx{Ctx: context.Background(), JobID: "job-restore", NATS: nc, Log: func(string, string) {}}
	tgt := restoreAppTarget{AppID: "app-1", AppName: "vaultwarden", NodeID: "n-compute", GenerationID: r.genID, RestoreID: "restore-1"}

	for _, c := range []struct {
		why    string
		egress *RestoreEgress
		member string
	}{
		{"an unconfigured egress", unconfigured, r.member},
		{"an unplanned member", r.egress, unplanned.Member},
	} {
		cfg := RestoreAppConfig{Egress: c.egress, heldCredential: func(secret.Value) {
			t.Errorf("%s: a credential was minted", c.why)
		}}
		plan := RestoreVolumePlan{Member: c.member, Volume: "v", SizeBytes: 1}
		if _, err := sendRestoreVolume(sc, cfg, tgt, plan, subject); !errors.Is(err, errRestoreMint) {
			t.Errorf("%s: err = %v, want errRestoreMint", c.why, err)
		}
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	select {
	case cmd := <-cmds:
		t.Fatalf("a restore command was sent although no credential could be minted: %+v", cmd)
	default:
	}
}
