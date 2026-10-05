package storage

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// TC-825-37: each transfer attempt carries a freshly minted upload
// credential, and the held secret.Value is destroyed once its command is
// built. A transfer that fails once is retried on a second credential and
// lands.
func TestFanOut_UploadCredentialIsAValuePerAttempt(t *testing.T) {
	var (
		mu     sync.Mutex
		held   []secret.Value
		minted []string
	)
	r := runWithApps(t, runHarnessOpts{
		apps:          []*apps.App{testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden")},
		tiles:         clusterTiles(),
		stageOutcomes: map[string]stageOutcome{"vaultwarden-data": {failFirstTransfer: true}},
		heldUploadCredential: func(v secret.Value) {
			mu.Lock()
			defer mu.Unlock()
			held = append(held, v)
			minted = append(minted, string(v.Reveal()))
		},
	})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	if vw := r.record(t, "vaultwarden", "vaultwarden-data"); !vw.Captured {
		t.Fatalf("the retried upload did not land: %+v", vw)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(held) != 2 {
		t.Fatalf("minted %d credential(s), want 2: one per attempt", len(held))
	}
	recs := r.h.agent.transferRecords()
	if len(recs) != 2 {
		t.Fatalf("transfer commands = %d, want 2", len(recs))
	}
	for i, rec := range recs {
		if rec.cmd.Credential == "" || rec.cmd.Credential != minted[i] {
			t.Errorf("attempt %d carried credential %q, want the one minted for it", i+1, rec.cmd.Credential)
		}
		if held[i].Len() != 0 {
			t.Errorf("attempt %d's credential has %d bytes after its command was built, want it destroyed", i+1, held[i].Len())
		}
	}
	if minted[0] == minted[1] {
		t.Error("the retry reused the first attempt's credential")
	}
}

// fanOutBus answers the stage and unstage verbs and counts transfer requests.
type fanOutBus struct {
	mu        sync.Mutex
	transfers int
}

func (b *fanOutBus) RequestWithContext(_ context.Context, subj string, _ []byte) (*nats.Msg, error) {
	switch {
	case subj == proto.BackupStageVolumeSubject("n1"):
		data, _ := json.Marshal(proto.BackupStageVolumeAck{OK: true, Digest: strings.Repeat("a", 64), SizeBytes: 10, AppRestored: true})
		return &nats.Msg{Data: data}, nil
	case subj == proto.BackupTransferSubject("n1"):
		b.mu.Lock()
		b.transfers++
		b.mu.Unlock()
		return nil, errors.New("not expected")
	default:
		data, _ := json.Marshal(proto.BackupUnstageAck{OK: true})
		return &nats.Msg{Data: data}, nil
	}
}

// TC-825-37: a mint error records "could not mint an upload credential" and
// sends no transfer request.
func TestCaptureOne_MintErrorSendsNoTransfer(t *testing.T) {
	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	bus := &fanOutBus{}
	o := fanOutOpts{
		NATS:         bus,
		JobID:        "01JOB",
		GenerationID: "20260903T120000Z-JOB12345-full",
		// No generation is open, so the endpoint refuses to mint.
		Ingest: backupxfer.New(auth, 1, slog.New(slog.DiscardHandler)),
		Log:    func(string, string) {},
		routes: map[string]routeAnswer{"n1": {destination: "https://n1.example/ingest"}},
		heldCredential: func(secret.Value) {
			t.Error("a credential was handed out although the mint failed")
		},
	}
	rec := o.captureOne(context.Background(), 0, PlannedVolume{
		AppID: "a1", AppName: "app", NodeID: "n1", Volume: "data", Class: "state", Quiesce: "live",
	})
	if !strings.Contains(rec.Reason, "could not mint an upload credential") {
		t.Errorf("reason = %q, want the mint refusal", rec.Reason)
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if bus.transfers != 0 {
		t.Errorf("transfer requests = %d, want 0", bus.transfers)
	}
}

// TC-825-37: uploadCommand sets exactly the credential on the base command.
func TestUploadCommand_SetsTheCredential(t *testing.T) {
	cred := secret.New([]byte("cred-825"))
	defer cred.Destroy()
	b, err := uploadCommand(proto.BackupTransferCmd{StagingName: "s", Member: "m"}, cred)
	if err != nil {
		t.Fatal(err)
	}
	var cmd proto.BackupTransferCmd
	if err := json.Unmarshal(b, &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Credential != "cred-825" || cmd.StagingName != "s" || cmd.Member != "m" {
		t.Errorf("command = %+v", cmd)
	}
}
