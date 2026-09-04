package quiesce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// The verbs over a real bus, against the docker mock. Same harness as the
// storage and docker handler tests.

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
	msg, err := nc.Request(subj, payload, 10*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subj, err)
	}
	if err := json.Unmarshal(msg.Data, out); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
}

func registered(t *testing.T) (*nats.Conn, *docker.MockBackend, *Stager) {
	t.Helper()
	nc := startNATS(t)
	mb, err := docker.NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mb.Deploy(context.Background(), "ha", "Home Assistant", "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	dir, err := mb.VolumeDir("ha", "homeassistant-config")
	if err != nil {
		t.Fatal(err)
	}
	fixtureVolume(t, dir)
	s := newStager(t, mb)
	subs, err := RegisterHandlers(nc, "node-1", s)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, sub := range subs {
			_ = sub.Unsubscribe()
		}
	})
	return nc, mb, s
}

func TestHandlers_StageAndUnstageOverTheBus(t *testing.T) {
	nc, mb, s := registered(t)
	var ack proto.BackupStageVolumeAck
	requestInto(t, nc, proto.BackupStageVolumeSubject("node-1"),
		stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "ha.tar"), &ack)
	if !ack.OK || !ack.Stopped || !ack.AppRestored {
		t.Fatalf("ack = %+v", ack)
	}
	if running, _ := mb.AppRunning(context.Background(), "ha"); !running {
		t.Error("the app is not running after the verb answered")
	}
	if _, err := os.Stat(ack.StagedPath); err != nil {
		t.Errorf("staged file missing: %v", err)
	}
	if !strings.HasPrefix(ack.StagedPath, s.stagingRoot) {
		t.Errorf("staged outside the root: %s", ack.StagedPath)
	}

	var un proto.BackupUnstageAck
	requestInto(t, nc, proto.BackupUnstageSubject("node-1"), proto.BackupUnstageCmd{StagingName: "ha.tar"}, &un)
	if !un.OK || !un.Existed || un.FreedBytes != ack.SizeBytes {
		t.Errorf("unstage = %+v", un)
	}
}

func TestHandlers_BadCommandIsRefusedNotDefaulted(t *testing.T) {
	nc, _, _ := registered(t)
	msg, err := nc.Request(proto.BackupStageVolumeSubject("node-1"), []byte("{not json"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var ack proto.BackupStageVolumeAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.OK || ack.Refusal != proto.StorageRefusalBackendError || !ack.AppRestored {
		t.Errorf("ack = %+v", ack)
	}
}

// A panic inside the driver still answers on the bus, and the app is back
// before the answer goes out.
func TestHandlers_PanicStillAnswersAndTheAppIsBack(t *testing.T) {
	nc, mb, s := registered(t)
	s.afterFile = func(string) error { panic("boom") }
	var ack proto.BackupStageVolumeAck
	requestInto(t, nc, proto.BackupStageVolumeSubject("node-1"),
		stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "ha.tar"), &ack)
	if ack.OK || !strings.Contains(ack.Detail, "panic") {
		t.Fatalf("ack = %+v", ack)
	}
	if !ack.Stopped || !ack.AppRestored {
		t.Errorf("stopped=%t restored=%t: %s", ack.Stopped, ack.AppRestored, ack.RestoreDetail)
	}
	if running, _ := mb.AppRunning(context.Background(), "ha"); !running {
		t.Error("the app is down after a panic in the copy")
	}
}

// Declared-but-unbuilt strategies refuse over the bus with the volume named,
// and never touch the app.
func TestHandlers_UnbuiltStrategyRefusesLoudly(t *testing.T) {
	nc, mb, _ := registered(t)
	var ack proto.BackupStageVolumeAck
	requestInto(t, nc, proto.BackupStageVolumeSubject("node-1"),
		stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiescePostgres, "ha.tar"), &ack)
	if ack.OK || ack.Refusal != proto.BackupRefusalQuiesceUnsupported {
		t.Fatalf("ack = %+v", ack)
	}
	if !strings.Contains(ack.Detail, "homeassistant-config") || !strings.Contains(ack.Detail, "postgres") {
		t.Errorf("detail must name the volume and the strategy: %q", ack.Detail)
	}
	if running, _ := mb.AppRunning(context.Background(), "ha"); !running {
		t.Error("a refused strategy stopped the app")
	}
}

// The restore verb over the bus, against the docker mock: the mock's volume
// directory is what the real ResolveVolume answers for it, so the staging
// tree lands beside it and the exchange is the real one.
func TestHandlers_RestoreVolumeOverTheBus(t *testing.T) {
	nc, mb, s := registered(t)
	s.SetRestoreRecordDir(t.TempDir())
	if _, _, err := mb.Deploy(context.Background(), "vw", "vaultwarden", "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	vol, err := mb.VolumeDir("vw", "vaultwarden-data")
	if err != nil {
		t.Fatal(err)
	}
	writeVolFile(t, vol+"/db.sqlite3", "ORIGINAL")
	tarPath := t.TempDir() + "/vw.tar"
	if _, err := writeTar(context.Background(), vol, tarPath, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	backup, _ := os.ReadFile(tarPath)
	sum := sha256.Sum256(backup)
	e := newEgress(t, backup)
	writeVolFile(t, vol+"/db.sqlite3", "CORRUPT")

	var ack proto.BackupRestoreVolumeAck
	requestInto(t, nc, proto.BackupRestoreVolumeSubject("node-1"), proto.BackupRestoreVolumeCmd{
		AppID: "vw", AppName: "vaultwarden", Volume: "vaultwarden-data", Class: tileschema.BackupCritical,
		Source: e.source(t), Credential: rsCred, GenerationID: rsGen, Member: rsMember,
		PlaintextDigest: hex.EncodeToString(sum[:]), PlaintextBytes: uint64(len(backup)),
	}, &ack)
	if !ack.OK || !ack.Replaced || !ack.Stopped || !ack.AppRestored {
		t.Fatalf("ack = %+v", ack)
	}
	if got, _ := os.ReadFile(vol + "/db.sqlite3"); string(got) != "ORIGINAL" {
		t.Fatalf("db.sqlite3 = %q after the restore", got)
	}
	if running, _ := mb.AppRunning(context.Background(), "vw"); !running {
		t.Error("the app is not running after the verb answered")
	}
	if got, _ := os.ReadFile(ack.PreviousKept + "/db.sqlite3"); string(got) != "CORRUPT" {
		t.Fatalf("the previous contents are not kept at %s: %q", ack.PreviousKept, got)
	}
}
