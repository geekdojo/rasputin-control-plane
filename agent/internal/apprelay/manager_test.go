package apprelay

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// TC-1081-19: the key is made once and reused; a certificate over another
// key is refused and changes nothing; the modes are the plan's; MountDir is
// true only once installed; Remove closes and deletes; a bad app id is
// refused before any filesystem call.
func TestManager_KeyCertModesAndRemove(t *testing.T) {
	dir := filepath.Join(shortDir(t), "relay")
	ca := newTestCA(t)
	m, _ := newTestManager(t, dir, &fakeForwarder{})

	der1, err := m.Prepare(appA)
	if err != nil {
		t.Fatal(err)
	}
	key1, _ := os.ReadFile(m.keyPath(appA))
	der2, err := m.Prepare(appA)
	if err != nil {
		t.Fatal(err)
	}
	key2, _ := os.ReadFile(m.keyPath(appA))
	if !bytes.Equal(der1, der2) || !bytes.Equal(key1, key2) {
		t.Error("a second Prepare changed the key")
	}
	if _, ok := m.MountDir(appA); ok {
		t.Error("MountDir is true before Install")
	}

	other, _ := newTestManager(t, filepath.Join(shortDir(t), "other"), &fakeForwarder{})
	otherDER, _ := other.Prepare(appA)
	if err := m.Install(appA, ca.sign(t, otherDER, 2), ca.pem); err == nil {
		t.Fatal("a certificate over another key was installed")
	}
	if _, err := os.Stat(m.certPath(appA)); !os.IsNotExist(err) {
		t.Error("the refused install wrote a certificate")
	}
	if _, err := os.Stat(m.mnt(appA)); !os.IsNotExist(err) {
		t.Error("the refused install made the mount directory")
	}

	if err := m.Install(appA, ca.sign(t, der1, 3), ca.pem); err != nil {
		t.Fatal(err)
	}
	mnt, ok := m.MountDir(appA)
	if !ok || mnt != m.mnt(appA) {
		t.Fatalf("MountDir = %q, %v after Install", mnt, ok)
	}
	sock := filepath.Join(mnt, proto.AppRelaySocketName)
	for path, want := range map[string]fs.FileMode{
		m.appDir(appA): 0o700, m.keyPath(appA): 0o600, m.certPath(appA): 0o600,
		mnt: 0o755, filepath.Join(mnt, proto.AppRelayCAName): 0o644, sock: 0o666,
	} {
		if got := mode(t, path); got != want {
			t.Errorf("%s mode %o, want %o", filepath.Base(path), got, want)
		}
	}

	if err := m.Remove(appA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.appDir(appA)); !os.IsNotExist(err) {
		t.Error("Remove left the app's directory")
	}
	if c, err := net.Dial("unix", sock); err == nil {
		_ = c.Close()
		t.Error("the socket still answers after Remove")
	}
	if _, ok := m.MountDir(appA); ok {
		t.Error("MountDir is true after Remove")
	}

	for _, bad := range []string{"..", "a/b", "not-a-ulid", "01j9zk3q0m8x7y6w5v4t3s2r1a"} {
		if _, err := m.Prepare(bad); err == nil {
			t.Errorf("Prepare(%q) accepted", bad)
		}
		if err := m.Install(bad, nil, nil); err == nil {
			t.Errorf("Install(%q) accepted", bad)
		}
		if err := m.Remove(bad); err == nil {
			t.Errorf("Remove(%q) accepted", bad)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("a refused id touched the filesystem: %v", entries)
	}
}

// TC-1081-20: Restore reopens a key+cert directory (replacing a stale socket
// file), skips one with no cert, and logs one ERROR for an unreadable cert
// while the others still open. A state directory that does not exist (an
// agent from before the relay) is a no-op (TC-1081-26).
func TestManager_Restore(t *testing.T) {
	dir := filepath.Join(shortDir(t), "relay")
	ca := newTestCA(t)
	first, _ := newTestManager(t, dir, &fakeForwarder{})
	installed(t, first, ca, appA, 1)
	installed(t, first, ca, appB, 2)
	const appC = "01J9ZK3Q0M8X7Y6W5V4T3S2R1C"
	if _, err := first.Prepare(appC); err != nil {
		t.Fatal(err)
	}
	first.Close()
	// A's socket file is left behind, stale; B's certificate is corrupted.
	if err := os.WriteFile(filepath.Join(first.mnt(appA), proto.AppRelaySocketName), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.certPath(appB), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, rec := newTestManager(t, dir, &fakeForwarder{})
	m.Restore()
	if _, ok := m.MountDir(appA); !ok {
		t.Error("A was not reopened")
	}
	if c, err := net.Dial("unix", filepath.Join(m.mnt(appA), proto.AppRelaySocketName)); err != nil {
		t.Errorf("A's socket does not answer: %v", err)
	} else {
		_ = c.Close()
	}
	if _, ok := m.MountDir(appC); ok {
		t.Error("C, which has no certificate, was opened")
	}
	if _, ok := m.MountDir(appB); ok {
		t.Error("B, whose certificate is unreadable, was opened")
	}
	errs := rec.AtLevel(slog.LevelError)
	if len(errs) != 1 {
		t.Fatalf("%d ERROR records, want 1", len(errs))
	}
	if id, _ := logkittest.Attr(errs[0], "app_id"); id != appB {
		t.Errorf("ERROR names %q, want %s", id, appB)
	}
	if _, ok := logkittest.Attr(errs[0], "err"); !ok {
		t.Error("the ERROR has no err")
	}

	fresh, rec2 := newTestManager(t, filepath.Join(shortDir(t), "never"), &fakeForwarder{})
	fresh.Restore()
	if n := len(rec2.Records()); n != 0 {
		t.Errorf("Restore with no state directory logged %d records", n)
	}
}

// The app.relay verb drives the Manager: prepare returns the key, install
// opens the socket, remove closes it, and a bad command is refused with a
// sentence.
func TestHandle_AppRelayVerb(t *testing.T) {
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	ca := newTestCA(t)
	m, _ := newTestManager(t, filepath.Join(shortDir(t), "relay"), &fakeForwarder{})
	if _, err := RegisterHandlers(nc, "n", m); err != nil {
		t.Fatal(err)
	}
	req := func(cmd proto.AppRelayCmd) proto.AppRelayAck {
		t.Helper()
		b, _ := json.Marshal(cmd)
		msg, err := nc.Request(proto.AppRelaySubject("n"), b, 5e9)
		if err != nil {
			t.Fatal(err)
		}
		var ack proto.AppRelayAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			t.Fatal(err)
		}
		return ack
	}
	prep := req(proto.AppRelayCmd{AppID: appA, Op: proto.AppRelayPrepare})
	if !prep.OK || len(prep.PublicKeyDER) == 0 {
		t.Fatalf("prepare = %+v", prep)
	}
	if ack := req(proto.AppRelayCmd{AppID: appA, Op: proto.AppRelayInstall, CertPEM: ca.sign(t, prep.PublicKeyDER, 1), CAPEM: ca.pem}); !ack.OK {
		t.Fatalf("install = %+v", ack)
	}
	if _, ok := m.MountDir(appA); !ok {
		t.Error("install did not open the socket")
	}
	if ack := req(proto.AppRelayCmd{AppID: appA, Op: proto.AppRelayRemove}); !ack.OK {
		t.Fatalf("remove = %+v", ack)
	}
	for _, cmd := range []proto.AppRelayCmd{{AppID: appA, Op: "list"}, {AppID: "..", Op: proto.AppRelayPrepare}} {
		if ack := req(cmd); ack.OK || ack.Detail == "" {
			t.Errorf("%+v answered %+v, want a refusal with a detail", cmd, ack)
		}
	}
	if ack := handle(m, []byte("{")); ack.OK || ack.Detail == "" {
		t.Errorf("a malformed command answered %+v", ack)
	}
}

// NewManager and NewRelay refuse a missing collaborator.
func TestConstructorsRefuseMissingDeps(t *testing.T) {
	log, _ := logkittest.New()
	ok := ManagerDeps{Dir: "/x", Rand: rand.Reader, Forward: &fakeForwarder{}, IDs: counter(), Log: log}
	for _, mut := range []func(*ManagerDeps){
		func(d *ManagerDeps) { d.Dir = "" }, func(d *ManagerDeps) { d.Rand = nil }, func(d *ManagerDeps) { d.Forward = nil },
		func(d *ManagerDeps) { d.IDs = nil }, func(d *ManagerDeps) { d.Log = nil },
	} {
		d := ok
		mut(&d)
		if _, err := NewManager(d); err == nil {
			t.Errorf("NewManager(%+v) accepted", d)
		}
	}
	if _, err := NewRelay("", DefaultCallBound, log); err == nil {
		t.Error("NewRelay accepted an empty node")
	}
	if _, err := NewRelay("n", 0, log); err == nil {
		t.Error("NewRelay accepted a zero bound")
	}
	if _, err := NewRelay("n", DefaultCallBound, nil); err == nil {
		t.Error("NewRelay accepted a nil logger")
	}
}
