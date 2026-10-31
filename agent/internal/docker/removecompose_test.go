package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// removeComposeTestValue stands in for a secret value a compose or the
// config-hash record could have held.
const removeComposeTestValue = "s3cr3t-783-canary-value"

// TC-783-01: a keep-volumes delete (Stop without deleteVolumes, then
// RemoveCompose) removes the compose file and config-hash.json, keeps
// volumes.json and a tile-owned file byte-for-byte, and leaves no file in the
// app's directory holding the value.
func TestRemoveCompose_TC783_01_KeepVolumesDeleteRemovesTheWorkerCopy(t *testing.T) {
	u := newUpgradedApp(t)
	dir := u.b.appDir(delULID)
	if err := os.WriteFile(u.b.composePath(delULID), []byte("services: {app: {environment: {PW: "+removeComposeTestValue+"}}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.b.configHashRecordPath(delULID), []byte(`{"app":"`+removeComposeTestValue+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tileFile := filepath.Join(dir, "data", "tile.conf")
	if err := os.MkdirAll(filepath.Dir(tileFile), 0o700); err != nil {
		t.Fatal(err)
	}
	tileBytes := []byte("tile-owned bind-mount data\n")
	if err := os.WriteFile(tileFile, tileBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	if status, detail, err := u.b.Stop(context.Background(), delULID, false); err != nil || status != proto.AppStatusStopped {
		t.Fatalf("Stop = %s %q %v", status, detail, err)
	}
	recordPath := filepath.Join(dir, volumeRecordFile)
	recordBefore, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("the keep-data stop wrote no %s: %v", volumeRecordFile, err)
	}

	if err := u.b.RemoveCompose(context.Background(), delULID); err != nil {
		t.Fatalf("RemoveCompose: %v", err)
	}

	for _, gone := range []string{composeFileName, configHashRecordFile} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s survived RemoveCompose (stat err %v)", gone, err)
		}
	}
	if got, err := os.ReadFile(recordPath); err != nil || !bytes.Equal(got, recordBefore) {
		t.Errorf("%s changed or went: %v", volumeRecordFile, err)
	}
	if got, err := os.ReadFile(tileFile); err != nil || !bytes.Equal(got, tileBytes) {
		t.Errorf("the tile's file changed or went: %v", err)
	}
	var files []string
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		files = append(files, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(removeComposeTestValue)) {
			t.Errorf("%s still holds the test value", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{recordPath, tileFile}
	slices.Sort(files)
	slices.Sort(want)
	if !slices.Equal(files, want) {
		t.Errorf("files left = %v, want %v", files, want)
	}
}

// TC-783-02: an absent compose file is success, and volumes.json stays.
func TestRemoveCompose_TC783_02_AbsentComposeIsSuccess(t *testing.T) {
	c := composeBackendWithoutLookPath(t)
	const id = "app-no-compose"
	if err := os.MkdirAll(c.appDir(id), 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(c.appDir(id), volumeRecordFile)
	if err := os.WriteFile(record, []byte(`{"anonymous":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveCompose(context.Background(), id); err != nil {
		t.Fatalf("RemoveCompose with no compose: %v", err)
	}
	if got, err := os.ReadFile(record); err != nil || string(got) != `{"anonymous":[]}` {
		t.Errorf("%s = %q, %v; want it untouched", volumeRecordFile, got, err)
	}
	// And with no app directory at all.
	if err := c.RemoveCompose(context.Background(), "never-deployed"); err != nil {
		t.Errorf("RemoveCompose with no app directory: %v", err)
	}
}

func TestRemoveCompose_RefusesAnAppIDThatIsNotOnePathElement(t *testing.T) {
	c := composeBackendWithoutLookPath(t)
	for _, id := range []string{"", ".", "..", "a/b"} {
		if err := c.RemoveCompose(context.Background(), id); err == nil {
			t.Errorf("RemoveCompose(%q) = nil, want a refusal", id)
		}
	}
}

func TestRemoveCompose_ReportsAFailedRemoval(t *testing.T) {
	c := composeBackendWithoutLookPath(t)
	const id = "app-1"
	// A non-empty directory where the compose file belongs cannot be removed
	// with os.Remove.
	if err := os.MkdirAll(filepath.Join(c.composePath(id), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveCompose(context.Background(), id); err == nil || !strings.Contains(err.Error(), composeFileName) {
		t.Errorf("RemoveCompose = %v, want an error naming %s", err, composeFileName)
	}
	_ = os.RemoveAll(c.composePath(id))
	if err := os.MkdirAll(filepath.Join(c.configHashRecordPath(id), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveCompose(context.Background(), id); err == nil || !strings.Contains(err.Error(), configHashRecordFile) {
		t.Errorf("RemoveCompose = %v, want an error naming %s", err, configHashRecordFile)
	}
}

func TestMockRemoveCompose_RemovesTheComposeAndKeepsState(t *testing.T) {
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := mb.Deploy(ctx, "a1", "A", "services: {}\n", nil); err != nil {
		t.Fatal(err)
	}
	if err := mb.RemoveCompose(ctx, "a1"); err != nil {
		t.Fatalf("RemoveCompose: %v", err)
	}
	if _, err := os.Stat(mb.composePath("a1")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("mock compose survived (stat err %v)", err)
	}
	if _, err := os.Stat(mb.statePath("a1")); err != nil {
		t.Errorf("mock state went: %v", err)
	}
	if err := mb.RemoveCompose(ctx, "a1"); err != nil {
		t.Errorf("second RemoveCompose: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(mb.composePath("a2"), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := mb.RemoveCompose(ctx, "a2"); err == nil {
		t.Error("RemoveCompose over an unremovable path = nil, want an error")
	}
}

// stopCallLog records Stop and RemoveCompose calls in order, and returns
// the configured outcome of each.
type stopCallLog struct {
	errBackend
	calls     []string
	stopErr   error
	removeErr error
}

func (r *stopCallLog) Stop(_ context.Context, appID string, deleteVolumes bool) (proto.AppStatus, string, error) {
	r.calls = append(r.calls, "Stop "+appID)
	if r.stopErr != nil {
		return proto.AppStatusFailed, "docker compose down: " + r.stopErr.Error(), r.stopErr
	}
	return proto.AppStatusStopped, "", nil
}

func (r *stopCallLog) RemoveCompose(_ context.Context, appID string) error {
	r.calls = append(r.calls, "RemoveCompose "+appID)
	return r.removeErr
}

// stopVia registers b on a fresh bus, sends payload on the stop subject and
// returns the decoded ack.
func stopVia(t *testing.T, b Backend, payload []byte) proto.AppStopAck {
	t.Helper()
	nc := startNATS(t)
	subs, err := RegisterHandlers(nc, "node-1", b)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	msg, err := nc.Request(proto.AppStopSubject("node-1"), payload, 3*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.AppStopAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	return ack
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TC-783-03: removeCompose:true stops, then removes the compose for the same
// id, and acks stopped with a detail saying the file was removed.
func TestHandleStop_TC783_03_RemoveComposeAfterStop(t *testing.T) {
	b := &stopCallLog{}
	ack := stopVia(t, b, mustJSON(t, proto.AppStopCmd{AppID: "app-1", RemoveCompose: true}))
	if want := []string{"Stop app-1", "RemoveCompose app-1"}; !slices.Equal(b.calls, want) {
		t.Errorf("calls = %v, want %v", b.calls, want)
	}
	if !ack.OK || ack.Status != proto.AppStatusStopped {
		t.Errorf("ack = %+v, want OK stopped", ack)
	}
	if !strings.Contains(ack.Detail, "compose file was removed") {
		t.Errorf("ack detail %q does not say the compose file was removed", ack.Detail)
	}
}

// TC-783-04: removeCompose false, and a body with no removeCompose key (an
// older api), never call RemoveCompose, and the ack is today's.
func TestHandleStop_TC783_04_NoRemoveWithoutTheFlag(t *testing.T) {
	for name, payload := range map[string][]byte{
		"false":        mustJSON(t, proto.AppStopCmd{AppID: "app-1", RemoveCompose: false}),
		"key absent":   []byte(`{"appId":"app-1"}`),
		"older delete": []byte(`{"appId":"app-1","deleteVolumes":false}`),
	} {
		t.Run(name, func(t *testing.T) {
			b := &stopCallLog{}
			ack := stopVia(t, b, payload)
			if want := []string{"Stop app-1"}; !slices.Equal(b.calls, want) {
				t.Errorf("calls = %v, want %v", b.calls, want)
			}
			if want := (proto.AppStopAck{OK: true, Status: proto.AppStatusStopped}); ack != want {
				t.Errorf("ack = %+v, want %+v", ack, want)
			}
		})
	}
}

// TC-783-05: (a) a failed removal acks OK:false, status stopped, with a detail
// naming the cause; (b) a failed Stop never calls RemoveCompose and the ack
// carries the stop failure.
func TestHandleStop_TC783_05_FailurePaths(t *testing.T) {
	t.Run("remove fails", func(t *testing.T) {
		b := &stopCallLog{removeErr: errors.New("permission denied")}
		ack := stopVia(t, b, mustJSON(t, proto.AppStopCmd{AppID: "app-1", RemoveCompose: true}))
		if ack.OK || ack.Status != proto.AppStatusStopped {
			t.Errorf("ack = %+v, want OK:false status stopped", ack)
		}
		if want := "Stopped, but the app's compose file could not be removed: permission denied."; ack.Detail != want {
			t.Errorf("detail = %q, want %q", ack.Detail, want)
		}
	})
	t.Run("stop fails", func(t *testing.T) {
		b := &stopCallLog{stopErr: errors.New("daemon gone")}
		ack := stopVia(t, b, mustJSON(t, proto.AppStopCmd{AppID: "app-1", RemoveCompose: true}))
		if want := []string{"Stop app-1"}; !slices.Equal(b.calls, want) {
			t.Errorf("calls = %v, want %v (no RemoveCompose after a failed stop)", b.calls, want)
		}
		if ack.OK || ack.Status != proto.AppStatusFailed || !strings.Contains(ack.Detail, "daemon gone") {
			t.Errorf("ack = %+v, want the stop failure", ack)
		}
	})
}
