//go:build docker

// Live functional tests for the quiesce half of ComposeBackend against a real
// `docker compose`. Excluded from the default run by the `docker` build tag;
// invoke with:
//
//	GOTOOLCHAIN=go1.26.4 go test -tags=docker -run TestQuiesceLive \
//	  -count=1 -v -timeout=10m ./agent/internal/docker/...
//
// Requires a working docker CLI + compose v2 and network access to pull
// busybox:latest and python:3.13-alpine once. Set RASPUTIN_TEST_SQLITE_IMAGE
// to run the snapshot case against another image — the pinned Home Assistant
// image, say, which is the one that matters.
//
// What only a live daemon can prove, and why each is here:
//
//  1. Compose labels a volume with the project and the tile's volume name,
//     and `docker volume ls --filter label=...` finds it by those labels.
//  2. `compose stop` / `compose start` round-trip a project without
//     re-evaluating it (no pull, no seed rerun, no orphan removal).
//  3. `docker exec` into a running container that mounts the volume can
//     snapshot a WAL-mode SQLite database that another process in that
//     container is writing, and the snapshot is self-contained and passes
//     integrity_check — through python3's backup API when there is no
//     sqlite3 binary, which is the Home Assistant case.
//
// On macOS the volume's Mountpoint is a path inside the Docker VM, so the
// host-side read is asserted only where the path is readable.

package docker

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const volumeCompose = `services:
  app:
    image: busybox:latest
    command: ["sh", "-c", "echo hello > /data/hello.txt; while true; do sleep 5; done"]
    volumes:
      - data:/data
volumes:
  data:
`

func sqliteCompose(image string) string {
	return `services:
  app:
    image: ` + image + `
    # entrypoint, not command: the Home Assistant image's ENTRYPOINT is s6's
    # /init, which would swallow a command.
    entrypoint:
      - python3
      - -c
      - |
        import sqlite3, time
        c = sqlite3.connect('/data/app.db')
        c.execute('pragma journal_mode=wal')
        c.execute('create table if not exists t (i integer, s text)')
        c.commit()
        i = 0
        while True:
            c.execute('insert into t values (?, ?)', (i, 'row %d' % i))
            c.commit()
            i += 1
            time.sleep(0.05)
    volumes:
      - data:/data
volumes:
  data:
`
}

func TestQuiesceLiveVolumeStopStart(t *testing.T) {
	requireDocker(t)
	c, appID := newLiveBackend(t, "qvol1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if status, detail, err := c.Deploy(ctx, appID, appID, volumeCompose); err != nil || status != "running" {
		t.Fatalf("Deploy: %v (status=%s detail=%s)", err, status, detail)
	}

	hostPath, err := c.ResolveVolume(ctx, appID, "data")
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}
	if !strings.HasPrefix(hostPath, "/") {
		t.Errorf("mountpoint %q is not absolute", hostPath)
	}
	if b, err := os.ReadFile(hostPath + "/hello.txt"); err == nil {
		if strings.TrimSpace(string(b)) != "hello" {
			t.Errorf("volume contents on the host: %q", b)
		}
	} else {
		t.Logf("volume mountpoint %s is not readable from this host (a VM-backed daemon): %v", hostPath, err)
	}
	if _, err := c.ResolveVolume(ctx, appID, "nope"); err == nil {
		t.Error("an undeclared volume resolved")
	}

	if r, err := c.AppRunning(ctx, appID); err != nil || !r {
		t.Fatalf("AppRunning before stop = %t, %v", r, err)
	}
	if err := c.StopApp(ctx, appID, 5); err != nil {
		t.Fatalf("StopApp: %v", err)
	}
	if r, err := c.AppRunning(ctx, appID); err != nil || r {
		t.Fatalf("AppRunning after stop = %t, %v", r, err)
	}
	if err := c.StartApp(ctx, appID); err != nil {
		t.Fatalf("StartApp: %v", err)
	}
	if r, err := c.AppRunning(ctx, appID); err != nil || !r {
		t.Fatalf("AppRunning after start = %t, %v", r, err)
	}
}

func TestQuiesceLiveSQLiteSnapshot(t *testing.T) {
	requireDocker(t)
	image := os.Getenv("RASPUTIN_TEST_SQLITE_IMAGE")
	if image == "" {
		image = "python:3.13-alpine"
	}
	c, appID := newLiveBackend(t, "qsql1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if status, detail, err := c.Deploy(ctx, appID, appID, sqliteCompose(image)); err != nil || status != "running" {
		t.Fatalf("Deploy: %v (status=%s detail=%s)", err, status, detail)
	}
	name, err := c.volumeName(ctx, appID, "data")
	if err != nil {
		t.Fatal(err)
	}
	cid, dest, err := c.mountingContainer(ctx, appID, name)
	if err != nil {
		t.Fatalf("mountingContainer: %v", err)
	}
	if dest != "/data" {
		t.Errorf("mount destination = %q", dest)
	}
	// Wait for the writer to have created the database.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := c.docker(ctx, "exec", cid, "test", "-f", "/data/app.db"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the writer never created /data/app.db")
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(time.Second) // let some rows land

	tool, err := c.SnapshotSQLite(ctx, appID, "data", "app.db", ".rasputin-quiesce/app.db")
	if err != nil {
		t.Fatalf("SnapshotSQLite: %v", err)
	}
	t.Logf("snapshot taken with %s in %s", tool, image)

	check := "import sqlite3\n" +
		"c = sqlite3.connect('/data/.rasputin-quiesce/app.db')\n" +
		"print(c.execute('pragma integrity_check').fetchone()[0])\n" +
		"print(c.execute('select count(*) from t').fetchone()[0])\n"
	out, err := c.docker(ctx, "exec", cid, "python3", "-c", check)
	if err != nil {
		t.Fatalf("verify snapshot: %v — %s", err, out)
	}
	lines := nonEmptyLines(out)
	if len(lines) != 2 || lines[0] != "ok" || lines[1] == "0" {
		t.Errorf("snapshot verification = %v, want [ok <n>0>]", lines)
	}
	if _, err := c.docker(ctx, "exec", cid, "test", "-e", "/data/.rasputin-quiesce/app.db-wal"); err == nil {
		t.Error("the snapshot has a -wal beside it; it is supposed to be self-contained")
	}
	if _, err := exec.LookPath("docker"); err == nil {
		_, _ = c.docker(ctx, "exec", cid, "rm", "-rf", "/data/.rasputin-quiesce")
	}
}
