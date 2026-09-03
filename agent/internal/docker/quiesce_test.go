package docker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The argv builders, pinned: every operand that came from somewhere else is an
// ARGUMENT, and the one place a path enters code (the sqlite3 SQL literal)
// escapes it.

func TestComposeStopArgsCarryTheGrace(t *testing.T) {
	got := composeArgs("/x/docker-compose.yml", "rasp_a1", composeStopArgs(60)...)
	want := []string{"compose", "-f", "/x/docker-compose.yml", "-p", "rasp_a1", "stop", "--timeout", "60"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("stop args = %v, want %v", got, want)
	}
	if strings.Contains(strings.Join(got, " "), "down") {
		t.Error("a quiesce stop must never be `compose down`: that removes the containers")
	}
}

func TestVolumeLookupArgsFilterByComposeLabels(t *testing.T) {
	got := volumeLookupArgs("rasp_a1", "vaultwarden-data")
	joined := strings.Join(got, " ")
	for _, want := range []string{"volume ls", "--quiet", "label=com.docker.compose.project=rasp_a1", "label=com.docker.compose.volume=vaultwarden-data"} {
		if !strings.Contains(joined, want) {
			t.Errorf("lookup args %v lack %q", got, want)
		}
	}
	if strings.Contains(joined, "rasp_a1_vaultwarden-data") {
		t.Error("the runtime name must be resolved by label, not reconstructed from the convention a compose file can override")
	}
}

func TestMountsArgsDoNotInterpolateTheVolumeName(t *testing.T) {
	got := mountsArgs("abc123")
	if got[len(got)-1] != "abc123" {
		t.Errorf("container id is not the operand: %v", got)
	}
	tmpl := got[2]
	if !strings.Contains(tmpl, "{{.Name}}") || !strings.Contains(tmpl, "{{.Destination}}") {
		t.Errorf("template prints name and destination for the caller to pick: %q", tmpl)
	}
}

func TestMountDestinationPicksTheRow(t *testing.T) {
	out := []byte("rasp_a1_other\t/other\nrasp_a1_vaultwarden-data\t/data\n\t/anon\n")
	if got := mountDestination(out, "rasp_a1_vaultwarden-data"); got != "/data" {
		t.Errorf("destination = %q, want /data", got)
	}
	if got := mountDestination(out, "missing"); got != "" {
		t.Errorf("missing volume returned %q", got)
	}
	if got := mountDestination([]byte("x\trelative\n"), "x"); got != "" {
		t.Errorf("a relative destination was accepted: %q", got)
	}
}

func TestSQLite3VacuumArgvQuotesTheDestination(t *testing.T) {
	argv := sqlite3VacuumArgv("/config/home-assistant_v2.db", "/config/.rasputin-quiesce/it's.db")
	if argv[0] != "sqlite3" || argv[1] != "/config/home-assistant_v2.db" {
		t.Errorf("argv = %v", argv)
	}
	if argv[2] != "VACUUM INTO '/config/.rasputin-quiesce/it''s.db'" {
		t.Errorf("SQL literal not escaped: %q", argv[2])
	}
}

func TestPython3BackupArgvPassesPathsInArgv(t *testing.T) {
	argv := python3BackupArgv("/config/a.db", "/config/.rasputin-quiesce/a.db")
	if argv[0] != "python3" || argv[1] != "-c" {
		t.Fatalf("argv = %v", argv)
	}
	prog := argv[2]
	if strings.Contains(prog, "/config") {
		t.Errorf("a path was interpolated into the program text: %q", prog)
	}
	if !strings.Contains(prog, "backup(") || !strings.Contains(prog, "sys.argv[1]") || !strings.Contains(prog, "sys.argv[2]") {
		t.Errorf("program does not use the Online Backup API over argv: %q", prog)
	}
	if argv[3] != "/config/a.db" || argv[4] != "/config/.rasputin-quiesce/a.db" {
		t.Errorf("paths not in argv positions: %v", argv)
	}
}

func TestExecArgsPrependExec(t *testing.T) {
	got := execArgs("cid", []string{"python3", "-c", "x"})
	if strings.Join(got, " ") != "exec cid python3 -c x" {
		t.Errorf("exec args = %v", got)
	}
}

func TestToolMissingRecognisesAnAbsentBinary(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	err127 := exec.Command("sh", "-c", "exit 127").Run()
	if !toolMissing(nil, err127) {
		t.Error("exit 127 is `command not found` and must fall through to the next tool")
	}
	err1 := exec.Command("sh", "-c", "exit 1").Run()
	if toolMissing([]byte("Error: database is locked"), err1) {
		t.Error("a real sqlite failure must NOT be mistaken for a missing tool")
	}
	if !toolMissing([]byte(`OCI runtime exec failed: exec: "sqlite3": executable file not found in $PATH`), err1) {
		t.Error("docker's own wording for a missing binary not recognised")
	}
	if toolMissing(nil, nil) {
		t.Error("no error is not a missing tool")
	}
}

func TestNonEmptyLines(t *testing.T) {
	got := nonEmptyLines([]byte("\n a \n\nb\n"))
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("lines = %v", got)
	}
}

// ----- the mock half ------------------------------------------------------

func TestMockVolumeDirIsResolvable(t *testing.T) {
	mb := newDockerMock(t)
	if _, err := mb.ResolveVolume(context.Background(), "a1", "data"); !errors.Is(err, ErrVolumeNotFound) {
		t.Errorf("an uncreated volume resolved: %v", err)
	}
	dir, err := mb.VolumeDir("a1", "data")
	if err != nil {
		t.Fatal(err)
	}
	got, err := mb.ResolveVolume(context.Background(), "a1", "data")
	if err != nil || got != dir {
		t.Errorf("ResolveVolume = %q, %v; want %q", got, err, dir)
	}
	if !strings.HasPrefix(dir, mb.dir) {
		t.Errorf("volume dir %s is outside the mock's state dir %s", dir, mb.dir)
	}
}

func TestMockStopAndStartFlipRunning(t *testing.T) {
	mb := newDockerMock(t)
	ctx := context.Background()
	if _, _, err := mb.Deploy(ctx, "a1", "x", "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	if r, _ := mb.AppRunning(ctx, "a1"); !r {
		t.Fatal("not running after deploy")
	}
	if err := mb.StopApp(ctx, "a1", 60); err != nil {
		t.Fatal(err)
	}
	if r, _ := mb.AppRunning(ctx, "a1"); r {
		t.Fatal("running after stop")
	}
	// `compose stop` keeps the compose file; only `down` would not.
	if _, err := os.Stat(filepath.Join(mb.dir, "a1", "docker-compose.yml")); err != nil {
		t.Error("compose file removed by a stop")
	}
	if err := mb.StartApp(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := mb.AppRunning(ctx, "a1"); !r {
		t.Fatal("not running after start")
	}
}

func TestMockSnapshotRefusesWhenTheAppIsStopped(t *testing.T) {
	mb := newDockerMock(t)
	ctx := context.Background()
	dir, _ := mb.VolumeDir("a1", "data")
	if err := os.WriteFile(filepath.Join(dir, "a.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mb.SnapshotSQLite(ctx, "a1", "data", "a.db", ".rasputin-quiesce/a.db"); !errors.Is(err, ErrNoRunningContainer) {
		t.Errorf("snapshot with no running container: %v", err)
	}
	if _, _, err := mb.Deploy(ctx, "a1", "x", "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	tool, err := mb.SnapshotSQLite(ctx, "a1", "data", "a.db", ".rasputin-quiesce/a.db")
	if err != nil || tool != "mock" {
		t.Fatalf("snapshot: %q, %v", tool, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".rasputin-quiesce", "a.db"))
	if err != nil || string(b) != "db" {
		t.Errorf("snapshot contents %q, %v", b, err)
	}
}

func TestMockFailModes(t *testing.T) {
	mb := newDockerMock(t)
	ctx := context.Background()
	if _, _, err := mb.Deploy(ctx, "a1", "x", "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	t.Setenv(mockFailModeEnv, "stop")
	if err := mb.StopApp(ctx, "a1", 60); err == nil {
		t.Error("stop did not fail under fail mode stop")
	}
	if r, _ := mb.AppRunning(ctx, "a1"); !r {
		t.Error("a failed stop changed the status")
	}
	t.Setenv(mockFailModeEnv, "")
	if err := mb.StopApp(ctx, "a1", 60); err != nil {
		t.Fatal(err)
	}
	t.Setenv(mockFailModeEnv, "start")
	if err := mb.StartApp(ctx, "a1"); err == nil {
		t.Error("start did not fail under fail mode start")
	}
	if r, _ := mb.AppRunning(ctx, "a1"); r {
		t.Error("a failed start changed the status")
	}
	t.Setenv(mockFailModeEnv, "snapshot")
	if _, err := mb.SnapshotSQLite(ctx, "a1", "data", "a.db", "x"); err == nil {
		t.Error("snapshot did not fail under fail mode snapshot")
	}
}
