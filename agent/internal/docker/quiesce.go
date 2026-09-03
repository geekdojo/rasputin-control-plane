package docker

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The runtime operations design/storage.md §4.3's quiesce drivers need, on the
// real backend. The drivers themselves live in agent/internal/quiesce and are
// runtime-agnostic; this file is the `docker` half of the seam and
// mock_quiesce.go is the mock half.
//
// Four facts about compose decide the shape of everything here:
//
//   - Compose labels every volume it creates with com.docker.compose.project
//     and com.docker.compose.volume, so a tile's declared volume name
//     (`vaultwarden-data`) is resolved to the runtime's name by LABEL rather
//     than by reconstructing compose's `<project>_<volume>` convention —
//     which a compose file can override with an explicit `name:`.
//   - `compose stop` keeps the containers and their networks; `compose start`
//     brings the same containers back. That is the pair a quiesce wants.
//     Stop (the Backend method) is `compose down`, which REMOVES them, and a
//     `down`/`up` round trip re-evaluates the whole stack: pulls, one-shot
//     seeds, orphan removal. A backup must not do any of that.
//   - A stopped app's data can only be read from the host. A running app's
//     SQLite can only be snapshotted consistently through a process that
//     shares its locks, which means `docker exec` into a container that
//     mounts the volume — the same kernel, the same shm, the same WAL.
//   - The volume's host path comes from `docker volume inspect`, never from
//     a guess at the data root: the appliance moves Docker's data-root onto
//     the persistent partition and a dev box does not.

// ErrVolumeNotFound means the runtime has no compose volume by that name for
// that app.
var ErrVolumeNotFound = errors.New("docker: no such compose volume for that app")

// ErrNoRunningContainer means no running container of the app mounts the
// volume, so there is nothing to `docker exec` a snapshot through.
var ErrNoRunningContainer = errors.New("docker: no running container mounts that volume")

// ErrSnapshotToolMissing means neither `sqlite3` nor `python3` is present in
// the container the volume is mounted in.
var ErrSnapshotToolMissing = errors.New("docker: the container has neither sqlite3 nor python3 to snapshot a database with")

// ResolveVolume returns the HOST path of the compose volume `volume` (as the
// tile declares it) belonging to appID.
func (c *ComposeBackend) ResolveVolume(ctx context.Context, appID, volume string) (string, error) {
	name, err := c.volumeName(ctx, appID, volume)
	if err != nil {
		return "", err
	}
	out, err := c.docker(ctx, volumeInspectArgs(name)...)
	if err != nil {
		return "", fmt.Errorf("docker volume inspect %s: %w", name, err)
	}
	mp := strings.TrimSpace(string(out))
	if mp == "" || !path.IsAbs(mp) {
		return "", fmt.Errorf("docker volume inspect %s: mountpoint %q is not an absolute path", name, mp)
	}
	return mp, nil
}

// volumeName resolves a tile's volume name to the runtime's, by label.
func (c *ComposeBackend) volumeName(ctx context.Context, appID, volume string) (string, error) {
	out, err := c.docker(ctx, volumeLookupArgs(projectName(appID), volume)...)
	if err != nil {
		return "", fmt.Errorf("docker volume ls: %w", err)
	}
	names := nonEmptyLines(out)
	if len(names) == 0 {
		return "", fmt.Errorf("%w: app %s, volume %q", ErrVolumeNotFound, appID, volume)
	}
	if len(names) > 1 {
		// Two volumes carrying the same project+volume labels is not a state
		// compose produces; refusing beats copying whichever listed first.
		return "", fmt.Errorf("app %s: %d volumes carry the label for %q (%v); refusing to pick one", appID, len(names), volume, names)
	}
	return names[0], nil
}

// AppRunning reports whether the app's stack is up — the fact the `stop`
// driver needs before it decides whether there is anything to stop, and
// therefore anything to restart.
func (c *ComposeBackend) AppRunning(ctx context.Context, appID string) (bool, error) {
	status, _, err := c.Status(ctx, appID)
	if err != nil {
		return false, err
	}
	// `deploying` counts: compose reports it while containers are settling,
	// and settling containers are live processes with the volume open.
	return status == proto.AppStatusRunning || status == proto.AppStatusDeploying, nil
}

// StopApp stops every container in the app's project WITHOUT removing it,
// giving each graceSeconds to exit on SIGTERM before it is killed.
func (c *ComposeBackend) StopApp(ctx context.Context, appID string, graceSeconds int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.run(ctx, appID, composeStopArgs(graceSeconds)...)
	if err != nil {
		return errors.New(formatCmdErr("docker compose stop", out, err))
	}
	return nil
}

// StartApp starts the app's stopped containers — the other half of StopApp,
// and what the watchdog calls.
func (c *ComposeBackend) StartApp(ctx context.Context, appID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.run(ctx, appID, "start")
	if err != nil {
		return errors.New(formatCmdErr("docker compose start", out, err))
	}
	return nil
}

// SnapshotSQLite writes a transactionally consistent copy of the SQLite
// database at dbRel (relative to the volume root) to dstRel (likewise), from
// INSIDE a running container of the app that mounts the volume. Returns the
// tool that did it.
//
// Why inside the container and not from the host: the snapshot has to take
// the database's locks the way the app does — same shm, same WAL — and the
// SQLite library that does it should be the one the app's data was written
// by. The pinned Home Assistant image (the only `sqlite` tile) ships NO
// sqlite3 binary and DOES ship python3 with the sqlite3 module (probed
// 2026-09-02, SQLite 3.53.2), so there are two ways in, tried in order:
//
//  1. `sqlite3 <db> "VACUUM INTO '<dst>'"` — the CLI, where an image has it.
//  2. `python3 -c '... src.backup(dst) ...' <db> <dst>` — the Online Backup
//     API through the module every CPython carries. Arguments travel in
//     argv, so no path is ever interpolated into code.
//
// Both write a self-contained database: no -wal, no -shm, nothing beside it
// needed. Both run in a read transaction and never block the app's writers
// for longer than a page copy.
func (c *ComposeBackend) SnapshotSQLite(ctx context.Context, appID, volume, dbRel, dstRel string) (string, error) {
	name, err := c.volumeName(ctx, appID, volume)
	if err != nil {
		return "", err
	}
	cid, dest, err := c.mountingContainer(ctx, appID, name)
	if err != nil {
		return "", err
	}
	src := path.Join(dest, dbRel)
	dst := path.Join(dest, dstRel)

	// The scratch directory is created from INSIDE the container, so it is
	// owned by whatever user the app runs as and the snapshot can be written
	// there whatever the host's view of the volume is.
	if out, err := c.docker(ctx, execArgs(cid, []string{"mkdir", "-p", path.Dir(dst)})...); err != nil {
		return "", fmt.Errorf("create snapshot dir in %s: %s", cid[:min(12, len(cid))], formatCmdErr("docker exec mkdir", out, err))
	}

	out, err := c.docker(ctx, execArgs(cid, sqlite3VacuumArgv(src, dst))...)
	if err == nil {
		return "sqlite3", nil
	}
	if !toolMissing(out, err) {
		return "", fmt.Errorf("sqlite3 VACUUM INTO in %s: %s", cid[:min(12, len(cid))], formatCmdErr("docker exec", out, err))
	}
	out, err = c.docker(ctx, execArgs(cid, python3BackupArgv(src, dst))...)
	if err == nil {
		return "python3", nil
	}
	if toolMissing(out, err) {
		return "", fmt.Errorf("%w (container %s)", ErrSnapshotToolMissing, cid[:min(12, len(cid))])
	}
	return "", fmt.Errorf("python3 sqlite3.backup in %s: %s", cid[:min(12, len(cid))], formatCmdErr("docker exec", out, err))
}

// mountingContainer finds a RUNNING container of the project that mounts the
// named volume, and where it mounts it.
func (c *ComposeBackend) mountingContainer(ctx context.Context, appID, volumeName string) (cid, dest string, err error) {
	out, err := c.docker(ctx, runningWithVolumeArgs(projectName(appID), volumeName)...)
	if err != nil {
		return "", "", fmt.Errorf("docker ps: %w", err)
	}
	ids := nonEmptyLines(out)
	if len(ids) == 0 {
		return "", "", fmt.Errorf("%w: app %s, volume %s", ErrNoRunningContainer, appID, volumeName)
	}
	cid = ids[0]
	out, err = c.docker(ctx, mountsArgs(cid)...)
	if err != nil {
		return "", "", fmt.Errorf("docker inspect %s: %w", cid, err)
	}
	dest = mountDestination(out, volumeName)
	if dest == "" {
		return "", "", fmt.Errorf("container %s is listed as mounting %s but reports no such mount", cid, volumeName)
	}
	return cid, dest, nil
}

// docker runs the docker CLI with an argv (never a shell) and returns combined
// output. The compose subcommands go through run(); this is for the volume,
// ps, inspect and exec calls that are not compose's.
func (c *ComposeBackend) docker(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// The argv builders. Each exists so the exact flags are assertable in a test
// without a daemon, and so every operand that came from somewhere else is
// visibly an ARGUMENT — nothing here is ever a shell string.

func composeStopArgs(graceSeconds int) []string {
	return []string{"stop", "--timeout", strconv.Itoa(graceSeconds)}
}

func volumeLookupArgs(project, volume string) []string {
	return []string{"volume", "ls", "--quiet",
		"--filter", "label=com.docker.compose.project=" + project,
		"--filter", "label=com.docker.compose.volume=" + volume}
}

func volumeInspectArgs(name string) []string {
	return []string{"volume", "inspect", "--format", "{{.Mountpoint}}", name}
}

func runningWithVolumeArgs(project, volumeName string) []string {
	return []string{"ps", "--quiet", "--no-trunc",
		"--filter", "label=com.docker.compose.project=" + project,
		"--filter", "volume=" + volumeName,
		"--filter", "status=running"}
}

// mountsArgs prints every mount as `name<TAB>destination`, one per line, and
// the caller picks the row. The volume name is deliberately NOT interpolated
// into the template: it came from docker's own output, but a template is
// code and an operand is not.
func mountsArgs(cid string) []string {
	return []string{"inspect", "--format", "{{range .Mounts}}{{.Name}}\t{{.Destination}}\n{{end}}", cid}
}

func execArgs(cid string, argv []string) []string {
	return append([]string{"exec", cid}, argv...)
}

// sqlite3VacuumArgv is the CLI form. The destination is an SQL string literal,
// so a quote in the path is doubled; the source is a plain argument.
func sqlite3VacuumArgv(src, dst string) []string {
	return []string{"sqlite3", src, "VACUUM INTO '" + strings.ReplaceAll(dst, "'", "''") + "'"}
}

// python3BackupArgv is the Online Backup API through CPython's sqlite3 module.
// Paths arrive in sys.argv; the program text is a constant.
func python3BackupArgv(src, dst string) []string {
	const prog = "import sqlite3, sys\n" +
		"src = sqlite3.connect(sys.argv[1])\n" +
		"dst = sqlite3.connect(sys.argv[2])\n" +
		"with dst:\n" +
		"    src.backup(dst)\n" +
		"dst.close()\n" +
		"src.close()\n"
	return []string{"python3", "-c", prog, src, dst}
}

// toolMissing recognises "that binary is not in the image", which is the one
// exec failure that should fall through to the next tool rather than fail the
// snapshot. Docker reports it as exit 126/127 with a distinctive message.
func toolMissing(out []byte, err error) bool {
	var ee *exec.ExitError
	if errors.As(err, &ee) && (ee.ExitCode() == 126 || ee.ExitCode() == 127) {
		return true
	}
	s := string(out)
	return strings.Contains(s, "executable file not found") || strings.Contains(s, "no such file or directory")
}

func nonEmptyLines(out []byte) []string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// mountDestination picks the destination for volumeName out of mountsArgs's
// output.
func mountDestination(out []byte, volumeName string) string {
	for _, l := range nonEmptyLines(out) {
		name, dest, ok := strings.Cut(l, "\t")
		if ok && name == volumeName && path.IsAbs(dest) {
			return dest
		}
	}
	return ""
}
