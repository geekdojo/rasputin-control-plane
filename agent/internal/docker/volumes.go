package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Orphaned volumes — geekdojo/geekdojo-brain#399.
//
// `docker compose down` without `-v` leaves an app's named volumes behind,
// which is what every uninstall did until #399, so a node can hold volumes
// named rasp_<appID>_* for apps that no longer exist anywhere. The api knows
// which app ids are still in its ledger; this file is the agent's half: an
// enumerator that lists every Rasputin-managed compose volume with its size
// and age, and a remover that takes exact names and refuses anything it should
// not touch.
//
// The remover's refusal rules, in the order they are applied to each name:
//
//  1. The name must parse as rasp_<ulid>_<volume> (proto.ParseAppVolumeName).
//     Anything outside the prefix, or with a malformed project segment, is
//     refused BY NAME — never silently skipped, so a caller that sent a wrong
//     name is told so.
//  2. The app id must not be in cmd.LiveAppIDs — the api's ledger. The api
//     refuses these before sending; this is the independent second gate, so a
//     live app's volume is unreachable through this verb even if the api that
//     called it is wrong.
//  3. Docker's own labels must agree: the volume must carry
//     com.docker.compose.project=rasp_<ulid>. A volume that merely LOOKS like
//     ours by name but was not created by our compose project is refused.
//  4. No container may reference the volume, running or not. A referenced
//     volume belongs to something that is still here.
//
// Every rule is a refusal with a reason, and an ack accounts for every name
// it was sent in either Removed or Refused.

// Compose's volume labels, as docker sets them.
const (
	labelComposeProject = "com.docker.compose.project"
	labelComposeVolume  = "com.docker.compose.volume"
)

// dockerExec runs the docker CLI with args and returns combined output. It is
// a field so tests can substitute a fake; the real one is runDocker.
type dockerExec func(ctx context.Context, args ...string) ([]byte, error)

func runDocker(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// volumeInspect is the subset of `docker volume inspect` this file reads.
type volumeInspect struct {
	Name       string            `json:"Name"`
	CreatedAt  string            `json:"CreatedAt"`
	Labels     map[string]string `json:"Labels"`
	Mountpoint string            `json:"Mountpoint"`
}

// dockerFor returns the exec to use — the injected one, or the real CLI.
func (c *ComposeBackend) dockerFor() dockerExec {
	if c.exec != nil {
		return c.exec
	}
	return runDocker
}

// sizeFor returns the directory sizer — the injected one, or a file walk.
func (c *ComposeBackend) sizeFor() func(string) (uint64, error) {
	if c.sizeOf != nil {
		return c.sizeOf
	}
	return dirSize
}

// dirSize sums the sizes of every regular file under root. It is what the
// agent can measure without the daemon's help — `docker volume ls` does not
// report size, and `docker system df -v` walks every volume on the host to
// answer for one. A volume mountpoint the agent cannot read counts as zero,
// with the error returned so the caller can say so.
func dirSize(root string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 0 {
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

// volumeLsArgs lists, by name only, every volume docker labels as belonging to
// SOME compose project. The rasp_ prefix is applied by the caller: docker's
// filter has no prefix match, and the name parse is the real check anyway.
func volumeLsArgs() []string {
	return []string{"volume", "ls", "--quiet", "--filter", "label=" + labelComposeProject}
}

func volumeInspectJSONArgs(names ...string) []string {
	return append([]string{"volume", "inspect", "--format", "{{json .}}"}, names...)
}

// volumeUsersArgs lists (by id) every container, running or not, that
// references the volume.
func volumeUsersArgs(name string) []string {
	return []string{"ps", "--all", "--quiet", "--filter", "volume=" + name}
}

func volumeRmArgs(name string) []string {
	return []string{"volume", "rm", name}
}

// ListProjectVolumes implements VolumeReaper.
func (c *ComposeBackend) ListProjectVolumes(ctx context.Context) ([]proto.AppVolumeInfo, error) {
	run := c.dockerFor()
	out, err := run(ctx, volumeLsArgs()...)
	if err != nil {
		return nil, fmt.Errorf("%s", formatCmdErr("docker volume ls", out, err))
	}
	var names []string
	for _, line := range splitLines(out) {
		if _, _, ok := proto.ParseAppVolumeName(line); ok {
			names = append(names, line)
		}
	}
	if len(names) == 0 {
		return []proto.AppVolumeInfo{}, nil
	}
	inspected, err := c.inspect(ctx, run, names)
	if err != nil {
		return nil, err
	}
	size := c.sizeFor()
	vols := make([]proto.AppVolumeInfo, 0, len(inspected))
	for _, v := range inspected {
		appID, volume, ok := proto.ParseAppVolumeName(v.Name)
		if !ok {
			continue
		}
		// The label has to agree with the name. A volume someone made by hand
		// with our prefix is not ours to report as reclaimable.
		if v.Labels[labelComposeProject] != proto.AppProjectName(appID) {
			continue
		}
		info := proto.AppVolumeInfo{Name: v.Name, AppID: appID, Volume: volume}
		if t, err := time.Parse(time.RFC3339Nano, v.CreatedAt); err == nil {
			info.CreatedAt = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, v.CreatedAt); err == nil {
			info.CreatedAt = t.UTC()
		}
		if v.Mountpoint != "" {
			// A size the agent could not measure is reported as zero rather
			// than failing the whole listing: the operator still needs to see
			// the volume exists.
			if n, err := size(v.Mountpoint); err == nil {
				info.SizeBytes = n
			}
		}
		users, err := run(ctx, volumeUsersArgs(v.Name)...)
		if err != nil {
			return nil, fmt.Errorf("%s", formatCmdErr("docker ps --filter volume="+v.Name, users, err))
		}
		info.InUse = len(splitLines(users)) > 0
		vols = append(vols, info)
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	return vols, nil
}

// RemoveProjectVolumes implements VolumeReaper. See the file comment for the
// rules; every one of them ends in a refusal by name.
func (c *ComposeBackend) RemoveProjectVolumes(ctx context.Context, cmd proto.AppVolumesRemoveCmd) proto.AppVolumesRemoveAck {
	ack := proto.AppVolumesRemoveAck{OK: true, Removed: []string{}, Refused: []proto.AppVolumeRefusal{}}
	live := make(map[string]bool, len(cmd.LiveAppIDs))
	for _, id := range cmd.LiveAppIDs {
		live[strings.ToUpper(id)] = true
	}
	run := c.dockerFor()
	refuse := func(name, reason string) {
		ack.Refused = append(ack.Refused, proto.AppVolumeRefusal{Name: name, Reason: reason})
	}
	for _, name := range cmd.Names {
		if reason := proto.RefuseAppVolumeName(name, live); reason != "" {
			refuse(name, reason)
			continue
		}
		appID, _, _ := proto.ParseAppVolumeName(name)
		inspected, err := c.inspect(ctx, run, []string{name})
		if err != nil || len(inspected) != 1 {
			detail := "docker could not inspect it"
			if err != nil {
				detail = err.Error()
			}
			refuse(name, "not removed: "+detail)
			continue
		}
		if got := inspected[0].Labels[labelComposeProject]; got != proto.AppProjectName(appID) {
			refuse(name, fmt.Sprintf("not a volume of compose project %s (docker labels it %q)", proto.AppProjectName(appID), got))
			continue
		}
		users, err := run(ctx, volumeUsersArgs(name)...)
		if err != nil {
			refuse(name, "not removed: "+formatCmdErr("docker ps --filter volume="+name, users, err))
			continue
		}
		if ids := splitLines(users); len(ids) > 0 {
			refuse(name, fmt.Sprintf("still referenced by %d container(s): %s", len(ids), strings.Join(ids, ", ")))
			continue
		}
		out, err := run(ctx, volumeRmArgs(name)...)
		if err != nil {
			ack.OK = false
			refuse(name, formatCmdErr("docker volume rm", out, err))
			continue
		}
		ack.Removed = append(ack.Removed, name)
	}
	return ack
}

// inspect runs `docker volume inspect` for names and decodes the result. The
// CLI emits one JSON object per line with --format '{{json .}}'.
func (c *ComposeBackend) inspect(ctx context.Context, run dockerExec, names []string) ([]volumeInspect, error) {
	out, err := run(ctx, volumeInspectJSONArgs(names...)...)
	if err != nil {
		return nil, fmt.Errorf("%s", formatCmdErr("docker volume inspect", out, err))
	}
	var vols []volumeInspect
	for _, line := range splitLines(out) {
		var v volumeInspect
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, fmt.Errorf("parse docker volume inspect: %w", err)
		}
		vols = append(vols, v)
	}
	return vols, nil
}

// splitLines returns the non-empty, trimmed lines of out.
func splitLines(out []byte) []string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
