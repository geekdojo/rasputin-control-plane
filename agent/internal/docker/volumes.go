package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
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
//     An anonymous volume's 64-hex name (geekdojo/geekdojo-brain#413) carries
//     no app id, so for one the rule is instead: exactly one app's per-app
//     record on this node (appvolumes.go) names it, and that app is its owner.
//     No record, or two, is a refusal by name.
//  2. The owning app id must not be in cmd.LiveAppIDs — the api's ledger. The
//     api refuses these before sending; this is the independent second gate,
//     so a live app's volume is unreachable through this verb even if the api
//     that called it is wrong.
//  3. Docker's own labels must agree: a named volume must carry
//     com.docker.compose.project=rasp_<ulid>, and an anonymous one must carry
//     com.docker.volume.anonymous and no project label. A volume that merely
//     LOOKS like ours by name but was not created by our compose project is
//     refused.
//  4. No container may reference the volume, running or not. A referenced
//     volume belongs to something that is still here.
//
// Rules 3 and 4 live in gateAndRemove, which is also the only way the
// delete-with-data sweep removes anything. Every rule is a refusal with a
// reason, and an ack accounts for every name it was sent in either Removed or
// Refused.

// Compose's volume labels, as docker sets them.
const (
	labelComposeProject = "com.docker.compose.project"
	labelComposeVolume  = "com.docker.compose.volume"
)

// dockerExec runs the docker CLI with args and returns combined output. It is
// a field so tests can substitute a fake; the real one is runDocker.
type dockerExec func(ctx context.Context, args ...string) ([]byte, error)

// runDocker is argv-form exec of the literal "docker" binary — no shell, so
// no argument can become a command. What constrains the arguments: every
// vector is built by the *Args builders in this file from constants plus
// volume names, and every volume name has passed proto.ParseAppVolumeName
// (rasp_<26-char Crockford ULID>_<volume>) or proto.IsAnonymousVolumeName
// (64 hex) before it is used — as a `--filter` VALUE, or as a free operand
// after `--`. The container ids appvolumes.go inspects come from docker's own
// `ps --quiet` output and also sit after `--`.
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
		// A size is never negative, but the conversion below is only sound
		// once that is checked on the value itself.
		if size := info.Size(); size > 0 {
			total += uint64(size)
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

// Every free operand below sits after a `--`, so a volume name can never be
// read as an option however it is shaped. Belt and braces: every name that
// reaches these has already passed proto.ParseAppVolumeName, which requires
// the rasp_ prefix, or proto.IsAnonymousVolumeName, which admits only hex, so
// none can begin with `-`; the `--` makes that a property of the argv rather
// than of the caller.
func volumeInspectJSONArgs(names ...string) []string {
	return append([]string{"volume", "inspect", "--format", "{{json .}}", "--"}, names...)
}

// volumeUsersArgs lists (by id) every container, running or not, that
// references the volume.
func volumeUsersArgs(name string) []string {
	return []string{"ps", "--all", "--quiet", "--filter", "volume=" + name}
}

func volumeRmArgs(name string) []string {
	return []string{"volume", "rm", "--", name}
}

// ListProjectVolumes implements VolumeReaper.
func (c *ComposeBackend) ListProjectVolumes(ctx context.Context, opts proto.AppVolumesListCmd) ([]proto.AppVolumeInfo, error) {
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
	vols := []proto.AppVolumeInfo{}
	if len(names) > 0 {
		inspected, err := c.inspect(ctx, run, names)
		if err != nil {
			return nil, err
		}
		for _, v := range inspected {
			appID, volume, ok := proto.ParseAppVolumeName(v.Name)
			if !ok {
				continue
			}
			// The label has to agree with the name. A volume someone made by
			// hand with our prefix is not ours to report as reclaimable.
			if v.Labels[labelComposeProject] != proto.AppProjectName(appID) {
				continue
			}
			info, err := c.describe(ctx, run, v, opts)
			if err != nil {
				return nil, err
			}
			info.AppID, info.Volume = appID, volume
			vols = append(vols, info)
		}
	}
	anon, err := c.listRecordedAnonymous(ctx, run, opts)
	if err != nil {
		return nil, err
	}
	vols = append(vols, anon...)
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	return vols, nil
}

// listRecordedAnonymous lists the anonymous volumes the per-app records name
// (appvolumes.go) — the only way the reaper can see one, since docker gives an
// anonymous volume no project label (geekdojo/geekdojo-brain#413).
//
// Each is listed only when all of these hold, which is the anonymous-volume
// analogue of "the label has to agree with the name":
//
//   - exactly one app's record names it — a volume two records claim has no
//     single owner for the api's ledger rule to be applied to;
//   - docker still has it, and still labels it anonymous and project-less.
//
// A record naming a volume docker no longer has is not an error: an operator
// may have removed it by hand. It is simply not listed.
func (c *ComposeBackend) listRecordedAnonymous(ctx context.Context, run dockerExec, opts proto.AppVolumesListCmd) ([]proto.AppVolumeInfo, error) {
	owners, meta, err := c.anonymousOwners()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(owners))
	for name, claimants := range owners {
		if len(claimants) == 1 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var vols []proto.AppVolumeInfo
	for _, name := range names {
		// One at a time: `volume inspect` fails the whole batch on a single
		// missing name, and a recorded volume going missing is ordinary.
		inspected, err := c.inspect(ctx, run, []string{name})
		if err != nil || len(inspected) != 1 || !isDockerAnonymous(inspected[0]) {
			continue
		}
		info, err := c.describe(ctx, run, inspected[0], opts)
		if err != nil {
			return nil, err
		}
		rv := meta[name]
		info.AppID = owners[name][0].AppID
		info.Anonymous, info.Service, info.Path = true, rv.Service, rv.Path
		vols = append(vols, info)
	}
	return vols, nil
}

// describe fills the parts of an AppVolumeInfo that do not depend on how the
// volume was identified: its name, creation time, size and whether any
// container references it.
func (c *ComposeBackend) describe(ctx context.Context, run dockerExec, v volumeInspect, opts proto.AppVolumesListCmd) (proto.AppVolumeInfo, error) {
	info := proto.AppVolumeInfo{Name: v.Name}
	if t, err := time.Parse(time.RFC3339Nano, v.CreatedAt); err == nil {
		info.CreatedAt = t.UTC()
	} else if t, err := time.Parse(time.RFC3339, v.CreatedAt); err == nil {
		info.CreatedAt = t.UTC()
	}
	if v.Mountpoint != "" && !opts.SkipSizes {
		// A size the agent could not measure is reported as zero rather
		// than failing the whole listing: the operator still needs to see
		// the volume exists.
		if n, err := c.sizeFor()(v.Mountpoint); err == nil {
			info.SizeBytes = n
		}
	}
	users, err := run(ctx, volumeUsersArgs(v.Name)...)
	if err != nil {
		return info, fmt.Errorf("%s", formatCmdErr("docker ps --filter volume="+v.Name, users, err))
	}
	info.InUse = len(splitLines(users)) > 0
	return info, nil
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
	// Read lazily, once: most reclaims name no anonymous volume at all.
	var (
		owners     map[string][]anonymousOwner
		ownersErr  error
		ownersRead bool
	)
	for _, name := range cmd.Names {
		if proto.IsAnonymousVolumeName(name) {
			if !ownersRead {
				owners, _, ownersErr = c.anonymousOwners()
				ownersRead = true
			}
			if ownersErr != nil {
				refuse(name, "not removed: "+ownersErr.Error())
				continue
			}
			claimants := owners[name]
			switch {
			case len(claimants) == 0:
				// Rule 1 for an anonymous volume: without a record naming it,
				// nothing ties it to any app, and it is not ours to touch.
				refuse(name, "not a Rasputin-managed volume: no app's volume record on this node names this anonymous volume")
				continue
			case len(claimants) > 1:
				refuse(name, claimedByMany(claimants))
				continue
			}
			owner := claimants[0]
			// Rule 2, on the owner the record names.
			if reason := proto.RefuseAppVolumeOwner(owner.AppID, live); reason != "" {
				refuse(name, reason)
				continue
			}
			res := c.gateAndRemove(ctx, run, name, owner.AppID, true)
			if !res.removed {
				ack.OK = ack.OK && !res.rmFailed
				refuse(name, res.reason)
				continue
			}
			if err := c.forgetAnonymous(owner.Dir, name); err != nil {
				// The volume is gone; a record still naming it is harmless —
				// listing skips a volume docker no longer has — but say so.
				log.Printf("rasputin-agent: docker.volumes.remove: removed %s but could not update %s's record: %v", name, owner.AppID, err)
			}
			ack.Removed = append(ack.Removed, name)
			continue
		}
		if reason := proto.RefuseAppVolumeName(name, live); reason != "" {
			refuse(name, reason)
			continue
		}
		appID, _, _ := proto.ParseAppVolumeName(name)
		res := c.gateAndRemove(ctx, run, name, appID, false)
		if !res.removed {
			ack.OK = ack.OK && !res.rmFailed
			refuse(name, res.reason)
			continue
		}
		ack.Removed = append(ack.Removed, name)
	}
	return ack
}

// gateResult is what gateAndRemove did with one name.
type gateResult struct {
	removed bool
	// absent: docker has no such volume. A refusal to the reaper, which was
	// asked for something that is not there; "already gone" to a delete.
	absent bool
	// rmFailed: every gate passed and `docker volume rm` itself failed.
	rmFailed bool
	reason   string
}

// gateAndRemove applies the docker-side refusal rules to one volume already
// attributed to appID, and removes it only if every one passes. It is the one
// place any volume is removed by name — the orphan reaper and the delete-with-
// data sweep both come through here, so the two cannot drift apart on what
// makes a removal safe:
//
//   - Rule 3, identity. A named volume must carry com.docker.compose.project =
//     rasp_<appID>. An anonymous volume must be one docker labels anonymous
//     and labels for NO project — so a named volume can never be removed by
//     being passed off as anonymous.
//   - Rule 4, no container may reference it, running or not. After `down` no
//     container of the app's own project exists, so on the delete path any
//     reference is from outside the app.
//
// The caller has already applied rules 1 and 2 (shape and ledger) where they
// apply: the reaper always; the delete sweep, which is deleting the very app
// the ledger still holds, applies identity by construction instead — it only
// ever passes names it found by this app's project label or this app's record.
func (c *ComposeBackend) gateAndRemove(ctx context.Context, run dockerExec, name, appID string, anonymous bool) gateResult {
	inspected, err := c.inspect(ctx, run, []string{name})
	if err != nil || len(inspected) != 1 {
		detail := "docker could not inspect it"
		if err != nil {
			detail = err.Error()
			if strings.Contains(strings.ToLower(detail), "no such volume") {
				return gateResult{absent: true, reason: "not removed: " + detail}
			}
		}
		return gateResult{reason: "not removed: " + detail}
	}
	v := inspected[0]
	if anonymous {
		if !isDockerAnonymous(v) {
			return gateResult{reason: fmt.Sprintf("not an anonymous volume: docker labels it %v", v.Labels)}
		}
	} else if got := v.Labels[labelComposeProject]; got != proto.AppProjectName(appID) {
		return gateResult{reason: fmt.Sprintf("not a volume of compose project %s (docker labels it %q)", proto.AppProjectName(appID), got)}
	}
	users, err := run(ctx, volumeUsersArgs(name)...)
	if err != nil {
		return gateResult{reason: "not removed: " + formatCmdErr("docker ps --filter volume="+name, users, err)}
	}
	if ids := splitLines(users); len(ids) > 0 {
		return gateResult{reason: fmt.Sprintf("still referenced by %d container(s): %s", len(ids), strings.Join(ids, ", "))}
	}
	out, err := run(ctx, volumeRmArgs(name)...)
	if err != nil {
		return gateResult{rmFailed: true, reason: formatCmdErr("docker volume rm", out, err)}
	}
	return gateResult{removed: true}
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
