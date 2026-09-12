package docker

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Volumes a compose change would drop — geekdojo/geekdojo-brain#412.
//
// A new compose that renames a volume key, or drops the service that mounted
// one, makes `up` exit 0 and mount a new empty volume; the data stays in the
// old volume with nothing mounting it (measured case 3, app-catalog.md §8a.2).
// The api refuses such a change unless the owner names those volumes for
// deletion, and it cannot tell which volumes a compose declares itself: no
// YAML parser enters the control plane (ADR-0006 D4). So the node answers,
// with Compose's own reading of the compose:
//
//   - CheckVolumes stages the new compose beside the live one, asks
//     `docker compose config --volumes` for the keys it declares, and
//     compares them with the app's named volumes on disk.
//   - DropAppVolumes removes, after `up` has succeeded, exactly the volumes
//     the owner named — refusing any the live compose still declares — through
//     gateAndRemove, the one by-name removal path the orphan reaper and the
//     delete-with-data sweep already share.
//
// Anonymous volumes are out of this gate. They have no key, so there is
// nothing to compare, and #413 records every one an app's containers mount so
// that deleting the app with its data removes them.

// stagedCheckPattern names the throwaway compose file CheckVolumes hands
// `compose config`. Distinct from the pull's, so neither can be mistaken for
// the other in an app's state directory.
const stagedCheckPattern = ".volumes-*.docker-compose.yml"

// composeConfigVolumesArgs prints the volume keys of a compose, one per line.
//
// Measured against compose v5.0.1 (2026-09-12), and read in compose v2.32.4's
// source (cmd/compose/config.go runVolumes), the version Buildroot 2025.02.17
// packages: both load the project exactly as `up` does — interpolation, the
// project directory's `.env`, profiles — drop every volume no enabled service
// mounts (WithoutUnnecessaryResources), and print the keys of what is left.
// That is the set `up` creates and keeps mounted, which is the comparison this
// gate needs: a key declared at the top level but mounted by nothing, or only
// by a service in a profile Rasputin never enables, orphans its data exactly
// as a removed key does. Keys are printed, not volume names, and in map order.
// An invalid compose (a service naming an undeclared volume, bad YAML) exits
// non-zero. It does not resolve env_file contents, which it does not need.
func composeConfigVolumesArgs() []string {
	return []string{"config", "--volumes"}
}

// parseVolumeKeys reads `compose config --volumes` output. The run merges
// stderr into stdout, so a warning compose prints on the way (an unset
// variable, an obsolete `version:`) is in the same buffer; only lines that
// are a whole compose volume key — compose-spec's ^[a-zA-Z0-9._-]+$ — are
// taken, and a warning, which always carries spaces or quotes, never is.
func parseVolumeKeys(out []byte) []string {
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if isVolumeKey(line) {
			seen[line] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isVolumeKey(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// declaredVolumeKeys is the set of volume keys the compose file at path
// declares, as compose resolves it under appID's project.
func (c *ComposeBackend) declaredVolumeKeys(ctx context.Context, appID, path string) (map[string]bool, []string, error) {
	out, err := c.dockerFor()(ctx, composeArgs(path, projectName(appID), composeConfigVolumesArgs()...)...)
	if err != nil {
		return nil, nil, errors.New(formatCmdErr("docker compose config --volumes", out, err))
	}
	keys := parseVolumeKeys(out)
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return set, keys, nil
}

// namedVolumesOnDisk is every named volume of appID's project on this node:
// labelled com.docker.compose.project=rasp_<appid> and named rasp_<appid>_*.
// The same identity removeAppVolumes and the orphan listing use; a `name:`
// volume labelled for the project but not named for it is not included, as
// neither of those paths can see it either.
func (c *ComposeBackend) namedVolumesOnDisk(ctx context.Context, appID string) ([]proto.AppDroppedVolume, error) {
	project := projectName(appID)
	out, err := c.dockerFor()(ctx, projectVolumeLsArgs(project)...)
	if err != nil {
		return nil, errors.New(formatCmdErr("docker volume ls --filter label="+labelComposeProject, out, err))
	}
	var vols []proto.AppDroppedVolume
	for _, name := range splitLines(out) {
		owner, key, ok := proto.ParseAppVolumeName(name)
		if !ok || proto.AppProjectName(owner) != project {
			continue
		}
		vols = append(vols, proto.AppDroppedVolume{Name: name, Volume: key})
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	return vols, nil
}

// CheckVolumes implements Backend: the keys composeYAML declares, and every
// named volume appID has on this node that it does not.
//
// Read-only, and like Pull it does not hold c.mu: nothing here writes the
// app's live compose or touches a container, and a check is part of every
// compose change's first step, which must not queue behind another app's
// deploy.
func (c *ComposeBackend) CheckVolumes(ctx context.Context, appID, composeYAML string) ([]string, []proto.AppDroppedVolume, error) {
	if !proto.ValidAppID(appID) {
		// The project name, and so every volume name compared below, is
		// derived from the id; anything but a ULID names no app's volumes.
		return nil, nil, fmt.Errorf("refusing app id %q: not an app id", appID)
	}
	staged, cleanup, err := c.stageCompose(appID, stagedCheckPattern, composeYAML)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()
	declared, keys, err := c.declaredVolumeKeys(ctx, appID, staged)
	if err != nil {
		return nil, nil, err
	}
	onDisk, err := c.namedVolumesOnDisk(ctx, appID)
	if err != nil {
		return nil, nil, err
	}
	dropped := []proto.AppDroppedVolume{}
	for _, v := range onDisk {
		if !declared[v.Volume] {
			dropped = append(dropped, v)
		}
	}
	return keys, dropped, nil
}

// DropAppVolumes implements VolumeReaper: remove named volumes of a live app
// that its compose on disk no longer declares, by exact name.
//
// It exists beside RemoveProjectVolumes rather than inside it because that
// verb's second rule — the owner must not be in the api's ledger — is the one
// that keeps a live app's data out of the reaper's reach, and it must stay
// true. This verb is for a live app, so it replaces that rule with one of its
// own, checked here on the node rather than trusted from the caller: the
// app's compose file, which the `up` that preceded this wrote, must not
// declare the volume's key. The rest are the shared gates:
//
//  1. The name must be a named volume of cmd.AppID's own project
//     (proto.RefuseAppDeleteVolumeName) — never an anonymous volume, never
//     another app's.
//  2. The live compose must be readable and must not declare the key. A
//     missing file, or one compose cannot read, refuses every name: what it
//     declares cannot be proved.
//  3. gateAndRemove: docker labels it for this project, and no container
//     references it, running or not.
//
// A volume docker no longer has is not refused — an earlier attempt removed
// it — and is named in Detail rather than in Removed.
//
// c.mu is held: this reads the live compose file, which Deploy writes under
// the same lock, and removal must not interleave with a deploy of the app
// that could start mounting the volume again.
func (c *ComposeBackend) DropAppVolumes(ctx context.Context, cmd proto.AppVolumesDropCmd) proto.AppVolumesRemoveAck {
	c.mu.Lock()
	defer c.mu.Unlock()
	ack := proto.AppVolumesRemoveAck{OK: true, Removed: []string{}, Refused: []proto.AppVolumeRefusal{}}
	refuseAll := func(reason string) proto.AppVolumesRemoveAck {
		for _, name := range cmd.Names {
			ack.Refused = append(ack.Refused, proto.AppVolumeRefusal{Name: name, Reason: reason})
		}
		return ack
	}
	if !proto.ValidAppID(cmd.AppID) || !safeAppID(cmd.AppID) {
		return refuseAll(fmt.Sprintf("not removed: %q is not an app id", cmd.AppID))
	}
	if _, err := os.Stat(c.composePath(cmd.AppID)); err != nil {
		return refuseAll("not removed: the app has no compose file on this node, so what it still declares cannot be checked: " + err.Error())
	}
	declared, _, err := c.declaredVolumeKeys(ctx, cmd.AppID, c.composePath(cmd.AppID))
	if err != nil {
		return refuseAll("not removed: what the app's compose on this node declares could not be read: " + err.Error())
	}
	run := c.dockerFor()
	var absent []string
	for _, name := range cmd.Names {
		if reason := proto.RefuseAppDeleteVolumeName(cmd.AppID, name); reason != "" {
			ack.Refused = append(ack.Refused, proto.AppVolumeRefusal{Name: name, Reason: reason})
			continue
		}
		_, key, _ := proto.ParseAppVolumeName(name)
		if declared[key] {
			ack.Refused = append(ack.Refused, proto.AppVolumeRefusal{Name: name,
				Reason: fmt.Sprintf("the app's compose on this node still declares volume %q; a volume the app's compose declares is never deleted", key)})
			continue
		}
		res := c.gateAndRemove(ctx, run, name, cmd.AppID, false)
		switch {
		case res.removed:
			ack.Removed = append(ack.Removed, name)
		case res.absent:
			absent = append(absent, name)
		default:
			ack.OK = ack.OK && !res.rmFailed
			ack.Refused = append(ack.Refused, proto.AppVolumeRefusal{Name: name, Reason: res.reason})
		}
	}
	if len(absent) > 0 {
		ack.Detail = "already absent: " + strings.Join(absent, ", ")
	}
	return ack
}
