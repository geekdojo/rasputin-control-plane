package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Every volume an app ever had — geekdojo/geekdojo-brain#413.
//
// `docker compose down -v` removes only the volumes the CURRENT compose
// declares (measured, case 8 of app-catalog.md §8a.2). Three kinds survive it:
//
//  1. a volume whose key an upgrade renamed away;
//  2. the volume of a service an upgrade dropped;
//  3. an anonymous volume — a service's unnamed `- /path` mount, or an image's
//     Dockerfile VOLUME the compose maps nothing to (immich's valkey declares
//     VOLUME /data today, so this one leaks before any upgrade exists).
//
// Kinds 1 and 2 keep their compose labels after `down`, so they can be found at
// any time by com.docker.compose.project and the rasp_<appid>_ name. Kind 3
// cannot: docker labels an anonymous volume com.docker.volume.anonymous and
// nothing else, so the only link between it and the app is a container of the
// app's project mounting it — and `down` removes the containers. That is why a
// delete cannot find these by looking at the node when it runs. The normal
// owner flow is stop, then delete: app.stop runs `down`, the containers go, and
// by the time app.delete runs there is nothing left that names the volume.
//
// So the agent RECORDS anonymous volumes while the containers exist, in
// <state>/<appID>/volumes.json, and never forgets one on its own: the record is
// a union across every compose version the app has run. It is taken
//
//   - before and after every `up` (deploy, upgrade and revert all deploy): after,
//     because that is when the current containers exist; before, because an
//     `up --remove-orphans` that drops a service removes the only container
//     that mounted its anonymous volume, and an app first deployed by an agent
//     older than the record has not been recorded yet;
//   - before every `down`, which is the last moment the containers exist.
//
// Named volumes are deliberately NOT recorded. Their labels already say whose
// they are, for as long as they exist, and a second copy of that fact could
// only disagree with the first.
//
// Only the delete-WITH-data path removes anything here, and everything it
// removes goes by exact name through gateAndRemove (volumes.go) — the same
// docker-side checks the orphan reaper applies. The keep-data delete removes
// nothing; the record is what lets the reaper list what it kept.

// volumeRecordFile is the per-app record's file name inside the app's state
// directory, beside docker-compose.yml.
const volumeRecordFile = "volumes.json"

// labelAnonymousVolume is the label docker puts on a volume it created for an
// unnamed mount — measured on Docker Engine 29.1.3 / Compose v5.0.1; which
// engine release introduced it, and whether the OS image's engine sets it, was
// not checked. It is docker's own statement that the volume is anonymous; a
// volume without it is never treated as one, so an engine that does not set
// it records nothing and removes nothing on this path.
const labelAnonymousVolume = "com.docker.volume.anonymous"

// labelComposeService is the label compose puts on each container naming its
// service — recorded so an anonymous volume can be described to an operator.
const labelComposeService = "com.docker.compose.service"

// volumeRecord is the on-disk record of the anonymous volumes an app's
// containers have been seen mounting.
type volumeRecord struct {
	AppID     string           `json:"appId"`
	Anonymous []recordedVolume `json:"anonymous"`
}

// recordedVolume is one anonymous volume, with where it was first seen.
type recordedVolume struct {
	Name      string    `json:"name"`
	Service   string    `json:"service,omitempty"`
	Path      string    `json:"path,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
}

func (c *ComposeBackend) recordPath(appID string) string {
	return filepath.Join(c.appDir(appID), volumeRecordFile)
}

// loadRecord reads appID's record. A missing record is an empty one: an app
// that never mounted an anonymous volume has none.
func (c *ComposeBackend) loadRecord(appID string) (*volumeRecord, error) {
	rec := &volumeRecord{AppID: appID}
	b, err := os.ReadFile(c.recordPath(appID))
	if errors.Is(err, fs.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read volume record: %w", err)
	}
	if err := json.Unmarshal(b, rec); err != nil {
		return nil, fmt.Errorf("parse volume record %s: %w", c.recordPath(appID), err)
	}
	return rec, nil
}

// saveRecord writes rec to appID's directory atomically, or removes the file
// when it records nothing — so an empty record never outlives the volumes it
// described.
func (c *ComposeBackend) saveRecord(appID string, rec *volumeRecord) error {
	path := c.recordPath(appID)
	if len(rec.Anonymous) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove volume record: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(c.appDir(appID), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	sort.Slice(rec.Anonymous, func(i, j int) bool { return rec.Anonymous[i].Name < rec.Anonymous[j].Name })
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write volume record: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write volume record: %w", err)
	}
	return nil
}

// projectContainersArgs lists (by full id) every container of the compose
// project, running or not.
func projectContainersArgs(project string) []string {
	return []string{"ps", "--all", "--quiet", "--no-trunc", "--filter", "label=" + labelComposeProject + "=" + project}
}

// containerInspectArgs inspects containers by id. The ids come from
// projectContainersArgs' output, and sit after `--` regardless.
func containerInspectArgs(ids ...string) []string {
	return append([]string{"container", "inspect", "--format", "{{json .}}", "--"}, ids...)
}

// projectVolumeLsArgs lists, by name, every volume labelled for the project.
func projectVolumeLsArgs(project string) []string {
	return []string{"volume", "ls", "--quiet", "--filter", "label=" + labelComposeProject + "=" + project}
}

// containerInspect is the subset of `docker container inspect` read here.
type containerInspect struct {
	Name   string `json:"Name"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}

// observeAnonymousVolumes returns every anonymous volume a container of
// appID's project mounts right now.
//
// A mount is taken only when docker itself says the volume is anonymous: the
// name has docker's 64-hex shape, the volume carries com.docker.volume.anonymous
// and it carries NO compose project label. A named volume of another project
// that this app mounts (a custom compose's `external:` volume, or case 4's
// explicit `name:`) is therefore never recorded as this app's.
func (c *ComposeBackend) observeAnonymousVolumes(ctx context.Context, appID string) ([]recordedVolume, error) {
	run := c.dockerFor()
	out, err := run(ctx, projectContainersArgs(projectName(appID))...)
	if err != nil {
		return nil, fmt.Errorf("%s", formatCmdErr("docker ps --filter label="+labelComposeProject, out, err))
	}
	ids := splitLines(out)
	if len(ids) == 0 {
		return nil, nil
	}
	out, err = run(ctx, containerInspectArgs(ids...)...)
	if err != nil {
		return nil, fmt.Errorf("%s", formatCmdErr("docker container inspect", out, err))
	}
	candidates := map[string]recordedVolume{}
	for _, line := range splitLines(out) {
		var ci containerInspect
		if err := json.Unmarshal([]byte(line), &ci); err != nil {
			return nil, fmt.Errorf("parse docker container inspect: %w", err)
		}
		for _, m := range ci.Mounts {
			if m.Type != "volume" || !proto.IsAnonymousVolumeName(m.Name) {
				continue
			}
			if _, seen := candidates[m.Name]; seen {
				continue
			}
			candidates[m.Name] = recordedVolume{Name: m.Name, Service: ci.Config.Labels[labelComposeService], Path: m.Destination}
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(candidates))
	for n := range candidates {
		names = append(names, n)
	}
	sort.Strings(names)
	inspected, err := c.inspect(ctx, run, names)
	if err != nil {
		return nil, err
	}
	var vols []recordedVolume
	for _, v := range inspected {
		if !isDockerAnonymous(v) {
			continue
		}
		if rv, ok := candidates[v.Name]; ok {
			vols = append(vols, rv)
		}
	}
	return vols, nil
}

// isDockerAnonymous is docker's own word that v was created for an unnamed
// mount and belongs to no compose project.
func isDockerAnonymous(v volumeInspect) bool {
	if !proto.IsAnonymousVolumeName(v.Name) {
		return false
	}
	if _, ok := v.Labels[labelAnonymousVolume]; !ok {
		return false
	}
	_, project := v.Labels[labelComposeProject]
	return !project
}

// recordVolumes adds every anonymous volume appID's containers mount now to
// its record. It only ever adds: a volume leaves the record when it is
// removed, never because a container stopped mounting it.
func (c *ComposeBackend) recordVolumes(ctx context.Context, appID string) error {
	seen, err := c.observeAnonymousVolumes(ctx, appID)
	if err != nil {
		return err
	}
	if len(seen) == 0 {
		return nil
	}
	rec, err := c.loadRecord(appID)
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(rec.Anonymous))
	for _, v := range rec.Anonymous {
		known[v.Name] = true
	}
	added := false
	now := time.Now().UTC()
	for _, v := range seen {
		if known[v.Name] {
			continue
		}
		v.FirstSeen = now
		rec.Anonymous = append(rec.Anonymous, v)
		added = true
	}
	if !added {
		return nil
	}
	return c.saveRecord(appID, rec)
}

// recordVolumesOrLog is recordVolumes where a failure must not fail the verb
// it rides on: a deploy that brought the app up, or a stop the owner asked
// for. It is logged, because a record that could not be written is an
// anonymous volume a later delete will not find.
func (c *ComposeBackend) recordVolumesOrLog(ctx context.Context, appID, verb string) {
	if err := c.recordVolumes(ctx, appID); err != nil {
		log.Printf("rasputin-agent: %s %s: could not record the app's anonymous volumes (a later delete may not find them): %v", verb, appID, err)
	}
}

// appVolumeSweep is what removeAppVolumes did.
type appVolumeSweep struct {
	Removed []string
	Refused []proto.AppVolumeRefusal
}

// removeAppVolumes removes every volume appID ever had that is still on the
// node: the named volumes labelled for its project (whatever the current
// compose declares) and the anonymous volumes its record names. It runs after
// `down -v`, so on a clean delete it finds only what `down -v` could not see.
//
// Every name goes through gateAndRemove, which refuses a volume any container
// still references — after `down` none of this app's containers exist, so a
// referencing container is by construction outside the app's project — and a
// volume whose docker labels disagree with the identity it was found by.
// Removed anonymous volumes leave the record; a refused one stays in it, so
// the orphan reaper can still list it once the app row is gone.
func (c *ComposeBackend) removeAppVolumes(ctx context.Context, appID string) (appVolumeSweep, error) {
	sweep := appVolumeSweep{Removed: []string{}, Refused: []proto.AppVolumeRefusal{}}
	run := c.dockerFor()
	project := projectName(appID)

	out, err := run(ctx, projectVolumeLsArgs(project)...)
	if err != nil {
		return sweep, fmt.Errorf("%s", formatCmdErr("docker volume ls --filter label="+labelComposeProject, out, err))
	}
	for _, name := range splitLines(out) {
		owner, _, ok := proto.ParseAppVolumeName(name)
		if !ok || proto.AppProjectName(owner) != project {
			// Labelled for this project but not named rasp_<appid>_*: a
			// compose `name:` volume. Not ours to remove by label alone —
			// the orphan reaper cannot list it either, and the two paths
			// must agree on what "this app's volume" means.
			continue
		}
		_ = c.sweepOne(ctx, run, &sweep, name, appID, false)
	}

	rec, err := c.loadRecord(appID)
	if err != nil {
		return sweep, err
	}
	owners, _, err := c.anonymousOwners()
	if err != nil {
		return sweep, err
	}
	kept := rec.Anonymous[:0]
	for _, v := range rec.Anonymous {
		if !proto.IsAnonymousVolumeName(v.Name) {
			// A hand-edited record. Refused by name, never passed to docker.
			sweep.Refused = append(sweep.Refused, proto.AppVolumeRefusal{Name: v.Name, Reason: "not an anonymous volume name"})
			kept = append(kept, v)
			continue
		}
		if claimants := owners[v.Name]; len(claimants) > 1 {
			// Another app's containers mounted it too — a custom compose
			// can name an anonymous volume as `external:`. Whose data it is
			// cannot be told from here, so it is nobody's to delete.
			sweep.Refused = append(sweep.Refused, proto.AppVolumeRefusal{Name: v.Name, Reason: claimedByMany(claimants)})
			kept = append(kept, v)
			continue
		}
		if !c.sweepOne(ctx, run, &sweep, v.Name, appID, true) {
			kept = append(kept, v)
		}
	}
	rec.Anonymous = kept
	if err := c.saveRecord(appID, rec); err != nil {
		return sweep, err
	}
	return sweep, nil
}

// sweepOne removes one volume for removeAppVolumes and reports whether it is
// gone afterwards — removed now, or already absent.
func (c *ComposeBackend) sweepOne(ctx context.Context, run dockerExec, sweep *appVolumeSweep, name, appID string, anonymous bool) bool {
	res := c.gateAndRemove(ctx, run, name, appID, anonymous)
	switch {
	case res.removed:
		sweep.Removed = append(sweep.Removed, name)
		return true
	case res.absent:
		// `down -v` or an earlier attempt already removed it.
		return true
	default:
		sweep.Refused = append(sweep.Refused, proto.AppVolumeRefusal{Name: name, Reason: res.reason})
		return false
	}
}

// anonymousOwner is one app directory whose record names an anonymous volume.
type anonymousOwner struct {
	AppID string // upper-cased, as the ledger holds it
	Dir   string // the state directory's name, as the agent created it
}

// anonymousOwners maps every anonymous volume named in any app's record under
// the state root to the apps whose records name it. The directory name is the
// app id; a directory that is not a ULID, or whose record claims a different
// app, is not trusted as an owner.
func (c *ComposeBackend) anonymousOwners() (map[string][]anonymousOwner, map[string]recordedVolume, error) {
	owners := map[string][]anonymousOwner{}
	meta := map[string]recordedVolume{}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return owners, meta, nil
		}
		return nil, nil, fmt.Errorf("read state root: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() || !proto.ValidAppID(e.Name()) {
			continue
		}
		rec, err := c.loadRecord(e.Name())
		if err != nil {
			log.Printf("rasputin-agent: docker.volumes: skipping %s: %v", e.Name(), err)
			continue
		}
		if !strings.EqualFold(rec.AppID, e.Name()) {
			log.Printf("rasputin-agent: docker.volumes: skipping %s: its record names app %q", e.Name(), rec.AppID)
			continue
		}
		owner := anonymousOwner{AppID: strings.ToUpper(e.Name()), Dir: e.Name()}
		for _, v := range rec.Anonymous {
			if !proto.IsAnonymousVolumeName(v.Name) {
				continue
			}
			owners[v.Name] = append(owners[v.Name], owner)
			meta[v.Name] = v
		}
	}
	return owners, meta, nil
}

// forgetAnonymous drops name from the record in state directory dir after the
// reaper removed it.
func (c *ComposeBackend) forgetAnonymous(dir, name string) error {
	rec, err := c.loadRecord(dir)
	if err != nil {
		return err
	}
	kept := rec.Anonymous[:0]
	for _, v := range rec.Anonymous {
		if v.Name != name {
			kept = append(kept, v)
		}
	}
	rec.Anonymous = kept
	return c.saveRecord(dir, rec)
}

// claimedByMany is the refusal for an anonymous volume more than one app's
// record names.
func claimedByMany(claimants []anonymousOwner) string {
	ids := make([]string, 0, len(claimants))
	for _, o := range claimants {
		ids = append(ids, o.AppID)
	}
	sort.Strings(ids)
	return "anonymous volume recorded for more than one app (" + strings.Join(ids, ", ") + "); whose data it is cannot be told, so it is not removed"
}
