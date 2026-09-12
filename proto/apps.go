package proto

import (
	"fmt"
	"strings"
	"time"
)

// AppStatus is the high-level state the api tracks for each app. The agent
// reports observed status on every command; the api stores the last value.
type AppStatus string

const (
	AppStatusStopped   AppStatus = "stopped"
	AppStatusDeploying AppStatus = "deploying"
	AppStatusRunning   AppStatus = "running"
	AppStatusStopping  AppStatus = "stopping"
	AppStatusFailed    AppStatus = "failed"
	AppStatusUnknown   AppStatus = "unknown"
)

// Deploy timing. These two live here, together, because they are ONE contract
// split across two processes and they only work if they stay ordered.
//
// AppDeployWork is how long the agent may spend on `docker compose up` — the
// real budget, and almost all of it is the image pull. AppDeployRPC is how long
// the api waits for the agent's reply. The api's must be LONGER, so the agent
// always loses the race and answers with what actually went wrong.
//
// Reversed, the api gives up while the agent is still working and the operator
// gets "deploy rpc: context deadline exceeded" — true, useless, and identical
// for a missing image, a bad compose and a slow network. That is exactly what
// shipped: a 60s api deadline under a 120s agent window, so EVERY slow deploy
// failed opaquely. Bench 2026-08-23 on e3bench: of 8 tiles deployed
// concurrently, 5 failed and every single failed task lasted exactly 1m 0s
// while the successes came in at 51s and 57s — a cliff at the deadline, not a
// spread. Two of the five recovered only because a retry hit a warm cache.
//
// 300s is the DEFAULT work budget: a four-container tile cold-pulling to an
// arm64 node over a home connection does not finish in one minute. A tile may
// override it — see AppDeployWorkFor.
const (
	AppDeployWork = 300 * time.Second
	AppDeployRPC  = AppDeployWork + AppDeployRPCSlack

	// AppDeployRPCSlack is how much longer the api waits than the agent works.
	// It covers the round trip and the agent's own teardown after its budget
	// expires; it is the whole reason the agent loses the race.
	AppDeployRPCSlack = 30 * time.Second

	// The bounds any per-app budget is clamped into. A tile declares its budget
	// in tile.json and tileschema rejects an out-of-range value at authoring
	// time, so the clamp here is the second line: the api must never hand the
	// agent a context derived from a row it did not write, whatever is in it.
	//
	// The floor is not zero on purpose. Below a minute nothing cold-pulls, and
	// a budget that cannot succeed is not a fast failure, it is a broken tile
	// that looks like a flaky network.
	AppDeployWorkMin = 60 * time.Second
	AppDeployWorkMax = 1800 * time.Second
)

// AppDeployWorkFor is how long the agent may spend bringing ONE app up: the
// tile's declared budget when it has one, AppDeployWork otherwise, clamped into
// [AppDeployWorkMin, AppDeployWorkMax].
//
// One budget for the whole catalog is a budget that fits none of it. It has to
// clear the slowest stack on the slowest link — so it gets set by immich, and
// then every fast tile inherits immich's patience. FreshRSS pulls one small
// image; when it hangs, five minutes of DEPLOYING tells the operator nothing
// that ninety seconds would not have told them sooner. Chasing the upper bound
// with a single number gates the quick apps to pay for the slow ones.
//
// Zero means "not declared", which is the only value an older api or a tile
// published before this field existed can send. It maps to the default rather
// than to zero patience.
func AppDeployWorkFor(seconds int) time.Duration {
	if seconds <= 0 {
		return AppDeployWork
	}
	d := time.Duration(seconds) * time.Second
	if d < AppDeployWorkMin {
		return AppDeployWorkMin
	}
	if d > AppDeployWorkMax {
		return AppDeployWorkMax
	}
	return d
}

// AppDeployRPCFor is the api-side deadline matching AppDeployWorkFor's budget.
// Always the longer of the pair, for the same reason AppDeployRPC is: the agent
// must lose the race and answer with what actually went wrong.
func AppDeployRPCFor(seconds int) time.Duration {
	return AppDeployWorkFor(seconds) + AppDeployRPCSlack
}

// AppDeployCmd is the request body on rasputin.node.<id>.cmd.docker.deploy.
// The agent writes the compose file to its app state directory and runs
// `docker compose up -d` (or the mock-backend equivalent).
type AppDeployCmd struct {
	AppID       string `json:"appId"`
	Name        string `json:"name"`
	ComposeYAML string `json:"composeYaml"`

	// WorkBudgetSeconds is this app's deploy budget, from its catalog tile.
	// Zero means the agent picks the default — which is what an api that
	// predates this field sends, so an old api against a new agent still gets
	// the behaviour it expects rather than an instant timeout. Read it through
	// AppDeployWorkFor, never directly.
	WorkBudgetSeconds int `json:"workBudgetSeconds,omitempty"`
}

// AppDeployAck is the synchronous reply.
type AppDeployAck struct {
	OK     bool      `json:"ok"`
	Status AppStatus `json:"status"`
	Detail string    `json:"detail,omitempty"`
}

// AppPullCmd is the request body on rasputin.node.<id>.cmd.docker.pull
// (geekdojo/geekdojo-brain#411): fetch every image ComposeYAML names, under
// the app's compose project, and do nothing else.
//
// It exists so a compose change can fail at the pull BEFORE anything on the
// node has changed. `up` pulls too, but by the time `up` runs the agent has
// already overwritten the app's compose file, and a pull that fails inside
// `up` leaves a node whose file names a compose it is not running. The agent
// stages this compose apart from the app's live file and never writes the
// live one, so a failed pull leaves the node exactly as it was — the old
// containers running (measured case 7, app-catalog.md §8a.2) and the file
// that `down` and `ps` read still describing them.
type AppPullCmd struct {
	AppID       string `json:"appId"`
	ComposeYAML string `json:"composeYaml"`

	// WorkBudgetSeconds bounds the pull, and is the same budget the deploy of
	// this compose gets: nearly all of a deploy's budget is its pull. Read it
	// through AppDeployWorkFor, never directly; zero is the default.
	WorkBudgetSeconds int `json:"workBudgetSeconds,omitempty"`
}

// AppPullAck is the synchronous reply to an AppPullCmd. There is no status:
// a pull changes no container, so the app's status is whatever it was.
type AppPullAck struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// AppStopCmd is sent on rasputin.node.<id>.cmd.docker.stop.
type AppStopCmd struct {
	AppID string `json:"appId"`
	// DeleteVolumes asks the agent to remove every volume the app ever had:
	// `compose down -v` for the volumes the current compose declares, then —
	// by exact name, through the same refusal gates the orphan reaper uses —
	// every volume `down -v` cannot see (geekdojo/geekdojo-brain#413): a
	// volume whose key an upgrade renamed away, a dropped service's volume, and
	// an anonymous volume, which carries no project label at all.
	//
	// Set ONLY by the app.delete saga, and only when the operator answered
	// "Delete volumes?" with a deliberate yes (geekdojo/geekdojo-brain#399).
	// Absent is false, which is what an api older than this field sends and
	// what an operator who did not tick the box sends — destroying data is
	// never the default, and false removes NO volume of any class. What makes
	// true safe is identity, not a pattern: a named volume must be named
	// rasp_<appID>_* AND carry this project's compose label; an anonymous one
	// must be in the agent's own record of volumes this app's containers
	// mounted; and no volume any container still references is removed.
	DeleteVolumes bool `json:"deleteVolumes,omitempty"`
}

type AppStopAck struct {
	OK     bool      `json:"ok"`
	Status AppStatus `json:"status"`
	Detail string    `json:"detail,omitempty"`
}

// AppStatusCmd asks the agent for the current status of a single app.
type AppStatusCmd struct {
	AppID string `json:"appId"`
}

type AppStatusAck struct {
	AppID    string             `json:"appId"`
	Status   AppStatus          `json:"status"`
	Services []AppServiceStatus `json:"services,omitempty"`
}

// AppServiceStatus is one container/service from a compose stack.
type AppServiceStatus struct {
	Name   string `json:"name"`
	State  string `json:"state"` // "running", "exited", etc — agent backend specific
	Health string `json:"health,omitempty"`

	// ExitCode is the container's exit status, and it is ONLY meaningful when
	// State says the container has exited. `docker compose ps --format json`
	// emits ExitCode for every container including live ones, where it reads
	// 0 — verified against compose v5.0.1: a healthy long-running busybox
	// reports {"State":"running","ExitCode":0}. So exit code alone can never
	// be read as "finished cleanly"; state and exit code are one fact and must
	// be read together.
	//
	// It is a pointer because absent and zero have to stay distinguishable on
	// the wire. An agent older than this field omits it, and an int would
	// unmarshal that silence as 0 — turning "we have no idea why this
	// container is gone" into "it completed successfully", which is precisely
	// the misreading this field exists to prevent. nil means unknown, and an
	// exited container with an unknown exit code is treated as a failure.
	ExitCode *int `json:"exitCode,omitempty"`

	// Outdated says this container was created from a service definition
	// other than the one in the app's compose file on disk — compose's own
	// com.docker.compose.config-hash label on the container differs from
	// `compose config --hash` of the file, or the file no longer declares the
	// service at all. Only reported for running containers.
	//
	// It is how the api tells "the app recovered" from "the app is still
	// running the compose it had before" (#411). The agent writes the new
	// compose before `up`, and an `up` that fails before it reaches a service
	// — a network it cannot create, a dependency that did not converge —
	// leaves that service's OLD container running under the NEW file.
	// Measured 2026-09-12 (compose v5.0.1): a network-pool conflict in the new
	// compose failed `up` with the previous container untouched and running.
	// Read as plain "running", that flipped a failed upgrade back to running
	// and routed the proxy to the new compose's port.
	//
	// false means current OR unknown — an agent older than the field, or a
	// hash that could not be read — which is exactly what every reader did
	// before the field existed.
	Outdated bool `json:"outdated,omitempty"`
}

// AppLeafCmd delivers a per-app TLS leaf (ADR-0004 §6) to the node hosting the
// app, on rasputin.node.<id>.cmd.app.leaf. The agent writes cert+key to the
// app's proxy-cert directory, where the node-local Caddy terminates TLS with
// them. Re-sent on rotation (no redeploy needed); a Remove tears the leaf down
// (app delete / re-target). Keyed by the stable AppID so a rename can't orphan
// or misdirect the files.
type AppLeafCmd struct {
	AppID   string `json:"appId"`
	Name    string `json:"name,omitempty"` // instance name — logging only
	CertPEM []byte `json:"certPem,omitempty"`
	KeyPEM  []byte `json:"keyPem,omitempty"`
	// TailnetFQDN / LANFQDN are the app's proxy Host names, from
	// mesh.AppRouteHosts. They share their FQDN constructors with the leaf's
	// SANs, so a route host matches the cert by construction — but the leaf
	// carries BOTH names always, while these carry the app's EXPOSURE: LANFQDN
	// is "" for a tailnet-only app, and that empty string is what keeps the app
	// off the node's LAN listener.
	TailnetFQDN string `json:"tailnetFqdn,omitempty"`
	LANFQDN     string `json:"lanFqdn,omitempty"`
	// UpstreamPort is the app's loopback port the node-local Caddy proxies to.
	UpstreamPort int `json:"upstreamPort,omitempty"`
	// UpstreamTLS says the app speaks HTTPS on UpstreamPort, so the proxy must
	// dial it over TLS rather than cleartext. From the tile's web port (#387);
	// absent for the overwhelming majority of apps, which serve plain HTTP
	// behind the proxy. This is the Caddy→container leg only — what the
	// operator is handed is https either way.
	UpstreamTLS bool `json:"upstreamTls,omitempty"`
	// Remove tears the leaf down (app delete / re-target). When true the other
	// fields are ignored and the app's proxy state is removed.
	Remove bool `json:"remove,omitempty"`
}

// AppLeafAck is the synchronous reply to an AppLeafCmd.
type AppLeafAck struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// AppLeafSubject is the cmd subject for delivering a leaf to nodeID.
func AppLeafSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "app.leaf")
}

// AppChangeType enumerates the change events the api publishes on
// rasputin.apps.<appId>.<change>.
type AppChangeType string

const (
	// Transitional — published the moment a saga starts working, so the UI
	// reflects the in-progress state immediately instead of looking unresponsive
	// while the (possibly slow) docker command runs.
	AppDeploying AppChangeType = "deploying"
	AppStopping  AppChangeType = "stopping"
	// Terminal.
	AppDeployed AppChangeType = "deployed"
	AppStopped  AppChangeType = "stopped"
	AppFailed   AppChangeType = "failed"
	AppDeleted  AppChangeType = "deleted"
)

// AppChangeEvt is published on rasputin.apps.<appId>.<change>.
type AppChangeEvt struct {
	AppID  string        `json:"appId"`
	Change AppChangeType `json:"change"`
	Status AppStatus     `json:"status"`
	Detail string        `json:"detail,omitempty"`
	Ts     time.Time     `json:"ts"`
}

// AppDeploySubject is the cmd subject for deploying an app to nodeID.
func AppDeploySubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.deploy")
}

// AppStopSubject is the cmd subject for stopping an app on nodeID.
func AppStopSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.stop")
}

// AppPullSubject is the cmd subject for pulling an app's images on nodeID
// without deploying them (#411).
func AppPullSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.pull")
}

// AppStatusSubject is the cmd subject for fetching app status from nodeID.
func AppStatusSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.status")
}

// AppVolumesListSubject is the cmd subject for enumerating the Rasputin-managed
// compose volumes on nodeID (read-only).
func AppVolumesListSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.volumes.list")
}

// AppVolumesRemoveSubject is the cmd subject for removing orphaned
// Rasputin-managed compose volumes on nodeID by exact name.
func AppVolumesRemoveSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.volumes.remove")
}

// AppVolumesCheckSubject is the cmd subject for asking nodeID which of an
// app's named volumes a compose would leave undeclared (#412; read-only).
func AppVolumesCheckSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.volumes.check")
}

// AppVolumesDropSubject is the cmd subject for removing, by exact name, named
// volumes of a LIVE app that its compose on nodeID no longer declares (#412).
func AppVolumesDropSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "docker.volumes.drop")
}

// AppChangeSubject is the publish subject for an app-lifecycle event.
func AppChangeSubject(appID string, change AppChangeType) string {
	return fmt.Sprintf("rasputin.apps.%s.%s", appID, string(change))
}

// AllAppsFilter matches every app change event. Used by the UI WebSocket
// bridge.
const AllAppsFilter = "rasputin.apps.>"

// --- Rasputin-managed volume names -----------------------------------------
//
// Every app's compose project is named rasp_<appID> (agent/internal/docker
// projectName), so compose names each of its volumes rasp_<appID>_<volume>.
// Both the api and the agent read that shape, and they read it from HERE so
// they cannot disagree about it: the api uses it to decide which volumes have
// no owner in the apps ledger, and the agent uses it to refuse to touch
// anything else.

// AppVolumePrefix is the prefix every Rasputin-managed compose volume carries.
const AppVolumePrefix = "rasp_"

// appIDLen is the length of a ULID, which is what every app id is
// (api/internal/api/apps_handlers.go mints them with ulid.Make).
const appIDLen = 26

// AppProjectName is the compose project name for appID: rasp_<appid>, lower-
// cased because that is what the agent hands `docker compose -p`.
func AppProjectName(appID string) string {
	return AppVolumePrefix + strings.ToLower(appID)
}

// AppVolumeName is the docker volume name compose gives volume `volume` of the
// app appID's project.
func AppVolumeName(appID, volume string) string {
	return AppProjectName(appID) + "_" + volume
}

// ParseAppVolumeName splits a docker volume name of the shape
// rasp_<ulid>_<volume> into its app id (upper-cased, as the ledger stores it)
// and its compose volume name. ok is false for anything else: a name outside
// the prefix, a project segment that is not a 26-character ULID, or an empty
// volume segment. It is the whole of the name check the remove verb applies,
// so it is deliberately strict — a ULID is Crockford base32, and nothing in
// that alphabet is an underscore, so the first underscore after the prefix is
// unambiguous.
func ParseAppVolumeName(name string) (appID, volume string, ok bool) {
	if !strings.HasPrefix(name, AppVolumePrefix) {
		return "", "", false
	}
	rest := name[len(AppVolumePrefix):]
	if len(rest) < appIDLen+2 || rest[appIDLen] != '_' {
		return "", "", false
	}
	id := rest[:appIDLen]
	if !ValidAppID(id) {
		return "", "", false
	}
	volume = rest[appIDLen+1:]
	if volume == "" {
		return "", "", false
	}
	return strings.ToUpper(id), volume, true
}

// ValidAppID reports whether id is shaped like an app id: a 26-character
// ULID in Crockford base32, either case. The agent uses it before it trusts a
// directory name under its state root as the owner of a volume.
func ValidAppID(id string) bool {
	if len(id) != appIDLen {
		return false
	}
	for _, r := range id {
		if !isCrockford(r) {
			return false
		}
	}
	return true
}

// anonymousVolumeNameLen is the length of the name docker gives a volume it
// creates for an unnamed mount: 64 lower-case hex characters.
const anonymousVolumeNameLen = 64

// IsAnonymousVolumeName reports whether name has the shape of a volume docker
// created for an unnamed mount — a service's `- /path`, or an image's
// Dockerfile VOLUME that the compose maps nothing to
// (geekdojo/geekdojo-brain#413).
//
// The shape is only a shape. It says nothing about which app, if any, the
// volume belongs to: docker labels such a volume com.docker.volume.anonymous
// and nothing else, so it carries no compose project label to check. Ownership
// comes from the agent's per-app record of the volumes an app's containers
// mounted, and every gate that removes one resolves it there. A name of this
// shape can never start with `-`, which keeps it an operand on any argv.
func IsAnonymousVolumeName(name string) bool {
	if len(name) != anonymousVolumeNameLen {
		return false
	}
	for _, r := range name {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// isCrockford reports whether r is in ULID's Crockford base32 alphabet, either
// case (compose lower-cases the project name; the ledger holds upper).
func isCrockford(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return true
	case r >= 'a' && r <= 'z':
		r -= 'a' - 'A'
	}
	if r < 'A' || r > 'Z' {
		return false
	}
	// Crockford excludes I, L, O and U.
	return r != 'I' && r != 'L' && r != 'O' && r != 'U'
}

// AppVolumeInfo is one Rasputin-managed volume as the agent sees it: a named
// compose volume, or an anonymous volume the agent recorded one of an app's
// containers mounting (Anonymous).
type AppVolumeInfo struct {
	// Name is the docker volume name: rasp_<appid>_<volume> for a named
	// volume, docker's 64-hex id for an anonymous one. It is the exact name
	// the remove verb takes.
	Name string `json:"name"`
	// AppID is the owning app, upper-cased to match the ledger: parsed out of
	// Name for a named volume, taken from the agent's per-app record for an
	// anonymous one.
	AppID string `json:"appId"`
	// Volume is the compose volume name parsed out of Name — what the tile
	// declares and what the backup manifest records. Empty for an anonymous
	// volume, which has no compose name.
	Volume string `json:"volume"`
	// Anonymous marks a volume docker created for an unnamed mount. It has
	// no project label, so it is listed only because the agent recorded one
	// of this app's containers mounting it (geekdojo/geekdojo-brain#413).
	Anonymous bool `json:"anonymous,omitempty"`
	// Service and Path say where an anonymous volume was mounted when the
	// agent recorded it — the compose service and the path inside its
	// container — which is the only description such a volume has.
	Service string `json:"service,omitempty"`
	Path    string `json:"path,omitempty"`
	// SizeBytes is the sum of the volume's file sizes on the node's disk.
	SizeBytes uint64 `json:"sizeBytes"`
	// CreatedAt is docker's creation timestamp for the volume.
	CreatedAt time.Time `json:"createdAt"`
	// InUse says at least one container (running or not) references the
	// volume. An in-use volume is never removed.
	InUse bool `json:"inUse"`
}

// AppVolumesListCmd is the request body on docker.volumes.list.
type AppVolumesListCmd struct {
	// SkipSizes leaves SizeBytes zero instead of walking every volume's
	// files. The api sets it when it lists only to resolve which app owns an
	// anonymous volume before a reclaim; a sizing walk of a large bulk volume
	// is the slow part of a listing and answers nothing that check needs. An
	// agent older than the field ignores it and sizes anyway.
	SkipSizes bool `json:"skipSizes,omitempty"`
}

// AppVolumesListAck is the reply: every volume on the node whose name parses
// as rasp_<ulid>_<volume> AND that docker labels as belonging to that compose
// project, plus every anonymous volume exactly one app's record on the node
// names and docker still labels anonymous. Nothing else is listed — the api,
// not the agent, knows which of these still have an owner.
type AppVolumesListAck struct {
	OK      bool            `json:"ok"`
	Detail  string          `json:"detail,omitempty"`
	Volumes []AppVolumeInfo `json:"volumes"`
}

// AppVolumesRemoveCmd is the request body on docker.volumes.remove.
type AppVolumesRemoveCmd struct {
	// Names is the exact volume names to remove. Each must parse as
	// rasp_<ulid>_<volume>, or be an anonymous volume's 64-hex name that the
	// agent's per-app record attributes to exactly one app; anything else is
	// refused by name, not skipped.
	Names []string `json:"names"`
	// LiveAppIDs is every app id the api's ledger currently holds. The agent
	// refuses any name whose app id appears here — a live app's volume must be
	// unreachable through this verb even if the api that called it is wrong.
	// The api also refuses before sending; this is the second, independent
	// gate.
	LiveAppIDs []string `json:"liveAppIds"`
}

// AppVolumeRefusal is one name the remove verb declined, with the reason.
type AppVolumeRefusal struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// AppVolumesRemoveAck is the reply. A refused name is never an error: the
// removed and refused lists together account for every name in the command.
type AppVolumesRemoveAck struct {
	OK      bool               `json:"ok"`
	Detail  string             `json:"detail,omitempty"`
	Removed []string           `json:"removed"`
	Refused []AppVolumeRefusal `json:"refused"`
}

// RefuseAppVolumeName applies the two rules that need no daemon — the name shape
// and the ledger — and returns the refusal reason, or "" when the name may go
// on to the docker-side checks. Exported because the api applies exactly the
// same two rules before it sends a remove command, and the wording should
// match wherever an operator meets it.
func RefuseAppVolumeName(name string, liveAppIDs map[string]bool) string {
	if !strings.HasPrefix(name, AppVolumePrefix) {
		return fmt.Sprintf("not a Rasputin-managed volume: the name does not start with %q", AppVolumePrefix)
	}
	appID, _, ok := ParseAppVolumeName(name)
	if !ok {
		return "not a Rasputin-managed volume: the name is not of the form rasp_<app-id>_<volume>"
	}
	return RefuseAppVolumeOwner(appID, liveAppIDs)
}

// RefuseAppVolumeOwner is the ledger rule on its own: the refusal reason when
// appID still has a row, "" otherwise. RefuseAppVolumeName applies it to the
// app id a named volume carries; an anonymous volume carries none, so its
// owner is resolved from the agent's record first and then checked here, in
// the same words.
func RefuseAppVolumeOwner(appID string, liveAppIDs map[string]bool) string {
	if liveAppIDs[strings.ToUpper(appID)] {
		return fmt.Sprintf("app %s is still installed; uninstall it to delete its volumes", strings.ToUpper(appID))
	}
	return ""
}

// --- Volumes a compose change would drop (geekdojo/geekdojo-brain#412) -------
//
// Renaming a volume key, or dropping the service that mounted it, makes `up`
// exit 0 and leave the old named volume on the node with nothing mounting it:
// the app starts empty and its data is orphaned (measured case 3,
// app-catalog.md §8a.2). So every compose change first asks the node which of
// the app's named volumes on disk the new compose does not declare, and is
// refused unless the owner names exactly those volumes for deletion — which
// then happens only after `up` has succeeded.
//
// The api holds no YAML parser (ADR-0006 D4), so it is Compose on the node
// that says what a compose declares: `docker compose config --volumes` over
// the staged compose, under the app's project. Anonymous volumes are outside
// this gate: they have no key to compare, and #413 already records every one
// an app's containers mount and removes them with the app's data.

// AppVolumesCheckWork is how long the agent may spend on a volumes check — a
// `compose config` and a `volume ls`, neither of which touches a registry.
// AppVolumesCheckRPC is the api's wait, the longer of the pair for the same
// reason AppDeployRPC is.
const (
	AppVolumesCheckWork = 15 * time.Second
	AppVolumesCheckRPC  = AppVolumesCheckWork + 5*time.Second
)

// AppVolumesCheckCmd is the request body on docker.volumes.check: which named
// volumes of AppID's project, on this node, does ComposeYAML not declare?
// Read-only: the compose is staged beside the app's live one and removed
// again, and nothing is created, pulled or removed.
type AppVolumesCheckCmd struct {
	AppID       string `json:"appId"`
	ComposeYAML string `json:"composeYaml"`
}

// AppDroppedVolume is one named volume the app has on disk that a compose
// does not declare.
type AppDroppedVolume struct {
	// Name is the docker volume name, rasp_<appid>_<volume> — the exact name
	// an owner puts in deleteVolumes.
	Name string `json:"name"`
	// Volume is the compose key the volume was declared under.
	Volume string `json:"volume"`
}

// AppVolumesCheckAck is the reply. Declared is the compose's volume keys as
// Compose itself resolved them — only volumes some active service mounts,
// which is exactly the set `up` creates and keeps. Dropped is every named
// volume labelled for the app's project whose key is not among them, sorted
// by name.
type AppVolumesCheckAck struct {
	OK       bool               `json:"ok"`
	Detail   string             `json:"detail,omitempty"`
	Declared []string           `json:"declared"`
	Dropped  []AppDroppedVolume `json:"dropped"`
}

// AppVolumesDropCmd is the request body on docker.volumes.drop: remove these
// named volumes of AppID, which is still installed. Sent only by a compose
// change's saga, only after its `up` succeeded, and only with the names the
// owner put in deleteVolumes and the check confirmed the change drops. The
// agent refuses, by name, anything that is not a volume of AppID's project,
// anything the app's compose on disk still declares, and anything a container
// still references. The reply is an AppVolumesRemoveAck.
type AppVolumesDropCmd struct {
	AppID string   `json:"appId"`
	Names []string `json:"names"`
}

// RefuseAppDeleteVolumeName is the daemon-free half of the rule for a name an
// owner puts in a compose change's deleteVolumes: it must be a named volume of
// appID's own project, rasp_<appid>_<volume>. An anonymous volume's 64-hex
// name is refused by name: anonymous volumes are outside the dropped-volume
// gate (#413 removes them with the app's data). Returns "" for an acceptable
// name. The api applies it before a job exists, the saga to its spec, and the
// agent again before it removes anything, so the wording is one.
func RefuseAppDeleteVolumeName(appID, name string) string {
	if IsAnonymousVolumeName(name) {
		return "an anonymous volume cannot be named for deletion with a compose change: it has no compose key to drop, and it is removed with the app's data when the app is deleted"
	}
	owner, _, ok := ParseAppVolumeName(name)
	if !ok {
		return "not a named volume of this app: the name is not of the form " + AppProjectName(appID) + "_<volume>"
	}
	if !strings.EqualFold(owner, appID) {
		return fmt.Sprintf("a volume of app %s, not of this app (%s)", owner, strings.ToUpper(appID))
	}
	return ""
}
