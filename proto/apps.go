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

// AppStopCmd is sent on rasputin.node.<id>.cmd.docker.stop.
type AppStopCmd struct {
	AppID string `json:"appId"`
	// DeleteVolumes asks the agent to run `compose down -v` rather than
	// `compose down`: the project's named volumes go with its containers.
	//
	// Set ONLY by the app.delete saga, and only when the operator answered
	// "Delete volumes?" with a deliberate yes (geekdojo/geekdojo-brain#399).
	// Absent is false, which is what an api older than this field sends and
	// what an operator who did not tick the box sends — destroying data is
	// never the default. `compose down -v` is scoped to the compose project,
	// which is the property that makes this safe: it can only remove volumes
	// named rasp_<appID>_*, never another app's and never a volume by name.
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
	for _, r := range id {
		if !isCrockford(r) {
			return "", "", false
		}
	}
	volume = rest[appIDLen+1:]
	if volume == "" {
		return "", "", false
	}
	return strings.ToUpper(id), volume, true
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

// AppVolumeInfo is one Rasputin-managed compose volume as the agent sees it.
type AppVolumeInfo struct {
	// Name is the docker volume name, rasp_<appid>_<volume>.
	Name string `json:"name"`
	// AppID is the ULID parsed out of Name, upper-cased to match the ledger.
	AppID string `json:"appId"`
	// Volume is the compose volume name parsed out of Name — what the tile
	// declares and what the backup manifest records.
	Volume string `json:"volume"`
	// SizeBytes is the sum of the volume's file sizes on the node's disk.
	SizeBytes uint64 `json:"sizeBytes"`
	// CreatedAt is docker's creation timestamp for the volume.
	CreatedAt time.Time `json:"createdAt"`
	// InUse says at least one container (running or not) references the
	// volume. An in-use volume is never removed.
	InUse bool `json:"inUse"`
}

// AppVolumesListCmd is the (empty) request body on docker.volumes.list.
type AppVolumesListCmd struct{}

// AppVolumesListAck is the reply: every volume on the node whose name parses
// as rasp_<ulid>_<volume> AND that docker labels as belonging to that compose
// project. Nothing else is listed — the api, not the agent, knows which of
// these still have an owner.
type AppVolumesListAck struct {
	OK      bool            `json:"ok"`
	Detail  string          `json:"detail,omitempty"`
	Volumes []AppVolumeInfo `json:"volumes"`
}

// AppVolumesRemoveCmd is the request body on docker.volumes.remove.
type AppVolumesRemoveCmd struct {
	// Names is the exact volume names to remove. Each must parse as
	// rasp_<ulid>_<volume>; anything else is refused by name, not skipped.
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
	if liveAppIDs[strings.ToUpper(appID)] {
		return fmt.Sprintf("app %s is still installed; uninstall it to delete its volumes", appID)
	}
	return ""
}
