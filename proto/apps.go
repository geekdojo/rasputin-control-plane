package proto

import (
	"fmt"
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

// AppDeployCmd is the request body on rasputin.node.<id>.cmd.docker.deploy.
// The agent writes the compose file to its app state directory and runs
// `docker compose up -d` (or the mock-backend equivalent).
type AppDeployCmd struct {
	AppID       string `json:"appId"`
	Name        string `json:"name"`
	ComposeYAML string `json:"composeYaml"`
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
	// TailnetFQDN / LANFQDN are the app's proxy Host names — the same names in
	// the leaf's SANs (both from mesh.AppLeafDNSNames), so the Caddy route host
	// matches the cert by construction. LANFQDN is "" for a tailnet-only app.
	TailnetFQDN string `json:"tailnetFqdn,omitempty"`
	LANFQDN     string `json:"lanFqdn,omitempty"`
	// UpstreamPort is the app's loopback port the node-local Caddy proxies to.
	UpstreamPort int `json:"upstreamPort,omitempty"`
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

// AppChangeSubject is the publish subject for an app-lifecycle event.
func AppChangeSubject(appID string, change AppChangeType) string {
	return fmt.Sprintf("rasputin.apps.%s.%s", appID, string(change))
}

// AllAppsFilter matches every app change event. Used by the UI WebSocket
// bridge.
const AllAppsFilter = "rasputin.apps.>"
