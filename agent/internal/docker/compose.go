package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ComposeBackend shells out to `docker compose` for real container lifecycle.
// State files live at <dir>/<appID>/docker-compose.yml; the compose project
// name is rasp_<appID> so projects don't collide with any other compose
// stacks the user is running.
type ComposeBackend struct {
	mu  sync.Mutex
	dir string
}

// NewComposeBackend constructs the real backend. dir is the per-agent state
// root; the docker CLI is assumed to be on PATH (the caller should LookPath
// first and fall back to the mock if it isn't).
func NewComposeBackend(dir string) (*ComposeBackend, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("docker-compose: mkdir: %w", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker-compose: docker CLI not found: %w", err)
	}
	return &ComposeBackend{dir: dir}, nil
}

func (c *ComposeBackend) Name() string { return "docker" }

func (c *ComposeBackend) appDir(appID string) string {
	return filepath.Join(c.dir, appID)
}

func (c *ComposeBackend) composePath(appID string) string {
	return filepath.Join(c.appDir(appID), "docker-compose.yml")
}

// projectName is what `docker compose -p` sees. Prefixed so we can identify
// (and clean up) Rasputin-managed projects. App IDs are ULIDs so they're
// safe in shell args.
func projectName(appID string) string {
	return "rasp_" + strings.ToLower(appID)
}

func (c *ComposeBackend) Deploy(ctx context.Context, appID, name, composeYAML string) (proto.AppStatus, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(c.appDir(appID), 0o755); err != nil {
		return proto.AppStatusFailed, "mkdir: " + err.Error(), err
	}
	if err := os.WriteFile(c.composePath(appID), []byte(composeYAML), 0o644); err != nil {
		return proto.AppStatusFailed, "write compose: " + err.Error(), err
	}

	out, err := c.run(ctx, appID, composeUpArgs()...)
	if err != nil {
		return proto.AppStatusFailed, formatCmdErr("docker compose up", out, err), err
	}
	status, _, err := c.statusLocked(ctx, appID)
	if err != nil {
		return status, err.Error(), err
	}
	return status, "", nil
}

func (c *ComposeBackend) Stop(ctx context.Context, appID string) (proto.AppStatus, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := os.Stat(c.composePath(appID)); errors.Is(err, os.ErrNotExist) {
		return proto.AppStatusStopped, "no compose file on disk", nil
	}
	out, err := c.run(ctx, appID, "down")
	if err != nil {
		return proto.AppStatusFailed, formatCmdErr("docker compose down", out, err), err
	}
	return proto.AppStatusStopped, "", nil
}

func (c *ComposeBackend) Status(ctx context.Context, appID string) (proto.AppStatus, []proto.AppServiceStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked(ctx, appID)
}

func (c *ComposeBackend) statusLocked(ctx context.Context, appID string) (proto.AppStatus, []proto.AppServiceStatus, error) {
	if _, err := os.Stat(c.composePath(appID)); errors.Is(err, os.ErrNotExist) {
		return proto.AppStatusStopped, nil, nil
	}
	out, err := c.run(ctx, appID, "ps", "--format", "json", "--all")
	if err != nil {
		return proto.AppStatusUnknown, nil, fmt.Errorf("docker compose ps: %w", err)
	}
	services, err := parsePsOutput(out)
	if err != nil {
		return proto.AppStatusUnknown, nil, err
	}
	if len(services) == 0 {
		return proto.AppStatusStopped, nil, nil
	}
	return aggregateStatus(services), services, nil
}

// run executes `docker compose -f <path> -p <project> <args...>` and returns
// combined stdout+stderr. ctx is honored — if it cancels, the command is
// killed.
func (c *ComposeBackend) run(ctx context.Context, appID string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", composeArgs(c.composePath(appID), projectName(appID), args...)...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// composeArgs builds the docker CLI arg vector for one compose invocation.
// It exists so the flags are assertable in a test — run() shells out through
// exec.CommandContext, which nothing can inspect.
func composeArgs(composePath, project string, args ...string) []string {
	return append([]string{"compose", "-f", composePath, "-p", project}, args...)
}

// composeUpArgs is the `up` invocation Deploy uses.
//
// --quiet-pull is load-bearing, not cosmetic. Compose streams one progress line
// per layer per state ("Pulling fs layer", "Downloading", "Extracting"), which
// for a multi-container tile buries the daemon's actual verdict under dozens of
// lines of noise. It is an `up` flag rather than the root `--progress quiet`
// deliberately: the root flag also mutes error output, which is the one thing
// we need to survive. Available since compose v2.0; the appliance already
// requires >= v2.23.1 for inline `configs` content (see the obs collector
// template), so there is no version floor to worry about here.
func composeUpArgs() []string {
	return []string{"up", "-d", "--remove-orphans", "--quiet-pull"}
}

// maxDetailBytes caps the compose output we attach to a failed task. Nothing
// downstream actually constrains this: the bus sets no MaxPayload (nats-server
// defaults to 1 MiB), apps.last_detail is a SQLite TEXT column, and the Tasks
// page renders the string in a pre-wrap <pre>. The Apps drawer clips its
// one-line summary to 36 chars client-side, which is where "keep it readable"
// belongs — not here, where clipping destroys the evidence.
const maxDetailBytes = 4096

func formatCmdErr(label string, out []byte, err error) string {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return fmt.Sprintf("%s: %v", label, err)
	}
	return fmt.Sprintf("%s: %v — %s", label, err, truncateDetail(trimmed))
}

// truncateDetail keeps the TAIL of s, not the head.
//
// Compose writes progress first and the real failure last, so a head-keeping
// cap kept exactly the wrong half. On the bench (2026-08-23, e3bench) a failed
// pi-hole deploy surfaced as `docker compose up: exit status 1` followed by ~17
// lines of per-layer pull progress and nothing else; the tile was pulled from
// the catalog undiagnosed because the daemon's message had been cut off. The
// last line is always the one worth reading.
func truncateDetail(s string) string {
	if len(s) <= maxDetailBytes {
		return s
	}
	// "…\n" so the truncation marker is visible and sits on its own line.
	const marker = "…\n"
	start := len(s) - (maxDetailBytes - len(marker))
	// Compose writes one status per line. Resuming mid-line reads like
	// corruption, so land on a line boundary whenever one is in budget.
	if s[start-1] == '\n' {
		return marker + s[start:]
	}
	if i := strings.IndexByte(s[start:], '\n'); i >= 0 {
		return marker + s[start+i+1:]
	}
	// One enormous line with no boundary to land on — back up to the next rune
	// start so we never hand the UI half of a UTF-8 sequence.
	cut := s[start:]
	for len(cut) > 0 && cut[0]&0xC0 == 0x80 {
		cut = cut[1:]
	}
	return "…" + cut
}

// composePsLine is the shape `docker compose ps --format json` emits, one
// per line. Field names match v2+ output.
type composePsLine struct {
	Name    string `json:"Name"`
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health,omitempty"`
}

func parsePsOutput(out []byte) ([]proto.AppServiceStatus, error) {
	services := []proto.AppServiceStatus{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Older docker CLI versions emit a JSON array instead of NDJSON.
		// Handle both.
		if line[0] == '[' {
			var batch []composePsLine
			if err := json.Unmarshal(line, &batch); err != nil {
				return nil, fmt.Errorf("parse compose ps array: %w", err)
			}
			for _, p := range batch {
				services = append(services, toServiceStatus(p))
			}
			continue
		}
		var p composePsLine
		if err := json.Unmarshal(line, &p); err != nil {
			return nil, fmt.Errorf("parse compose ps line: %w", err)
		}
		services = append(services, toServiceStatus(p))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return services, nil
}

func toServiceStatus(p composePsLine) proto.AppServiceStatus {
	return proto.AppServiceStatus{
		Name:   p.Service,
		State:  p.State,
		Health: p.Health,
	}
}

// aggregateStatus rolls up service-level state into the app-level enum. We
// report `running` only when every service is running; any failure flips us
// to `failed`; everything else is `deploying` (transient states like
// `created`, `restarting`).
func aggregateStatus(services []proto.AppServiceStatus) proto.AppStatus {
	allRunning := true
	for _, s := range services {
		switch strings.ToLower(s.State) {
		case "exited", "dead", "removing":
			return proto.AppStatusFailed
		case "running":
			// continue
		default:
			allRunning = false
		}
	}
	if allRunning {
		return proto.AppStatusRunning
	}
	return proto.AppStatusDeploying
}
