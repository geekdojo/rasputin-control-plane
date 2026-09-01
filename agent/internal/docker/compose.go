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
// root; the docker CLI is assumed to be on PATH (the caller LookPaths first,
// and DISABLES the subsystem if it isn't there — it does not fall back to the
// mock; see agent/internal/configfault).
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
	status, services, err := c.statusLocked(ctx, appID)
	if err != nil {
		return status, err.Error(), err
	}
	if status != proto.AppStatusRunning {
		// `up` returned 0 and we still aren't running, so compose has no
		// complaint to quote and the per-service state is the only evidence
		// there is. Returning "" here — which is what this did — is how a
		// failed deploy reached the operator as a bare FAILED with no reason
		// attached anywhere in the UI.
		return status, deployDetail(status, services), nil
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
	// ExitCode is a pointer so a payload that never carried the key stays
	// distinguishable from one that carried a 0 — see proto.AppServiceStatus.
	// Compose emits it unconditionally (v5.0.1 checked), but the parser also
	// eats hand-rolled and older output, and guessing 0 there would invent a
	// clean exit out of nothing.
	ExitCode *int `json:"ExitCode,omitempty"`
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
		Name:     p.Service,
		State:    p.State,
		Health:   p.Health,
		ExitCode: p.ExitCode,
	}
}

// serviceOutcome is what aggregateStatus makes of one container. It exists so
// the "state and exit code are one fact" rule lives in exactly one place —
// every caller that wants to know whether a container is a problem asks here
// rather than re-deriving it from the two fields and getting it subtly wrong.
type serviceOutcome int

const (
	outcomeRunning   serviceOutcome = iota // up right now
	outcomeCompleted                       // exited, and exited 0 — a finished one-shot
	outcomeBroken                          // exited non-zero, exit code unknown, dead, removing
	outcomeTransient                       // created, restarting, paused — still settling
)

func classifyService(s proto.AppServiceStatus) serviceOutcome {
	switch strings.ToLower(s.State) {
	case "running":
		return outcomeRunning
	case "dead", "removing":
		return outcomeBroken
	case "exited":
		// nil is "we were not told", not "zero". An agent that predates the
		// field, or any producer that omits it, leaves us unable to prove the
		// container finished cleanly — and an unprovable clean exit is treated
		// as a failure, which is exactly the behaviour this code had before
		// exit codes existed. Only an explicit 0 buys the benefit of the doubt.
		if s.ExitCode != nil && *s.ExitCode == 0 {
			return outcomeCompleted
		}
		return outcomeBroken
	default:
		return outcomeTransient
	}
}

// aggregateStatus rolls up service-level state into the app-level enum.
//
// The rule, and why each arm is what it is:
//
//   - any broken service (exited non-zero, exited with an exit code we were
//     never told, `dead`, `removing`) → failed. Failure wins over everything
//     else: a stack with a crashed container is a broken app no matter how
//     many of its siblings are happily up.
//   - otherwise, any transient service (`created`, `restarting`, `paused`) →
//     deploying. Unchanged: the stack is still settling and calling it either
//     way would be premature.
//   - otherwise, at least one service running → running. This is the arm that
//     fixes the bug. A finished one-shot is not a fault, it is the entire
//     point of a one-shot: compose ships
//     `depends_on: {condition: service_completed_successfully}` precisely
//     because a container that exits 0 is a normal, successful outcome.
//     Before this, `case "exited": return failed` fired on sight of any exited
//     container regardless of exit code, so every tile with an init container
//     failed 100% of the time — reproduced twice on e3bench (2026-08-24, OS
//     dev.179 / CP dev.124), where the v11 home-assistant tile's
//     `home-assistant-config-seed` writes configuration.yaml, exits 0, and
//     took the whole deploy down with it in 1 second flat against a 300s
//     budget.
//   - otherwise (every service completed cleanly, or there are none at all) →
//     stopped. NOT running: nothing is serving, and claiming otherwise would
//     put a green row on the Apps page for an app with no process behind it —
//     which the reconcile sweep would then act on by minting a TLS leaf and a
//     proxy route pointing at nothing. NOT failed either: exiting 0 is what
//     these containers were asked to do. `stopped` is also what statusLocked
//     already returns when compose reports no containers at all, and the two
//     cases are the same fact to an operator — nothing is up. It matters
//     beyond the degenerate all-one-shots stack: `docker compose stop` (as
//     opposed to the `down` our Stop uses) leaves containers behind as
//     exited-0, so an app stopped from the docker CLI must keep reading as
//     stopped rather than flipping to running.
func aggregateStatus(services []proto.AppServiceStatus) proto.AppStatus {
	var running, transient int
	for _, s := range services {
		switch classifyService(s) {
		case outcomeBroken:
			return proto.AppStatusFailed
		case outcomeRunning:
			running++
		case outcomeTransient:
			transient++
		case outcomeCompleted:
			// A finished one-shot neither helps nor hurts the rollup; it only
			// matters if it turns out to be the ONLY thing in the stack.
		}
	}
	if transient > 0 {
		return proto.AppStatusDeploying
	}
	if running > 0 {
		return proto.AppStatusRunning
	}
	return proto.AppStatusStopped
}

// deployDetail explains a deploy that did not come back `running`.
//
// It exists because Deploy used to return an empty string for every
// non-running outcome, and empty detail is invisible: the api swaps it for the
// generic "agent reported deploy failed", and the app drawer renders its
// failure block only when lastDetail is non-empty, so a failed home-assistant
// deploy showed the operator a bare FAILED chip and literally nothing else.
//
// The offending services come FIRST because the Apps table clips this to ~36
// chars for its tooltip — the head is the only part most readers ever see, so
// it has to carry the name and the verdict, not a preamble. The full string
// stays useful in the drawer.
func deployDetail(status proto.AppStatus, services []proto.AppServiceStatus) string {
	if len(services) == 0 {
		return fmt.Sprintf("app is %s: compose ps reported no containers", status)
	}
	var notable []string
	running := 0
	for _, s := range services {
		name := s.Name
		if name == "" {
			name = "(unnamed service)"
		}
		switch classifyService(s) {
		case outcomeRunning:
			running++
			continue
		case outcomeCompleted:
			notable = append(notable, name+" completed (exit 0)")
		case outcomeBroken:
			switch {
			case !strings.EqualFold(s.State, "exited"):
				notable = append(notable, fmt.Sprintf("%s %s", name, strings.ToLower(s.State)))
			case s.ExitCode == nil:
				// Worth spelling out: this is the agent saying it cannot tell
				// a clean finish from a crash, not a container that reported
				// no status.
				notable = append(notable, name+" exited (exit code unknown)")
			default:
				notable = append(notable, fmt.Sprintf("%s exited (code %d)", name, *s.ExitCode))
			}
		default:
			notable = append(notable, fmt.Sprintf("%s %s", name, strings.ToLower(s.State)))
		}
	}
	summary := fmt.Sprintf("app is %s (%d/%d services running)", status, running, len(services))
	if len(notable) == 0 {
		return summary
	}
	return strings.Join(notable, ", ") + " — " + summary
}
