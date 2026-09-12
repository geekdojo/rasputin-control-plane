package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	// exec and sizeOf are the docker CLI and the volume sizer the orphan-volume
	// verbs (volumes.go) use. nil means the real ones; tests inject fakes so
	// the refusal rules can be exercised without a daemon.
	exec   dockerExec
	sizeOf func(mountpoint string) (uint64, error)
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
	if !safeAppID(appID) {
		err := fmt.Errorf("refusing app id %q: not a single path element", appID)
		return proto.AppStatusFailed, err.Error(), err
	}
	if err := os.MkdirAll(c.appDir(appID), 0o755); err != nil {
		return proto.AppStatusFailed, "mkdir: " + err.Error(), err
	}
	// Record the anonymous volumes of the containers `up` may be about to
	// replace or remove (#413; see appvolumes.go). An `up --remove-orphans`
	// that drops a service takes the only container that named its anonymous
	// volume with it, and an app an older agent deployed has no record yet.
	c.recordVolumesOrLog(ctx, appID, "docker.deploy")
	if err := os.WriteFile(c.composePath(appID), []byte(composeYAML), 0o644); err != nil {
		return proto.AppStatusFailed, "write compose: " + err.Error(), err
	}

	out, err := c.run(ctx, appID, composeUpArgs()...)
	// And the ones the containers `up` left mount now — whether or not `up`
	// succeeded, since a failed `up` can still have created some of them.
	c.recordVolumesOrLog(ctx, appID, "docker.deploy")
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

// stagedPullPattern names the throwaway compose file Pull hands `compose pull`.
// A dotfile so nobody reading an app's state directory mistakes it for the
// app's compose, and never docker-compose.yml, which is the one name Pull must
// not write.
const stagedPullPattern = ".pull-*.docker-compose.yml"

// Pull fetches every image composeYAML names, under appID's compose project,
// and changes nothing else on the node (geekdojo/geekdojo-brain#411).
//
// The compose is STAGED — written to a temporary file of its own and removed
// again — and the app's live docker-compose.yml is never opened. That is the
// whole point of the verb. Stop runs `down` against the live file and Status
// runs `ps` against it, so if a pull that fails has already replaced it, the
// node is left describing a compose it is not running. Deploy cannot offer
// this: it must write the file before `up`, so a pull that fails inside `up`
// fails after the file has moved.
//
// The staged file sits in the app's own directory, beside the live one,
// because compose takes the project directory from the first -f file: `.env`
// interpolation and relative paths then resolve exactly as they will when the
// same compose is deployed. The directory is created if the app has none yet;
// an empty directory is not state — Status and Stop key on the compose file.
//
// `pull` creates no container, network or volume, so the running app is not
// touched whether the pull succeeds or not (measured, case 7 of
// app-catalog.md §8a.2, and pinned by the docker-tagged test).
//
// c.mu is deliberately NOT held. It serialises every app on the node, and a
// pull can take the app's whole deploy budget — minutes — during which every
// other app's status and stop would queue behind it. Nothing Pull does needs
// it: the staged file's name is unique, and the image store is the daemon's.
func (c *ComposeBackend) Pull(ctx context.Context, appID, composeYAML string) (string, error) {
	if !safeAppID(appID) {
		err := fmt.Errorf("refusing app id %q: not a single path element", appID)
		return err.Error(), err
	}
	if err := os.MkdirAll(c.appDir(appID), 0o755); err != nil {
		return "mkdir: " + err.Error(), err
	}
	staged, err := os.CreateTemp(c.appDir(appID), stagedPullPattern)
	if err != nil {
		return "stage compose: " + err.Error(), err
	}
	defer func() { _ = os.Remove(staged.Name()) }()
	if _, err := staged.WriteString(composeYAML); err != nil {
		_ = staged.Close()
		return "stage compose: " + err.Error(), err
	}
	if err := staged.Close(); err != nil {
		return "stage compose: " + err.Error(), err
	}
	out, err := c.dockerFor()(ctx, composeArgs(staged.Name(), projectName(appID), composePullArgs()...)...)
	if err != nil {
		return formatCmdErr("docker compose pull", out, err), err
	}
	return "", nil
}

// safeAppID reports whether appID can name a directory under the state root:
// one path element, never "." or "..". Pull creates a file under it, and the
// id arrives on the bus.
func safeAppID(appID string) bool {
	return appID != "" && appID != "." && appID != ".." && filepath.Base(appID) == appID &&
		!strings.ContainsAny(appID, `/\`)
}

// composePullArgs is the `pull` invocation Pull uses. Each flag makes the pull
// establish what `up` will then need, and nothing `up` would not do:
//
//   - --policy missing: an image already on the node is not fetched again.
//     That is `up`'s own default for a service with no pull_policy, and it is
//     what lets re-applying a compose whose images are still cached succeed
//     with the registry unreachable — the owner's way back must not depend on
//     the registry. Digest-pinned references count as present when the digest
//     is (checked against compose v5.0.1). It overrides a service's own
//     pull_policy, so a service that says `always` is still pulled again by
//     `up`, and a failure there lands in the after-pull branch — the
//     conservative one, where nothing is reverted automatically.
//   - --ignore-buildable: a service `up` would build is not pulled, so a
//     custom compose with a build section does not fail a pull `up` would
//     never have attempted.
//   - --quiet: no per-layer progress. Unlike the root `--progress quiet` it
//     keeps the daemon's error, the one line worth reading (checked: a bad
//     digest's "not found" survives it).
//
// All three exist in compose v2.32.4, the version Buildroot 2025.02.17
// packages, as well as in v5.0.1.
func composePullArgs() []string {
	return []string{"pull", "--quiet", "--policy", "missing", "--ignore-buildable"}
}

func (c *ComposeBackend) Stop(ctx context.Context, appID string, deleteVolumes bool) (proto.AppStatus, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !safeAppID(appID) {
		// The id names a directory this verb can now remove.
		err := fmt.Errorf("refusing app id %q: not a single path element", appID)
		return proto.AppStatusFailed, err.Error(), err
	}
	_, statErr := os.Stat(c.composePath(appID))
	composeMissing := errors.Is(statErr, os.ErrNotExist)
	switch {
	case composeMissing && !deleteVolumes:
		return proto.AppStatusStopped, "no compose file on disk", nil
	case !composeMissing:
		// `down` removes the containers, and with them the only link between
		// the app and its anonymous volumes. This is the last moment to record
		// them — for app.stop too, which is how stop-then-delete keeps them
		// findable (#413; see appvolumes.go).
		c.recordVolumesOrLog(ctx, appID, "docker.stop")
		label := "docker compose down"
		if deleteVolumes {
			label = "docker compose down -v"
		}
		out, err := c.run(ctx, appID, composeDownArgs(deleteVolumes)...)
		if err != nil {
			return proto.AppStatusFailed, formatCmdErr(label, out, err), err
		}
	}
	if !deleteVolumes {
		// Keeping the data keeps ALL of it: named, renamed-away, dropped and
		// anonymous alike. Nothing below runs, and the record stays so the
		// orphan reaper can list what was kept once the app row is gone.
		return proto.AppStatusStopped, "", nil
	}

	// `down -v` removed what the current compose declares. Everything else the
	// app ever had goes now, by exact name, through the reaper's gates. This
	// runs without a compose file too — labels and the record need none — so
	// a retried delete, or an app whose compose went missing, still leaves
	// nothing behind.
	sweep, err := c.removeAppVolumes(ctx, appID)
	if err != nil {
		return proto.AppStatusFailed, "containers removed; the app's remaining volumes could not be enumerated, so some may still be on the node: " + err.Error(), err
	}
	if len(sweep.Refused) > 0 {
		// The operator asked for the data to go and some of it is still here.
		// Reporting success would let the row be removed on a belief that is
		// false, so the stop fails and names what stayed. The state directory,
		// and the record in it, stay too: a retry finds the same volumes, and
		// an uninstall that keeps volumes leaves them listed as orphans.
		reasons := make([]string, 0, len(sweep.Refused))
		for _, r := range sweep.Refused {
			reasons = append(reasons, r.Name+": "+r.Reason)
		}
		err := fmt.Errorf("%d volume(s) not removed", len(sweep.Refused))
		return proto.AppStatusStopped, fmt.Sprintf("containers removed, but %d of the app's volume(s) were NOT deleted — %s", len(sweep.Refused), strings.Join(reasons, "; ")), err
	}
	// Every volume is handled, so nothing on the node needs the app's state
	// any more — the record included.
	detail := "containers and volumes removed"
	if composeMissing {
		detail = "no compose file on disk; the volumes the app's project label and volume record name were removed"
	}
	if len(sweep.Removed) > 0 {
		detail += fmt.Sprintf("; including %d volume(s) the current compose does not declare: %s", len(sweep.Removed), strings.Join(sweep.Removed, ", "))
	}
	if err := os.RemoveAll(c.appDir(appID)); err != nil {
		detail += "; the app's agent state directory could not be removed: " + err.Error()
	}
	return proto.AppStatusStopped, detail, nil
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
	lines, err := parsePsLines(out)
	if err != nil {
		return proto.AppStatusUnknown, nil, err
	}
	if len(lines) == 0 {
		return proto.AppStatusStopped, nil, nil
	}
	services := toServiceStatuses(lines)
	c.markOutdated(ctx, appID, lines, services)
	return aggregateStatus(services), services, nil
}

// markOutdated sets Outdated on every running service whose container was
// created from a definition other than the one in the live compose file
// (#411; see proto.AppServiceStatus.Outdated for why the api needs to know).
//
// Compose stamps each container with com.docker.compose.config-hash — the hash
// of its service's definition when it was created — and `compose config
// --hash '*'` prints the same hash for the file as it stands. They match
// exactly when `up` has converged the service onto this file, which is also
// the test compose itself uses to decide whether `up` must recreate it.
//
// Anything that stops the comparison being made leaves the flag false:
// no running service, a container without the label, or a hash listing that
// could not be run or read. Unknown must read as the status did before this
// existed, never as outdated, or a failed app that genuinely recovered could
// never be recorded as running again.
func (c *ComposeBackend) markOutdated(ctx context.Context, appID string, lines []composePsLine, services []proto.AppServiceStatus) {
	anyRunning := false
	for _, s := range services {
		if classifyService(s) == outcomeRunning {
			anyRunning = true
			break
		}
	}
	if !anyRunning {
		return
	}
	out, err := c.run(ctx, appID, composeConfigHashArgs()...)
	if err != nil {
		log.Printf("rasputin-agent: docker.status %s: %s", appID, formatCmdErr("docker compose config --hash", out, err))
		return
	}
	want := parseConfigHashes(out)
	if len(want) == 0 {
		return
	}
	for i, s := range services {
		if classifyService(s) != outcomeRunning {
			continue
		}
		have := configHashLabel(lines[i].Labels)
		if have == "" {
			continue
		}
		// A running service the file no longer declares is outdated too: it
		// is left over from a compose `up` never finished replacing.
		if want[lines[i].Service] != have {
			services[i].Outdated = true
		}
	}
}

// composeConfigHashArgs prints one "<service> <hash>" line per service of the
// live compose file.
func composeConfigHashArgs() []string {
	return []string{"config", "--hash", "*"}
}

// configHashLabelKey is the label compose stamps a service's definition hash
// under.
const configHashLabelKey = "com.docker.compose.config-hash"

// parseConfigHashes reads `compose config --hash '*'` output. The run merges
// stderr into stdout, so a warning compose prints on the way ("No services to
// build", a `level=warning` line) is in the same buffer; only lines that are
// exactly a service name and a 64-hex hash are taken.
func parseConfigHashes(out []byte) map[string]string {
	hashes := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || !isHexHash(fields[1]) {
			continue
		}
		hashes[fields[0]] = fields[1]
	}
	return hashes
}

// configHashLabel pulls compose's config-hash out of the comma-joined Labels
// string `compose ps --format json` carries. "" when it is absent or not a
// hash.
func configHashLabel(labels string) string {
	for _, kv := range strings.Split(labels, ",") {
		if v, ok := strings.CutPrefix(kv, configHashLabelKey+"="); ok && isHexHash(v) {
			return v
		}
	}
	return ""
}

func isHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// run executes `docker compose -f <path> -p <project> <args...>` and returns
// combined stdout+stderr. ctx is honored — if it cancels, the command is
// killed.
//
// It goes through dockerFor, so a test that injects a docker CLI sees every
// compose invocation too.
func (c *ComposeBackend) run(ctx context.Context, appID string, args ...string) ([]byte, error) {
	return c.dockerFor()(ctx, composeArgs(c.composePath(appID), projectName(appID), args...)...)
}

// composeArgs builds the docker CLI arg vector for one compose invocation.
// It exists so the flags are assertable in a test.
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

// composeDownArgs is the `down` invocation Stop uses.
//
// `-v` is the difference between an uninstall that keeps an app's data and one
// that destroys it, and it is passed through here rather than inline so a test
// can assert which one the flag produces. Compose scopes `down -v` to the
// volumes the CURRENT compose declares, and to the anonymous volumes of the
// containers it is removing — it cannot reach a volume another project
// created, and it cannot be handed a name.
//
// That scope is also why `down -v` alone is not a delete (#413, measured case
// 8 of app-catalog.md §8a.2): it leaves renamed-away and dropped volumes, and
// every anonymous volume whose container a stop or an upgrade already removed.
// Stop removes those afterwards, by exact name, through gateAndRemove — the
// orphan reaper's gates. Keep by-name removal there, never here.
func composeDownArgs(deleteVolumes bool) []string {
	if deleteVolumes {
		return []string{"down", "-v"}
	}
	return []string{"down"}
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
	// Labels is the container's labels, comma-joined — read only for compose's
	// config-hash (markOutdated).
	Labels string `json:"Labels,omitempty"`
}

func parsePsOutput(out []byte) ([]proto.AppServiceStatus, error) {
	lines, err := parsePsLines(out)
	if err != nil {
		return nil, err
	}
	return toServiceStatuses(lines), nil
}

func toServiceStatuses(lines []composePsLine) []proto.AppServiceStatus {
	services := make([]proto.AppServiceStatus, 0, len(lines))
	for _, p := range lines {
		services = append(services, toServiceStatus(p))
	}
	return services
}

// parsePsLines decodes `compose ps --format json` in either shape compose has
// emitted it.
func parsePsLines(out []byte) ([]composePsLine, error) {
	lines := []composePsLine{}
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
			lines = append(lines, batch...)
			continue
		}
		var p composePsLine
		if err := json.Unmarshal(line, &p); err != nil {
			return nil, fmt.Errorf("parse compose ps line: %w", err)
		}
		lines = append(lines, p)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
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
