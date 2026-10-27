package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Secret values beside the compose (geekdojo/geekdojo-brain#776).
//
// A secret-bearing compose arrives holding ${RASPUTIN_SECRET_<NAME>}
// references, and the values arrive beside it in AppDeployCmd.SecretEnv. They
// reach Compose as the process environment of exactly two calls, `config
// --hash` (recorded here) and `up`, and so they reach the container's
// environment and dockerd's container store and nothing this agent writes.
//
// Every other call — ps, stop, start, down, pull, config --volumes — runs
// without them. Compose then warns that the variable is not set and
// interpolates a blank, which is harmless everywhere but one place: `config
// --hash` without the values hashes a different definition from the one `up`
// stamped on the container, so Status would call every secret-bearing app
// outdated for ever. The deploy therefore records the hashes it computed WITH
// the values, and Status reads that record instead (wantConfigHashes). The
// record holds SHA-256 hashes the container's own label already carries.

// configHashRecordFile is the per-app record of `config --hash '*'` computed
// with the app's secret values, written by a secret-bearing deploy.
const configHashRecordFile = "config-hash.json"

// stagedGuardPattern names the throwaway compose the guard hands Compose.
const stagedGuardPattern = ".guard-*.docker-compose.yml"

// dockerEnvExec runs the docker CLI with args and env added to the agent's own
// environment, and returns combined output. The real one is runDockerEnv
// (volumes.go), beside runDocker, so the package has one exec of docker.
type dockerEnvExec func(ctx context.Context, env []string, args ...string) ([]byte, error)

// dockerEnvFor returns the env-carrying exec — the injected one, or the real.
func (c *ComposeBackend) dockerEnvFor() dockerEnvExec {
	if c.execEnv != nil {
		return c.execEnv
	}
	return runDockerEnv
}

// runEnv is run with env as the call's added process environment.
func (c *ComposeBackend) runEnv(ctx context.Context, appID string, env proto.AppSecretEnv, args ...string) ([]byte, error) {
	return c.dockerEnvFor()(ctx, envEntries(env), composeArgs(c.composePath(appID), projectName(appID), args...)...)
}

// envEntries renders env as KEY=value entries, sorted by key.
func envEntries(env proto.AppSecretEnv) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

func (c *ComposeBackend) configHashRecordPath(appID string) string {
	return filepath.Join(c.appDir(appID), configHashRecordFile)
}

// removeConfigHashRecord removes appID's record. Absent is success.
func (c *ComposeBackend) removeConfigHashRecord(appID string) error {
	if err := os.Remove(c.configHashRecordPath(appID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// recordConfigHash runs `config --hash '*'` on the live compose with env and
// writes what it prints to appID's record, owner-only. A run that fails, or
// prints no hash, fails the deploy before `up`: without the record Status
// could never read the app as current.
func (c *ComposeBackend) recordConfigHash(ctx context.Context, appID string, env proto.AppSecretEnv) error {
	out, err := c.runEnv(ctx, appID, env, composeConfigHashArgs()...)
	if err != nil {
		return errors.New(formatCmdErr("docker compose config --hash", out, err))
	}
	hashes := parseConfigHashes(out)
	if len(hashes) == 0 {
		return errors.New("docker compose config --hash printed no service hash")
	}
	b, err := json.Marshal(hashes)
	if err != nil {
		return fmt.Errorf("encode config-hash record: %w", err)
	}
	if err := atrest.WriteSecretFile(c.configHashRecordPath(appID), b); err != nil {
		return fmt.Errorf("write config-hash record: %w", err)
	}
	return nil
}

// wantConfigHashes is each service's definition hash for appID's live
// compose: from the record when a secret-bearing deploy wrote one, and
// otherwise `config --hash '*'` run now, as every release before #776 did —
// which is also what an app an older agent deployed, values inline, needs.
func (c *ComposeBackend) wantConfigHashes(ctx context.Context, appID string) (map[string]string, error) {
	b, err := os.ReadFile(c.configHashRecordPath(appID))
	switch {
	case err == nil:
		hashes := map[string]string{}
		if err := json.Unmarshal(b, &hashes); err != nil {
			return nil, fmt.Errorf("read %s: %w", configHashRecordFile, err)
		}
		return hashes, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("read %s: %w", configHashRecordFile, err)
	}
	out, err := c.run(ctx, appID, composeConfigHashArgs()...)
	if err != nil {
		return nil, errors.New(formatCmdErr("docker compose config --hash", out, err))
	}
	return parseConfigHashes(out), nil
}

// composeGuardArgs prints the compose's normalized model as JSON, with every
// variable reference left as written.
func composeGuardArgs() []string {
	return []string{"config", "--no-interpolate", "--format", "json"}
}

// secretRefRe finds a reference to a secret variable in either of Compose's
// forms, $NAME and ${NAME...}.
var secretRefRe = regexp.MustCompile(`\$\{?(` + regexp.QuoteMeta(proto.SecretEnvPrefix) + `[A-Za-z0-9_]*)`)

// guardSecretRefs refuses composeYAML unless every string in it naming a
// secret variable (proto.SecretEnvPrefix) sits in an entry of some service's
// `environment:`, and env holds every variable those entries reference. It asks Compose itself, on a staged copy and without
// the values: `config --no-interpolate --format json` is Compose's own
// normalized model — anchors, merge keys, extends, include and list-form
// environment all resolved — of the exact bytes `up` will be given. The live
// file is not touched, so a refused deploy leaves the app as it was.
//
// A value outside `environment:` could land where dockerd quotes it back in an
// error and the journal keeps it (a rejected `user:`), or in a label, a
// command line or a file. Refusing it is what keeps the value in the one place
// it is meant to be.
//
// The refusal names the JSON path or the variable, never a value: the model
// is uninterpolated, so it holds none.
func (c *ComposeBackend) guardSecretRefs(ctx context.Context, appID, composeYAML string, env proto.AppSecretEnv) error {
	staged, cleanup, err := c.stageCompose(appID, stagedGuardPattern, composeYAML)
	if err != nil {
		return err
	}
	defer cleanup()
	out, err := c.dockerFor()(ctx, composeArgs(staged, projectName(appID), composeGuardArgs()...)...)
	if err != nil {
		return errors.New(formatCmdErr("docker compose config --no-interpolate", out, err))
	}
	model, err := decodeGuardModel(out)
	if err != nil {
		return err
	}
	var outside []string
	var missing []string
	seenMissing := map[string]bool{}
	walkGuardModel(model, nil, func(path []string, s string) {
		if !strings.Contains(s, proto.SecretEnvPrefix) {
			return
		}
		if !isServiceEnv(path) {
			outside = append(outside, strings.Join(path, "."))
			return
		}
		for _, r := range secretRefRe.FindAllStringSubmatch(s, -1) {
			if _, ok := env[r[1]]; !ok && !seenMissing[r[1]] {
				seenMissing[r[1]] = true
				missing = append(missing, r[1])
			}
		}
	})
	if len(outside) > 0 {
		sort.Strings(outside)
		return fmt.Errorf("refusing the deploy: a secret reference may sit only in a service's environment, and the compose has one at %s", strings.Join(outside, ", "))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("refusing the deploy: the compose references %s, which the command carries no value for", strings.Join(missing, ", "))
	}
	return nil
}

// decodeGuardModel reads the JSON model out of the guard's output. The run
// merges stderr into stdout, so Compose's warnings may come first; decoding
// starts at the first line that opens with '{'. Output with no such line, or
// one that does not decode, is refused.
func decodeGuardModel(out []byte) (any, error) {
	at := -1
	for i := 0; i < len(out); {
		line := out[i:]
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			line = line[:j]
		}
		if t := bytes.TrimLeft(line, " \t\r"); len(t) > 0 && t[0] == '{' {
			at = i
			break
		}
		i += len(line) + 1
	}
	if at < 0 {
		return nil, errors.New("refusing the deploy: docker compose config printed no JSON model to check the secret references against")
	}
	var model any
	if err := json.NewDecoder(bytes.NewReader(out[at:])).Decode(&model); err != nil {
		return nil, fmt.Errorf("refusing the deploy: reading docker compose config's JSON model: %w", err)
	}
	return model, nil
}

// walkGuardModel calls visit with the path and text of every string in v,
// object keys included at their own path. An extension field (a key that opens
// with "x-") is not walked: Compose reads it only where a merge copies it into
// a service, and the copy is walked there.
func walkGuardModel(v any, path []string, visit func(path []string, s string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if strings.HasPrefix(k, "x-") {
				continue
			}
			p := append(path[:len(path):len(path)], k)
			visit(p, k)
			walkGuardModel(child, p, visit)
		}
	case []any:
		for i, child := range t {
			walkGuardModel(child, append(path[:len(path):len(path)], fmt.Sprint(i)), visit)
		}
	case string:
		visit(path, t)
	}
}

// isServiceEnv reports whether path is services.<service>.environment.<key>:
// an entry of a service's environment, in map form (the key) or list form
// (the index).
func isServiceEnv(path []string) bool {
	return len(path) == 4 && path[0] == "services" && path[2] == "environment"
}
