package appsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// functionalEnv is the switch that makes this file's skips failures.
const functionalEnv = "RASPUTIN_APPSECRET_FUNCTIONAL"

// The functional half of this package's tests: what REAL Docker Compose does
// with what Resolve and Escape emit.
//
// The unit tests above pin the strings. They cannot tell you whether Compose
// accepts them, and that is the whole reason Escape exists — so this drives the
// real binary. Measured with Compose 29.1.3 on 2026-09-23:
//
//   - an unescaped `${secret:x}` makes Compose refuse the WHOLE FILE with
//     "invalid interpolation format", including on `config --volumes`, which is
//     exactly the path the volume gate uses. So shipping a token to a node
//     unescaped does not degrade, it breaks the deploy.
//   - `$${secret:x}` parses, and Compose emits the literal — the value never
//     resolves on a path that must not see it.
//   - a resolved compose holds ${RASPUTIN_SECRET_<NAME>} references
//     (geekdojo/geekdojo-brain#776): with the map as Compose's process
//     environment the value arrives intact and unquoted in the service's
//     environment, which is why base64url-nopad was chosen; without it, the
//     value is nowhere in Compose's output (TC-776-31).
//
// Skips where Docker or the Compose plugin is absent, so it is free on a laptop
// without them. RASPUTIN_APPSECRET_FUNCTIONAL=required turns those skips into
// failures: the required `backend (vet + test + build)` CI job sets it on its
// `test (api with coverage)` step, so on every PR into main this test must run
// against real Compose and pass. See docs/testing-appsecret-compose.md
// (geekdojo/geekdojo-brain#695).
func TestCompose_AcceptsEscapedRefusesRawResolvesDerived(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		functest.SkipOrFail(t, functionalEnv, "docker not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "compose", "version").CombinedOutput(); err != nil {
		functest.SkipOrFail(t, functionalEnv, "docker compose plugin unavailable: %v (%s)",
			err, strings.TrimSpace(string(out)))
	}

	const tile = `services:
  app:
    image: alpine:3.20
    environment:
      SESSION_KEY: ${secret:session-key}
      DATA_DIR: /data
    volumes:
      - ./data:/data
`
	seed, err := NewSeed(make([]byte, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	want, err := str(seed.Derive("01K5R6P8Q9ZJ7V2XW4YB3D5EFG", "session-key", InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	resolvedCompose, env, err := resolved(Resolve(tile, "01K5R6P8Q9ZJ7V2XW4YB3D5EFG", seed, InitialVersion))
	if err != nil {
		t.Fatal(err)
	}

	runEnv := func(t *testing.T, body string, env map[string]string, args ...string) (string, error) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
		cmd.Dir = dir
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	run := func(t *testing.T, body string, args ...string) (string, error) {
		t.Helper()
		return runEnv(t, body, nil, args...)
	}

	// The volume gate's own call. A raw token must fail it — that is the bug.
	if out, _ := run(t, tile, "config", "--volumes"); !strings.Contains(out, "invalid interpolation format") {
		t.Errorf("an unescaped token should make Compose refuse the file; got %q.\n"+
			"If Compose has changed to tolerate it, Escape may no longer be needed — "+
			"re-read the reasoning above before deleting anything", out)
	}

	// Escaped: parses, and the value stays literal.
	if out, err := run(t, Escape(tile), "config"); err != nil {
		t.Errorf("escaped compose must parse: %v\n%s", err, out)
	} else if !strings.Contains(out, "$${secret:session-key}") {
		t.Errorf("escaped compose must keep the placeholder literal, so no secret reaches this path; got:\n%s", out)
	} else if strings.Contains(out, want) {
		t.Error("the escaped path emitted the DERIVED value; it must never see it")
	}
	if out, err := run(t, Escape(tile), "config", "--volumes"); err != nil {
		t.Errorf("escaped compose must pass the volume gate's own call: %v\n%s", err, out)
	}

	// TC-776-31. Resolved: the compose holds the reference and no value. With
	// the map as the process environment it parses and the derived value
	// arrives intact and unquoted in the service's environment; without the
	// map the value is nowhere in Compose's output.
	if strings.Contains(resolvedCompose, want) || !strings.Contains(resolvedCompose, "${RASPUTIN_SECRET_SESSION_KEY}") {
		t.Fatalf("the resolved compose must hold the reference and no value:\n%s", resolvedCompose)
	}
	out, err := runEnv(t, resolvedCompose, env, "config")
	if err != nil {
		t.Fatalf("resolved compose must parse with its values: %v\n%s", err, out)
	}
	if !strings.Contains(out, "SESSION_KEY: "+want) {
		t.Errorf("the derived value must arrive intact and need no quoting (which is why the\n"+
			"encoding is base64url-nopad). want %q in:\n%s", "SESSION_KEY: "+want, out)
	}
	if out, _ := run(t, resolvedCompose, "config"); strings.Contains(out, want) {
		t.Errorf("without the map Compose must not see the value; got:\n%s", out)
	}

	// TC-762-26: a compose the store source resolved (geekdojo-brain#762),
	// from an entry of the derived shape that is not this seed's value, so
	// the value Compose sees can only have come from the store.
	other, err := NewSeed(bytes.Repeat([]byte{0x5a}, SeedLen), DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := str(other.Derive(appID, "session-key", InitialVersion))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := secrets.AppSecret(appID, "session-key")
	if err != nil {
		t.Fatal(err)
	}
	log, _ := logkittest.New()
	src, err := NewStoreSource(StoreSourceDeps{
		Secrets: newFakeSecrets(map[string]string{ref.String(): stored}),
		Apps:    &fakeNodes{nodes: map[string]string{appID: "n"}}, Refs: &fakeRefs{}, Seed: seed, Operator: noOperatorSecrets{}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	fromStore, storeEnv, err := resolved(src.ResolveCompose(context.Background(), appID, tile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fromStore, stored) {
		t.Fatalf("the store-resolved compose must hold no value:\n%s", fromStore)
	}
	out, err = runEnv(t, fromStore, storeEnv, "config")
	if err != nil {
		t.Fatalf("the store-resolved compose must parse: %v\n%s", err, out)
	}
	if !strings.Contains(out, "SESSION_KEY: "+stored) {
		t.Errorf("the stored value must arrive intact. want %q in:\n%s", "SESSION_KEY: "+stored, out)
	}

	// TC-779-07: a stored value that would change compose text if it were
	// ever written into it (geekdojo/geekdojo-brain#779). Compose interpolates
	// it once and never re-reads it, so the parsed model has the key paths of
	// the benign run and the service gets the value byte-exact, after undoing
	// Compose's own $ -> $$ output escape.
	modelOf := func(t *testing.T, value string) (paths []string, sessionKey string) {
		t.Helper()
		src, err := NewStoreSource(StoreSourceDeps{
			Secrets: newFakeSecrets(map[string]string{ref.String(): value}),
			Apps:    &fakeNodes{nodes: map[string]string{appID: "n"}}, Refs: &fakeRefs{}, Seed: seed, Operator: noOperatorSecrets{}, Log: log,
		})
		if err != nil {
			t.Fatal(err)
		}
		compose, env, err := resolved(src.ResolveCompose(context.Background(), appID, tile))
		if err != nil {
			t.Fatal(err)
		}
		out, err := runEnv(t, compose, env, "config", "--format", "json")
		if err != nil {
			t.Fatalf("the store-resolved compose must parse: %v\n%s", err, out)
		}
		var model struct {
			Services map[string]struct {
				Environment map[string]string `json:"environment"`
			} `json:"services"`
		}
		if err := json.Unmarshal([]byte(out), &model); err != nil {
			t.Fatalf("compose config output is not JSON: %v\n%s", err, out)
		}
		var raw any
		if err := json.Unmarshal([]byte(out), &raw); err != nil {
			t.Fatal(err)
		}
		return jsonKeyPaths(raw, ""), model.Services["app"].Environment["SESSION_KEY"]
	}
	t.Run("hostile values", func(t *testing.T) {
		if v, err := exec.Command("docker", "compose", "version", "--short").Output(); err == nil {
			t.Logf("docker compose %s", strings.TrimSpace(string(v)))
		}
		benign, _ := modelOf(t, stored)
		for _, v := range hostileValues {
			t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
				paths, got := modelOf(t, v)
				if !slices.Equal(paths, benign) {
					t.Errorf("the parsed model's key paths changed:\n%v\nwant:\n%v", paths, benign)
				}
				if got = strings.ReplaceAll(got, "$$", "$"); got != v {
					t.Errorf("SESSION_KEY = %q, want %q byte-exact", got, v)
				}
			})
		}
	})

	// TC-604-18 (geekdojo/geekdojo-brain#604): an unset optional operator
	// secret resolves to "" and real Compose delivers it as an empty string:
	// the parsed model has the key paths of a run with a value, and the
	// service's variable is "".
	t.Run("TC-604-18 an empty optional value", func(t *testing.T) {
		const optTile = `services:
  app:
    image: alpine:3.20
    environment:
      OPT_KEY: ${secret:opt-key}
      DATA_DIR: /data
`
		no := false
		decls := &fakeDecls{decls: []tileschema.OperatorSecret{{Name: "opt-key", Label: "Optional key", Required: &no}}}
		optRef, err := secrets.AppSecret(appID, "opt-key")
		if err != nil {
			t.Fatal(err)
		}
		model := func(t *testing.T, entries map[string]string) (paths []string, env map[string]string, optKey string) {
			t.Helper()
			src, err := NewStoreSource(StoreSourceDeps{
				Secrets: newFakeSecrets(entries),
				Apps:    &fakeNodes{nodes: map[string]string{appID: "n"}}, Refs: &fakeRefs{}, Seed: seed, Operator: decls, Log: log,
			})
			if err != nil {
				t.Fatal(err)
			}
			compose, env, err := resolved(src.ResolveCompose(context.Background(), appID, optTile))
			if err != nil {
				t.Fatal(err)
			}
			out, err := runEnv(t, compose, env, "config", "--format", "json")
			if err != nil {
				t.Fatalf("the resolved compose must parse: %v\n%s", err, out)
			}
			var m struct {
				Services map[string]struct {
					Environment map[string]*string `json:"environment"`
				} `json:"services"`
			}
			if err := json.Unmarshal([]byte(out), &m); err != nil {
				t.Fatalf("compose config output is not JSON: %v\n%s", err, out)
			}
			var raw any
			if err := json.Unmarshal([]byte(out), &raw); err != nil {
				t.Fatal(err)
			}
			v := m.Services["app"].Environment["OPT_KEY"]
			if v == nil {
				t.Fatalf("OPT_KEY is missing or null in the parsed model:\n%s", out)
			}
			return jsonKeyPaths(raw, ""), env, *v
		}
		withValue, _, _ := model(t, map[string]string{optRef.String(): "set-value"})
		paths, env, got := model(t, nil)
		if v, ok := env["RASPUTIN_SECRET_OPT_KEY"]; !ok || v != "" {
			t.Fatalf("the resolved env holds %q (present %v), want present and empty", v, ok)
		}
		if !slices.Equal(paths, withValue) {
			t.Errorf("the parsed model's key paths changed with an empty value:\n%v\nwant:\n%v", paths, withValue)
		}
		if got != "" {
			t.Errorf("OPT_KEY = %q, want \"\"", got)
		}
	})
}

// jsonKeyPaths is the sorted set of object-key paths in a decoded JSON value,
// an array item's index standing in for its key.
func jsonKeyPaths(v any, prefix string) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			p := prefix + "/" + k
			out = append(out, p)
			out = append(out, jsonKeyPaths(c, p)...)
		}
	case []any:
		for i, c := range x {
			p := fmt.Sprintf("%s/%d", prefix, i)
			out = append(out, p)
			out = append(out, jsonKeyPaths(c, p)...)
		}
	}
	slices.Sort(out)
	return out
}
