package appsecret

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
//   - a resolved compose parses and the base64url-nopad value arrives intact
//     and unquoted, which is why that encoding was chosen.
//
// Skips where Compose is absent, so it is free on a laptop without Docker. That
// makes it a test a developer runs, NOT an enforced gate — it needs a CI job
// with Docker present, like the repo's existing real-caddy and real-grafana
// jobs, to be one. Flagged rather than assumed (geekdojo/geekdojo-brain#520).
func TestCompose_AcceptsEscapedRefusesRawResolvesDerived(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker binary")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("no docker compose plugin")
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
	want, err := seed.Derive("01K5R6P8Q9ZJ7V2XW4YB3D5EFG", "session-key", InitialVersion)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(tile, "01K5R6P8Q9ZJ7V2XW4YB3D5EFG", seed, InitialVersion)
	if err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, body string, args ...string) (string, error) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		return string(out), err
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

	// Resolved: parses, and the derived value arrives intact and unquoted.
	out, err := run(t, resolved, "config")
	if err != nil {
		t.Fatalf("resolved compose must parse: %v\n%s", err, out)
	}
	if !strings.Contains(out, "SESSION_KEY: "+want) {
		t.Errorf("the derived value must arrive intact and need no quoting (which is why the\n"+
			"encoding is base64url-nopad). want %q in:\n%s", "SESSION_KEY: "+want, out)
	}
}
