package docker

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The functional half of geekdojo/geekdojo-brain#776 (F1.6, the #695 gate):
// the real ComposeBackend against real Docker Compose, with a value carried
// beside the compose as the process environment of `config --hash` and `up`.
// The unit tests in secretenv_test.go pin which calls get the values; only a
// real Compose can show what each call then does — that the value reaches the
// container, that a value-less `stop`/`start` keeps it, that the recorded hash
// equals the label `up` stamps (so Status does not read outdated), and that a
// container deployed with the value inline is not recreated by the move to a
// reference.
//
// It skips where Docker or the Compose plugin is absent, so it is free on a
// laptop without them. RASPUTIN_APPSECRET_FUNCTIONAL=required turns the skips
// into failures: the required `backend (vet + test + build)` CI job sets it on
// its `test (remaining modules)` step, so on every PR this test must run
// against the runner's real Compose and pass. The switch is inlined, as in
// agent/internal/proxy, because api/internal/functest is internal to the api
// module. See docs/testing-appsecret-compose.md.

const appSecretFunctionalEnv = "RASPUTIN_APPSECRET_FUNCTIONAL"

// functionalImage is pulled once per runner; pinned so the test does not move.
const functionalImage = "busybox:1.36.1"

// requireCompose skips, or fails under RASPUTIN_APPSECRET_FUNCTIONAL=required,
// when the docker CLI, the Compose plugin or the daemon is missing.
func requireCompose(t *testing.T) {
	t.Helper()
	required := os.Getenv(appSecretFunctionalEnv) == "required"
	skip := func(why string) {
		t.Helper()
		if required {
			t.Fatalf("%s=required but %s", appSecretFunctionalEnv, why)
		}
		t.Skip(why)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not on PATH: " + err.Error())
	}
	if out, err := exec.Command("docker", "compose", "version").CombinedOutput(); err != nil {
		skip("docker compose plugin unavailable: " + err.Error() + " " + strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		skip("docker daemon unreachable: " + err.Error() + " " + strings.TrimSpace(string(out)))
	}
}

// functionalAppID is a fresh ULID-shaped id, so each run has its own compose
// project and nothing from an earlier run is found.
func functionalAppID(t *testing.T) string {
	t.Helper()
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	b := make([]byte, 26)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	return string(b)
}

// functionalBackend is the real backend over a temporary state root; every
// app deployed under appIDs is deleted with its volumes when the test ends.
func functionalBackend(t *testing.T, appIDs ...string) *ComposeBackend {
	t.Helper()
	c, err := NewComposeBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, id := range appIDs {
			_, _, _ = c.Stop(context.Background(), id, true)
			// Whatever Stop could not reach (no compose file after a refused
			// deploy), by project label.
			ids := projectContainers(t, id)
			if len(ids) > 0 {
				_ = exec.Command("docker", append([]string{"rm", "-f", "--"}, ids...)...).Run()
			}
		}
	})
	return c
}

// projectContainers lists every container of appID's compose project.
func projectContainers(t *testing.T, appID string) []string {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-aq", "--filter", "label=com.docker.compose.project="+projectName(appID)).Output()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	return strings.Fields(string(out))
}

// oneContainer is appID's only container.
func oneContainer(t *testing.T, appID string) string {
	t.Helper()
	ids := projectContainers(t, appID)
	if len(ids) != 1 {
		t.Fatalf("project %s has %d containers, want 1", projectName(appID), len(ids))
	}
	return ids[0]
}

// containerHolds reports whether the running container's environment holds
// value, as `docker exec env` shows it and as `docker inspect` records it.
func containerHolds(t *testing.T, id, value string) (inEnv, inInspect bool) {
	t.Helper()
	env, err := exec.Command("docker", "exec", id, "env").Output()
	if err != nil {
		t.Fatalf("docker exec env: %v", err)
	}
	inspect, err := exec.Command("docker", "inspect", "--format", "{{json .Config.Env}}", id).Output()
	if err != nil {
		t.Fatalf("docker inspect: %v", err)
	}
	return strings.Contains(string(env), value), strings.Contains(string(inspect), value)
}

// assertRunningCurrent fails unless appID reads running with no service
// outdated.
func assertRunningCurrent(t *testing.T, c *ComposeBackend, appID string) {
	t.Helper()
	status, services, err := c.Status(context.Background(), appID)
	if err != nil || status != proto.AppStatusRunning {
		t.Fatalf("Status = %s, %v", status, err)
	}
	for _, s := range services {
		if s.Outdated {
			t.Errorf("service %s reads outdated", s.Name)
		}
	}
}

func secretCompose(user string) string {
	s := "services:\n  web:\n    image: " + functionalImage + "\n    command: [\"sleep\", \"3600\"]\n"
	if user != "" {
		s += "    user: \"" + user + "\"\n"
	}
	return s + "    environment:\n      APP_SECRET: ${RASPUTIN_SECRET_CANARY}\n"
}

// TC-776-26, TC-776-27, TC-776-29: the value reaches the container and no
// file; a value-less quiesce keeps it; delete removes the record.
func TestSecretEnvFunctional_DeployQuiesceDelete(t *testing.T) {
	requireCompose(t)
	ctx := context.Background()
	appID := functionalAppID(t)
	c := functionalBackend(t, appID)
	canary := canaryValue(t)
	env := proto.AppSecretEnv{"RASPUTIN_SECRET_CANARY": canary}

	// TC-776-26.
	status, detail, err := c.Deploy(ctx, appID, "fn", secretCompose(""), env)
	if err != nil || status != proto.AppStatusRunning {
		t.Fatalf("Deploy = %s, %q, %v", status, detail, err)
	}
	scanForCanary(t, c.dir, canary)
	id := oneContainer(t, appID)
	if inEnv, inInspect := containerHolds(t, id, canary); !inEnv || !inInspect {
		t.Fatalf("the value is in exec env %v, in inspect Config.Env %v; want both", inEnv, inInspect)
	}
	assertRunningCurrent(t, c, appID)

	// TC-776-27: stop and start run without the values.
	if err := c.StopApp(ctx, appID, 5); err != nil {
		t.Fatalf("StopApp: %v", err)
	}
	if err := c.StartApp(ctx, appID); err != nil {
		t.Fatalf("StartApp: %v", err)
	}
	if running, err := c.AppRunning(ctx, appID); err != nil || !running {
		t.Fatalf("AppRunning = %v, %v after the quiesce", running, err)
	}
	if inEnv, _ := containerHolds(t, oneContainer(t, appID), canary); !inEnv {
		t.Fatal("the container lost the value across a value-less stop and start")
	}
	assertRunningCurrent(t, c, appID)
	scanForCanary(t, c.dir, canary)

	// TC-776-29.
	if _, detail, err := c.Stop(ctx, appID, true); err != nil {
		t.Fatalf("Stop(delete) = %q, %v", detail, err)
	}
	if _, err := os.Stat(c.appDir(appID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the app's state directory is still there: %v", err)
	}
	if ids := projectContainers(t, appID); len(ids) != 0 {
		t.Errorf("%d container(s) remain after delete", len(ids))
	}
}

// TC-776-28: a reference in `user:` is refused before any container exists,
// on a service named `web` and on one named `x-web`,
// and a deploy that fails at the daemon (a literal user that does not exist)
// with the value in its environment does not quote the value back.
func TestSecretEnvFunctional_PlacementRefusalAndFailedDetail(t *testing.T) {
	requireCompose(t)
	ctx := context.Background()
	refused, failed := functionalAppID(t), functionalAppID(t)
	c := functionalBackend(t, refused, failed)
	canary := canaryValue(t)
	env := proto.AppSecretEnv{"RASPUTIN_SECRET_CANARY": canary}

	// F-776-12: a service named "x-…" is a service, not an extension field.
	xWeb := strings.Replace(secretCompose("${RASPUTIN_SECRET_CANARY}"), "  web:\n", "  x-web:\n", 1)
	for compose, path := range map[string]string{
		secretCompose("${RASPUTIN_SECRET_CANARY}"): "services.web.user",
		xWeb: "services.x-web.user",
	} {
		_, detail, err := c.Deploy(ctx, refused, "fn", compose, env)
		if err == nil || !strings.Contains(detail, path) || strings.Contains(detail, canary) {
			t.Fatalf("Deploy = %q, %v; want the placement refusal naming %s", detail, err, path)
		}
		if ids := projectContainers(t, refused); len(ids) != 0 {
			t.Fatalf("a refused deploy created %d container(s)", len(ids))
		}
	}

	status, detail, err := c.Deploy(ctx, failed, "fn", secretCompose("no-such-user-776"), env)
	if err == nil && status == proto.AppStatusRunning {
		t.Fatal("a deploy with a nonexistent user came up running")
	}
	if strings.Contains(detail, canary) {
		t.Fatalf("the failed deploy's detail holds the value: %s", detail)
	}
	if detail == "" {
		t.Fatal("the failed deploy has no detail, so the check proved nothing")
	}
	scanForCanary(t, c.dir, canary)
}

// TC-776-30: an app deployed with its value inline — what an older api or
// agent leaves — reads current, and moving it to the reference shape keeps
// its container (the interpolated definition hash is unchanged) and its value,
// and the live compose no longer holds the value.
func TestSecretEnvFunctional_UpgradeFromInline(t *testing.T) {
	requireCompose(t)
	ctx := context.Background()
	appID := functionalAppID(t)
	c := functionalBackend(t, appID)
	canary := canaryValue(t)

	inline := strings.Replace(secretCompose(""), "${RASPUTIN_SECRET_CANARY}", canary, 1)
	if status, detail, err := c.Deploy(ctx, appID, "fn", inline, nil); err != nil || status != proto.AppStatusRunning {
		t.Fatalf("inline Deploy = %s, %q, %v", status, detail, err)
	}
	assertRunningCurrent(t, c, appID)
	before := oneContainer(t, appID)

	env := proto.AppSecretEnv{"RASPUTIN_SECRET_CANARY": canary}
	if status, detail, err := c.Deploy(ctx, appID, "fn", secretCompose(""), env); err != nil || status != proto.AppStatusRunning {
		t.Fatalf("reference Deploy = %s, %q, %v", status, detail, err)
	}
	after := oneContainer(t, appID)
	if after != before {
		t.Errorf("the container was recreated (%s → %s)", before, after)
	}
	if inEnv, _ := containerHolds(t, after, canary); !inEnv {
		t.Error("the container lost the value")
	}
	scanForCanary(t, c.dir, canary)
	assertRunningCurrent(t, c, appID)
}
