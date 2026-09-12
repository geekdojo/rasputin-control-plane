//go:build docker

// Live functional test for ComposeBackend against a real `docker compose`.
// Excluded from the default `go test` run by the `docker` build tag — invoke
// with:
//
//	GOTOOLCHAIN=go1.26.4 go test -tags=docker -run TestComposeBackendLive \
//	  -count=1 -v -timeout=5m ./agent/internal/docker/...
//
// Requires:
//   - A working `docker` CLI + compose v2+ on PATH (Docker Desktop, Rancher
//     Desktop, OrbStack and Colima all work).
//   - Network access to pull busybox:latest, once. Nothing else is pulled and
//     no port is bound, so this is safe to run on a developer laptop.
//
// Why this test has to exist at all: the one-shot bug was never a bug in our
// logic in the abstract — it was a bug about what real compose emits. A unit
// test can only assert against the JSON shape we BELIEVE compose produces, and
// the belief was the broken part. Two facts here are only checkable against a
// live daemon, and both are load-bearing:
//
//  1. `compose ps --format json --all` reports ExitCode for every container,
//     including live ones, where it reads 0. Exit code alone therefore proves
//     nothing; it is only meaningful alongside State.
//  2. A one-shot that exits 0 remains listed by `--all` after `up` returns, in
//     state "exited" — so Deploy sees it, every time, and has to have an
//     opinion about it.
//
// Verified against compose v5.0.1 / engine 29.1.3 (2026-08-24), the same
// compose the appliance ships.
//
// Side effects: creates and removes compose projects named rasp_<appid> using
// the throwaway app IDs below. Cleanup runs via t.Cleanup even on failure.

package docker

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// oneShotCompose is the shape that failed 100% of the time on e3bench: a
// long-running service gated on an init container that does a job and exits.
// `service_completed_successfully` is compose's own name for the thing the
// agent used to call a failure.
const oneShotCompose = `services:
  seed:
    image: busybox:latest
    command: ["sh", "-c", "echo seeded > /tmp/seeded; exit 0"]
  app:
    image: busybox:latest
    command: ["sh", "-c", "while true; do sleep 5; done"]
    depends_on:
      seed:
        condition: service_completed_successfully
`

// crasherCompose is the regression guard. Nothing about the fix may make a
// genuinely broken stack look healthy.
const crasherCompose = `services:
  app:
    image: busybox:latest
    command: ["sh", "-c", "while true; do sleep 5; done"]
  broken:
    image: busybox:latest
    command: ["sh", "-c", "exit 3"]
`

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "compose", "version").CombinedOutput(); err != nil {
		t.Skipf("docker compose unavailable: %v — %s", err, out)
	}
}

// newLiveBackend builds a ComposeBackend over a throwaway state dir and
// registers the `compose down` teardown, so a failing assertion can never
// leave containers behind on a developer's machine.
func newLiveBackend(t *testing.T, appID string) (*ComposeBackend, string) {
	t.Helper()
	c, err := NewComposeBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewComposeBackend: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if _, _, err := c.Stop(ctx, appID, false); err != nil {
			t.Logf("cleanup: stop %s: %v", appID, err)
		}
	})
	return c, appID
}

// deployLive brings the stack up, guarantees teardown, and returns Deploy's
// verdict.
func deployLive(t *testing.T, appID, yaml string) (proto.AppStatus, string, []proto.AppServiceStatus) {
	t.Helper()
	c, appID := newLiveBackend(t, appID)

	// Generous: the first run pulls busybox.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	status, detail, err := c.Deploy(ctx, appID, appID, yaml)
	if err != nil {
		t.Fatalf("Deploy: %v (status=%s detail=%s)", err, status, detail)
	}
	_, services, err := c.Status(ctx, appID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return status, detail, services
}

func TestComposeBackendLiveOneShotDeploysClean(t *testing.T) {
	requireDocker(t)
	status, detail, services := deployLive(t, "01liveoneshot", oneShotCompose)

	if status != proto.AppStatusRunning {
		t.Fatalf("status = %q, want %q (detail: %s; services: %+v)", status, proto.AppStatusRunning, detail, services)
	}
	if detail != "" {
		t.Errorf("a clean deploy must carry no failure detail, got %q", detail)
	}

	// The premise of the whole fix: compose really did list the exited
	// one-shot, and really did tell us it exited 0. If either stops being
	// true, the fix rests on nothing and this is where we find out.
	var sawCompletedSeed, sawRunningApp bool
	for _, s := range services {
		if s.ExitCode == nil {
			t.Errorf("service %q (%s): compose reported no ExitCode — the parser or the compose contract changed", s.Name, s.State)
			continue
		}
		switch s.Name {
		case "seed":
			if !strings.EqualFold(s.State, "exited") || *s.ExitCode != 0 {
				t.Errorf("seed: state=%q exit=%d, want exited/0", s.State, *s.ExitCode)
				continue
			}
			sawCompletedSeed = true
		case "app":
			if !strings.EqualFold(s.State, "running") {
				t.Errorf("app: state=%q, want running", s.State)
				continue
			}
			// The trap, straight from the daemon: a container that is UP
			// reports ExitCode 0 too. Anything reading the exit code without
			// the state would call this finished.
			if *s.ExitCode != 0 {
				t.Logf("note: running container reported ExitCode %d (was 0 on compose v5.0.1)", *s.ExitCode)
			}
			sawRunningApp = true
		}
	}
	if !sawCompletedSeed {
		t.Error("compose ps --all did not list the completed one-shot — the bug's premise no longer holds")
	}
	if !sawRunningApp {
		t.Error("compose ps --all did not list the running app")
	}
}

// TestComposeBackendLiveCrashStillFails is the regression guard: nothing about
// excusing clean exits may excuse a crash.
//
// It asserts against Status rather than Deploy's return value on purpose.
// `up -d` returns once containers are STARTED, not once they have settled, so
// a container that crashes a moment later can still be "running" when Deploy
// takes its reading — observed here: Deploy reported running while `broken`
// was mid-flight, and the same container read `exited` a second later. That
// race predates this change (the old code was equally blind to a crash that
// had not happened yet) and is what the api's reconcile sweep exists to
// correct, so it is out of scope here — but it makes Deploy's instantaneous
// verdict the wrong thing to pin a crash test to.
func TestComposeBackendLiveCrashStillFails(t *testing.T) {
	requireDocker(t)
	c, appID := newLiveBackend(t, "01livecrasher")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, detail, err := c.Deploy(ctx, appID, appID, crasherCompose); err != nil {
		t.Fatalf("Deploy: %v (detail: %s)", err, detail)
	}

	// Wait for the crash to actually land, then assert on what compose reports.
	// Hard deadline: a wait that can hang forever is a broken test.
	var (
		status   proto.AppStatus
		services []proto.AppServiceStatus
	)
	deadline := time.Now().Add(60 * time.Second)
	for {
		var err error
		status, services, err = c.Status(ctx, appID)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if crashed(services) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("`broken` never exited within 60s — services: %+v", services)
		}
		time.Sleep(500 * time.Millisecond)
	}

	if status != proto.AppStatusFailed {
		t.Fatalf("status = %q, want %q (services: %+v)", status, proto.AppStatusFailed, services)
	}
	// The second bug: a failed deploy that says nothing is a failed deploy the
	// operator cannot act on.
	detail := deployDetail(status, services)
	if detail == "" {
		t.Fatal("failed status produced an empty detail")
	}
	if !strings.Contains(detail, "broken") {
		t.Errorf("detail %q does not name the offending service", detail)
	}
	if !strings.Contains(detail, "3") {
		t.Errorf("detail %q does not carry the exit code", detail)
	}
	t.Logf("detail: %s", detail)
}

// crashed reports whether the `broken` service has finished dying.
func crashed(services []proto.AppServiceStatus) bool {
	for _, s := range services {
		if s.Name == "broken" && strings.EqualFold(s.State, "exited") {
			return true
		}
	}
	return false
}

// runningCompose is the app as it runs before an owner changes its compose.
const runningCompose = `services:
  app:
    image: busybox:latest
    command: ["sh", "-c", "while true; do sleep 5; done"]
`

// badDigestCompose is the change whose pull fails: a digest no registry has.
// Nothing is pulled — the registry answers "not found" for the manifest.
const badDigestCompose = `services:
  app:
    image: busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000
    command: ["sh", "-c", "while true; do sleep 5; done"]
`

// containerIdentity is what "the running app was not touched" means: the same
// container, started at the same instant, still running.
func containerIdentity(t *testing.T, appID string) (id, startedAt string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "--quiet", "--no-trunc",
		"--filter", "label=com.docker.compose.project="+projectName(appID),
		"--filter", "label=com.docker.compose.service=app").Output()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		t.Fatalf("want exactly one running app container, got %v", ids)
	}
	started, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.StartedAt}}", ids[0]).Output()
	if err != nil {
		t.Fatalf("docker inspect: %v", err)
	}
	return ids[0], strings.TrimSpace(string(started))
}

// geekdojo/geekdojo-brain#411, against a real daemon: a pull of a compose whose
// image digest does not exist fails, and leaves the running container (same
// id, same StartedAt) and the app's live compose file exactly as they were.
// This is measured case 7 of app-catalog.md §8a.2, pinned through the agent's
// own verb rather than a hand-typed `compose up`.
func TestComposeBackendLiveBadDigestPullChangesNothing(t *testing.T) {
	requireDocker(t)
	c, appID := newLiveBackend(t, "01livebadpull")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if status, detail, err := c.Deploy(ctx, appID, appID, runningCompose); err != nil || status != proto.AppStatusRunning {
		t.Fatalf("Deploy: %v (status=%s detail=%s)", err, status, detail)
	}
	idBefore, startedBefore := containerIdentity(t, appID)
	liveBefore, err := os.ReadFile(c.composePath(appID))
	if err != nil {
		t.Fatal(err)
	}
	statBefore, _ := os.Stat(c.composePath(appID))

	detail, err := c.Pull(ctx, appID, badDigestCompose)
	if err == nil {
		t.Fatalf("a pull of a nonexistent digest succeeded (detail: %s)", detail)
	}
	if !strings.Contains(detail, "docker compose pull") || !strings.Contains(detail, "0000000000") {
		t.Errorf("detail %q does not carry compose's reason naming the image", detail)
	}
	t.Logf("pull detail: %s", detail)

	idAfter, startedAfter := containerIdentity(t, appID)
	if idAfter != idBefore || startedAfter != startedBefore {
		t.Errorf("the running container changed: %s@%s → %s@%s", idBefore, startedBefore, idAfter, startedAfter)
	}
	liveAfter, err := os.ReadFile(c.composePath(appID))
	if err != nil {
		t.Fatalf("live compose after the pull: %v", err)
	}
	statAfter, _ := os.Stat(c.composePath(appID))
	if !bytes.Equal(liveAfter, liveBefore) || !statAfter.ModTime().Equal(statBefore.ModTime()) {
		t.Errorf("the live compose file was rewritten by a pull")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(c.appDir(appID), ".pull-*")); len(leftovers) != 0 {
		t.Errorf("staged compose left behind: %v", leftovers)
	}
	if status, services, err := c.Status(ctx, appID); err != nil || status != proto.AppStatusRunning {
		t.Errorf("status after the failed pull = %s %+v %v, want running", status, services, err)
	} else if services[0].Outdated {
		t.Errorf("the untouched container reads as outdated: %+v", services)
	}

	// And a pull of the compose that is running succeeds without the
	// registry: its image is already on the node (--policy missing).
	if detail, err := c.Pull(ctx, appID, runningCompose); err != nil {
		t.Errorf("pull of the running compose: %v (%s)", err, detail)
	}
}

// networkConflictCompose changes the service AND declares two networks with
// the same subnet, so `up` fails creating the second network — before it ever
// reaches the service. No port is bound; the subnets are private and only ever
// exist for the life of this test.
const networkConflictCompose = `services:
  app:
    image: busybox:latest
    command: ["sh", "-c", "while true; do sleep 7; done"]
    networks: [n1, n2]
networks:
  n1:
    ipam:
      config: [{subnet: 10.231.77.0/24}]
  n2:
    ipam:
      config: [{subnet: 10.231.77.0/24}]
`

// The after-pull failure branch of #411: an `up` that fails before converging
// a service leaves that service's OLD container running under the NEW compose
// file. Status must still say running — it is — and flag the container
// outdated, which is what keeps the api's reconcile from reading a failed
// upgrade as recovered. Re-applying the running compose clears the flag.
func TestComposeBackendLiveFailedUpLeavesAnOutdatedContainer(t *testing.T) {
	requireDocker(t)
	c, appID := newLiveBackend(t, "01liveoutdated")
	// `down` runs against whatever compose is live at cleanup, which no longer
	// declares the networks the failed up created, so they are removed by name.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, n := range []string{"n1", "n2"} {
			_ = exec.CommandContext(ctx, "docker", "network", "rm", projectName(appID)+"_"+n).Run()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if status, detail, err := c.Deploy(ctx, appID, appID, runningCompose); err != nil || status != proto.AppStatusRunning {
		t.Fatalf("Deploy: %v (status=%s detail=%s)", err, status, detail)
	}
	idBefore, startedBefore := containerIdentity(t, appID)

	if _, detail, err := c.Deploy(ctx, appID, appID, networkConflictCompose); err == nil {
		t.Fatalf("up with two networks on one subnet succeeded (detail: %s) — the fixture no longer fails before the service", detail)
	} else {
		t.Logf("up detail: %s", detail)
	}
	if idAfter, startedAfter := containerIdentity(t, appID); idAfter != idBefore || startedAfter != startedBefore {
		t.Fatalf("the fixture's failed up touched the container (%s@%s → %s@%s); it no longer exercises an outdated survivor",
			idBefore, startedBefore, idAfter, startedAfter)
	}
	status, services, err := c.Status(ctx, appID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != proto.AppStatusRunning || len(services) != 1 || !services[0].Outdated {
		t.Fatalf("status = %s %+v, want running with the surviving container outdated", status, services)
	}

	if status, detail, err := c.Deploy(ctx, appID, appID, runningCompose); err != nil || status != proto.AppStatusRunning {
		t.Fatalf("re-apply: %v (status=%s detail=%s)", err, status, detail)
	}
	if _, services, err := c.Status(ctx, appID); err != nil || len(services) != 1 || services[0].Outdated {
		t.Errorf("after re-applying the running compose: %+v %v, want one current container", services, err)
	}
}
