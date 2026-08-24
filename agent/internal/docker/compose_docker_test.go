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
	"context"
	"os/exec"
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
		if _, _, err := c.Stop(ctx, appID); err != nil {
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
