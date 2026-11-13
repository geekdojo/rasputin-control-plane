package proctest

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// startGroup starts name in a process group of its own, with stdout on a
// pipe the test can read to EOF. The caller reaps it.
func startGroup(t *testing.T, name string, args ...string) (*exec.Cmd, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	cmd := exec.Command(name, args...)
	cmd.Stdout = w
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = w.Close()
		t.Fatal(err)
	}
	_ = w.Close()
	return cmd, r
}

// F-966-17: a group with a live member is not zombie-only.
func TestAllExiting_LiveGroup(t *testing.T) {
	cmd, _ := startGroup(t, "tail", "-f", "/dev/null")
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	got, err := allExiting(cmd.Process.Pid)
	if err != nil || got {
		t.Fatalf("allExiting(live group) = %v, %v; want false, nil", got, err)
	}
}

// F-966-17: on darwin, kill(-pgid, SIGKILL) on a group whose only member is
// an unreaped zombie answers EPERM, allExiting counts it as gone, and Stop's judgement
// of that EPERM is "already gone". The zombie is this test's own child, so it
// stays a zombie until the test reaps it.
func TestAllExiting_ZombieGroup(t *testing.T) {
	cmd, r := startGroup(t, "true")
	t.Cleanup(func() { _ = cmd.Wait() })
	pgid := cmd.Process.Pid
	// EOF: the child has closed its stdout on the way out. It becomes a
	// zombie just after; wait on that fact, which nothing undoes until Wait.
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	for {
		gone, err := allExiting(pgid)
		if err != nil {
			t.Fatal(err)
		}
		if gone {
			break
		}
	}
	err := syscall.Kill(-pgid, syscall.SIGKILL)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("kill(-pgid) on a zombie-only group = %v, want EPERM (the darwin behaviour Stop handles)", err)
	}
	if got := groupKillResult(pgid, err, allExiting); got != nil {
		t.Fatalf("groupKillResult = %v, want nil for a zombie-only group", got)
	}
}
