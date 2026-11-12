package proctest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/iotest"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// These tests run /bin/sh fakes; nothing here needs a real server.

// writeFake writes an executable /bin/sh script into its own temp dir.
func writeFake(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// fifo makes a named pipe the fake writes to. Reading it blocks until the
// fake has written, so a test waits on that fact and on no timer.
func fifo(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pid.fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readInts(t *testing.T, path string) []int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		n, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("pid %q: %v", f, err)
		}
		out = append(out, n)
	}
	return out
}

func assertReaped(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		t.Fatalf("no pid to check (%d)", pid)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("kill -0 %d = %v, want ESRCH: the process is still there", pid, err)
	}
}

// launched starts a fake that runs setup, then writes its PID, then runs
// body, and returns once the PID is written (a fact).
func launched(t *testing.T, spec Spec, setup, body string) (*Proc, int) {
	t.Helper()
	pidPipe := fifo(t)
	spec.Bin = writeFake(t, setup+`echo $$ > "`+pidPipe+`"
`+body)
	if spec.Name == "" {
		spec.Name = "secret store"
	}
	p, err := Start(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Signal(syscall.SIGKILL); <-p.Exited() })
	return p, readInts(t, pidPipe)[0]
}

// TC-966-16 (moved from secretstoretest's TestLineLogTail): the line log
// keeps only the last lines, an unterminated last line included, for the
// early-exit error.
func TestLineLogTail(t *testing.T) {
	l := newLineLog(Spec{Logger: slog.New(slog.DiscardHandler)}, "stderr", 3)
	if got := l.tail(); got != "(none)" {
		t.Errorf("empty tail = %q", got)
	}
	l.consume(strings.NewReader("a\nb\r\nc\npartial"))
	if got := l.tail(); got != "b | c | partial" {
		t.Errorf("tail = %q, want %q", got, "b | c | partial")
	}
}

// TC-966-16 (moved from secretstoretest's TestLineLogConsume_ReadError,
// F-753-19): a read that fails with anything but EOF cuts the stream short,
// so consume logs one WARN naming the stream and the error. EOF logs no WARN.
func TestLineLogConsume_ReadError(t *testing.T) {
	errX := errors.New("read broke")
	log, rec := logkittest.New()
	l := newLineLog(Spec{Logger: log, Name: "secret store", Source: "openbao"}, "stderr", 3)
	l.consume(io.MultiReader(strings.NewReader("a\n"), iotest.ErrReader(errX)))

	warns := rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("%d WARN records, want 1:\n%s", len(warns), rec.Text())
	}
	if warns[0].Message != "secret store output read failed" {
		t.Errorf("WARN message = %q", warns[0].Message)
	}
	for key, want := range map[string]string{"source": "openbao", "stream": "stderr", "err": errX.Error()} {
		if got, ok := logkittest.Attr(warns[0], key); !ok || got != want {
			t.Errorf("WARN %s = %q (present %t), want %q", key, got, ok, want)
		}
	}
	if got := l.tail(); got != "a" {
		t.Errorf("tail = %q, want the line read before the error", got)
	}

	eofLog, eofRec := logkittest.New()
	newLineLog(Spec{Logger: eofLog}, "stdout", 0).consume(strings.NewReader("a\nb"))
	if w := eofRec.AtLevel(slog.LevelWarn); len(w) != 0 {
		t.Errorf("EOF input logged %d WARN record(s), want 0:\n%s", len(w), eofRec.Text())
	}
}

// TC-966-16 (moved from secretstoretest's
// TestClose_KillsAStoreThatIgnoresSIGTERM, TC-753-07): a process that
// ignores SIGTERM is SIGKILLed only because the ctx given to Stop has ended,
// with one WARN naming its pid, and Stop proves it was reaped.
func TestStop_KillsAProcessThatIgnoresSIGTERM(t *testing.T) {
	log, rec := logkittest.New()
	p, pid := launched(t, Spec{Logger: log}, "trap '' TERM\n", "exec tail -f /dev/null\n")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := p.Stop(ctx); err != nil {
		t.Errorf("Stop = %v, want nil", err)
	}
	assertReaped(t, pid)
	warns := rec.Matching(slog.LevelWarn, "secret store ignored SIGTERM; killed")
	if len(warns) != 1 {
		t.Fatalf("%d WARN records, want 1", len(warns))
	}
	if got, _ := logkittest.Attr(warns[0], "pid"); got != strconv.Itoa(pid) {
		t.Errorf("WARN pid = %q, want %d", got, pid)
	}
	if st := rec.Matching(slog.LevelInfo, "secret store stopped"); len(st) != 1 {
		t.Errorf("%d 'stopped' records, want 1", len(st))
	}
}

// TC-966-16: a process that honours SIGTERM stops with no SIGKILL and no
// WARN, even under a ctx that never ends.
func TestStop_SIGTERMIsEnough(t *testing.T) {
	log, rec := logkittest.New()
	p, pid := launched(t, Spec{Logger: log}, "", "exec tail -f /dev/null\n")
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop = %v", err)
	}
	assertReaped(t, pid)
	if w := rec.AtLevel(slog.LevelWarn); len(w) != 0 {
		t.Errorf("%d WARN records for a process that honoured SIGTERM", len(w))
	}
}

// alivePipe is an anonymous pipe whose write end the child inherits as fd 3.
// A process that keeps fd 3 holds the pipe open while it lives; reading the
// read end to EOF then means every holder has closed it, which a process
// does when it dies, whether or not anything has reaped it. That is the fact
// the tests below wait on: an orphan that died stays a zombie until init
// reaps it, and kill(2) cannot tell a zombie from a live process.
//
// It is an anonymous pipe, not a named one: on macOS a read on a FIFO can
// stay blocked after its last writer has exited (F-966-13), and a pipe's EOF
// does not depend on that.
func alivePipe(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

// awaitReady reads the line the member writes to fd 3 once it is set up, so
// a test signals it only after that fact. It closes this process's copy of
// the write end first, so the pipe's only writers are the child's.
func awaitReady(t *testing.T, r, w *os.File) {
	t.Helper()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != "ready\n" {
		t.Fatalf("ready line = %q, %v", buf, err)
	}
}

// assertDead reads the alive pipe to EOF: every holder has closed it.
func assertDead(t *testing.T, r *os.File) {
	t.Helper()
	if _, err := io.ReadAll(r); err != nil {
		t.Errorf("read the alive pipe: %v", err)
	}
}

// F-966-01: with Spec.Group, a launcher whose real server is a child it does
// not exec (kc.sh runs java in the background and waits) is stopped whole:
// the SIGTERM reaches the child too.
func TestStop_GroupStopsTheChild(t *testing.T) {
	r, w := alivePipe(t)
	// The child is an exec'd sh that says it is ready and then execs tail,
	// so by the time the test reads the line it is a process with the
	// default SIGTERM disposition. A bare "tail &" is not: bash's forked
	// child drops a SIGTERM that arrives before its exec, and the tail lives
	// on. The launcher closes its own fd 3, so only the child holds it.
	bin := writeFake(t, `sh -c 'echo ready >&3; exec tail -f /dev/null' &
exec 3>&-
wait
`)
	p, err := Start(Spec{Bin: bin, Logger: slog.New(slog.DiscardHandler), Name: "identity service", Group: true, ExtraFiles: []*os.File{w}})
	if err != nil {
		t.Fatal(err)
	}
	awaitReady(t, r, w)
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop = %v", err)
	}
	assertReaped(t, p.Pid())
	assertDead(t, r)
}

// F-966-01: a group member that outlives its leader (it ignores SIGTERM, and
// the leader does not wait for it) is killed with the group once the leader
// has exited.
func TestStop_GroupKillsAMemberThatOutlivesItsLeader(t *testing.T) {
	r, w := alivePipe(t)
	// The member's output goes elsewhere, as a daemonised helper's does; one
	// still holding the pipe keeps Exited open, and Stop's ctx ends that. It
	// says it is ready only after its trap is set, so the signal can only
	// arrive once it has its disposition.
	bin := writeFake(t, `trap 'exit 0' TERM
(trap '' TERM; echo ready >&3; exec tail -f /dev/null >/dev/null 2>&1) &
exec 3>&-
wait
`)
	p, err := Start(Spec{Bin: bin, Logger: slog.New(slog.DiscardHandler), Name: "identity service", Group: true, ExtraFiles: []*os.File{w}})
	if err != nil {
		t.Fatal(err)
	}
	awaitReady(t, r, w)
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop = %v", err)
	}
	assertReaped(t, p.Pid())
	assertDead(t, r)
}

// TC-966-16: Await returns nil as soon as the check answers true, and notes
// each change of answer once.
func TestAwait_EndsOnTheCheck(t *testing.T) {
	p, _ := launched(t, Spec{Logger: slog.New(slog.DiscardHandler)}, "", "exec tail -f /dev/null\n")
	n := 0
	var noted []string
	err := Await(t.Context(), p, func(context.Context) (bool, string, error) {
		n++
		switch {
		case n < 3:
			return false, "starting", nil
		case n < 5:
			return false, "", errors.New("connection refused")
		default:
			return true, "up", nil
		}
	}, func(last string) { noted = append(noted, last) })
	if err != nil {
		t.Fatalf("Await = %v", err)
	}
	if strings.Join(noted, ",") != "starting,connection refused" {
		t.Errorf("noted = %q, want each change once", noted)
	}
}

// TC-966-16: a process that exits before the check holds ends Await at once
// with ExitError, carrying the exit status and the last lines of both kept
// streams.
func TestAwait_EndsOnExit(t *testing.T) {
	bin := writeFake(t, "echo out-line\necho bind: address already in use >&2\nexit 3\n")
	p, err := Start(Spec{Bin: bin, Logger: slog.New(slog.DiscardHandler), Name: "identity service", StdoutTail: 5, StderrTail: 5})
	if err != nil {
		t.Fatal(err)
	}
	err = Await(t.Context(), p, func(context.Context) (bool, string, error) { return false, "not yet", nil }, nil)
	var exited *ExitedError
	if !errors.As(err, &exited) {
		t.Fatalf("Await = %v, want an *ExitedError", err)
	}
	var ee interface{ ExitCode() int }
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("Await = %v, want it to wrap exit status 3", err)
	}
	for _, want := range []string{"exit status 3", "last stderr: bind: address already in use", "last stdout: out-line"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to carry %q", err, want)
		}
	}
}

// TC-966-16: ctx ending first returns a *NotReadyError naming the last
// answer, never the answer a cancelled request gave.
func TestAwait_EndsOnCtx(t *testing.T) {
	p, _ := launched(t, Spec{Logger: slog.New(slog.DiscardHandler)}, "", "exec tail -f /dev/null\n")
	ctx, cancel := context.WithCancel(t.Context())
	n := 0
	err := Await(ctx, p, func(rctx context.Context) (bool, string, error) {
		n++
		if n == 1 {
			return false, "503 starting", nil
		}
		cancel()
		return false, "", rctx.Err()
	}, nil)
	var nr *NotReadyError
	if !errors.As(err, &nr) || nr.Last != "503 starting" || !errors.Is(err, context.Canceled) {
		t.Fatalf("Await = %v, want a NotReadyError with the last answer 503 starting", err)
	}
	if !strings.Contains(err.Error(), "last answer: 503 starting") {
		t.Errorf("err = %v, want it to name the last answer", err)
	}
}

// testGate is a Gate a test holds and releases.
type testGate struct {
	mu   sync.Mutex
	cond *sync.Cond
	held bool
	// waiting is closed the first time a reader waits while held.
	waiting chan struct{}
	once    sync.Once
}

func newTestGate() *testGate {
	g := &testGate{held: true, waiting: make(chan struct{})}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *testGate) Wait() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.held {
		g.once.Do(func() { close(g.waiting) })
		g.cond.Wait()
	}
}

func (g *testGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.held = false
	g.cond.Broadcast()
}

// TC-966-16: a held Gate pauses the reader before each line until it is
// released, and the reader then reads to EOF; a nil gate never blocks.
func TestGate_PausesTheReaderUntilReleased(t *testing.T) {
	g := newTestGate()
	l := newLineLog(Spec{Logger: slog.New(slog.DiscardHandler)}, "stdout", 5)
	l.gate = g
	done := make(chan struct{})
	go func() { defer close(done); l.consume(strings.NewReader("a\nb\n")) }()
	<-g.waiting
	if got := l.tail(); got != "(none)" {
		t.Fatalf("tail = %q while held, want nothing read", got)
	}
	g.release()
	<-done
	if got := l.tail(); got != "a | b" {
		t.Fatalf("tail = %q, want both lines once released", got)
	}

	open := newLineLog(Spec{Logger: slog.New(slog.DiscardHandler)}, "stdout", 5)
	open.consume(strings.NewReader("c\n"))
	if got := open.tail(); got != "c" {
		t.Errorf("tail with no gate = %q", got)
	}
}

// Watch sees every line of both streams, which is how a harness reads a port
// the process reports.
func TestWatch_SeesEveryLine(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	bin := writeFake(t, "echo one\necho two >&2\n")
	p, err := Start(Spec{Bin: bin, Logger: slog.New(slog.DiscardHandler), Watch: func(l string) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, l)
	}})
	if err != nil {
		t.Fatal(err)
	}
	<-p.Exited()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Errorf("seen = %q, want both lines", seen)
	}
}

// Start refuses a Spec with no logger and names a binary it cannot start;
// Signal on an exited process is not an error.
func TestStart_Refusals(t *testing.T) {
	if _, err := Start(Spec{Bin: "/bin/true"}); err == nil || !strings.Contains(err.Error(), "Logger") {
		t.Errorf("Start with no Logger = %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := Start(Spec{Bin: missing, Logger: slog.New(slog.DiscardHandler)}); err == nil || !strings.Contains(err.Error(), "start "+missing) {
		t.Errorf("Start of a missing binary = %v", err)
	}
	p, err := Start(Spec{Bin: "/bin/sh", Args: []string{"-c", "exit 0"}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	<-p.Exited()
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Errorf("Signal after exit = %v", err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Errorf("Stop after exit = %v", err)
	}
}

// FreePort returns a loopback port that is free once it returns.
func TestFreePort(t *testing.T) {
	port, err := FreePort()
	if err != nil || port <= 0 {
		t.Fatalf("FreePort = %d, %v", port, err)
	}
}

// A *Final check error ends Await at once with the wrapped error, and a nil
// Proc is a wait only the check and ctx can end.
func TestAwait_FinalAndNoProcess(t *testing.T) {
	gone := errors.New("container is not running")
	err := Await(t.Context(), nil, func(context.Context) (bool, string, error) {
		return false, "", &Final{Err: gone}
	}, nil)
	if !errors.Is(err, gone) {
		t.Fatalf("Await = %v, want the final error", err)
	}
	n := 0
	if err := Await(t.Context(), nil, func(context.Context) (bool, string, error) {
		n++
		return n == 2, "x", nil
	}, nil); err != nil || n != 2 {
		t.Fatalf("Await with no process = %v after %d checks", err, n)
	}
}
