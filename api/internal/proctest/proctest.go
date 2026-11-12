// Package proctest runs one real child process for a test harness: it starts
// it, reads its output a line at a time into the logger, waits on a readiness
// fact the caller checks, and stops it with proof that it was reaped. The
// secret store harness (secretstoretest) and the identity harness
// (identitytest) both run their process through it, so the launch, line-log,
// await and stop code exists once (ARCH-DRY, geekdojo/geekdojo-brain#966).
//
// Tests import it; nothing in a shipped binary does.
package proctest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// recheckInterval is how often Await re-asks the caller's check. It decides
// nothing: the wait ends on the check's own answer, a process that exits
// fails at once, and the wait as a whole is bounded only by the caller's
// ctx. The interval only sets how soon after the fact becomes true the
// harness notices it. Timer-audit row K22.
const recheckInterval = 20 * time.Millisecond

// Gate pauses a stream reader between lines while it is held. A nil Gate
// never pauses.
type Gate interface{ Wait() }

// Spec is one process to start.
type Spec struct {
	// Bin is the executable; Args follow it.
	Bin  string
	Args []string
	// Env is the child's whole environment; nil inherits this process's.
	Env []string
	// Dir is the child's working directory; "" is this process's.
	Dir string
	// Logger receives each output line at DEBUG and the stop records.
	Logger *slog.Logger
	// Name is the process's name in log messages ("secret store").
	Name string
	// Source is the source attribute on each output line ("openbao").
	Source string
	// StdoutTail and StderrTail are how many of each stream's last lines
	// ExitError carries. The cause of an early exit is only ever there.
	StdoutTail, StderrTail int
	// StdoutGate, when set, is waited on before each stdout line is read.
	StdoutGate Gate
	// Group starts the process in a process group of its own, and every
	// signal goes to the whole group. A launcher script that runs its real
	// server as a child (Keycloak's kc.sh) or a program with helpers (Chrome)
	// leaves nothing behind when it is stopped this way.
	Group bool
	// Watch, when set, is called with every output line, from the reader
	// goroutines. A harness reads a fact the process prints (a bound port)
	// through it.
	Watch func(line string)
}

// Proc is one started process. Its methods are safe for concurrent use.
type Proc struct {
	spec    Spec
	cmd     *exec.Cmd
	stdout  *lineLog
	stderr  *lineLog
	exited  chan struct{} // closed once cmd.Wait has returned
	waitErr error         // cmd.Wait's result; read only after exited closes
}

// Start starts the process. Its stdout and stderr are read a line at a time
// into the logger. One goroutine owns cmd.Wait: it waits for both readers to
// reach EOF (exec requires every read from the pipes to finish before Wait),
// then reaps the process and closes Exited.
func Start(spec Spec) (*Proc, error) {
	if spec.Logger == nil {
		return nil, errors.New("proctest: Spec.Logger is nil")
	}
	cmd := exec.Command(spec.Bin, spec.Args...)
	cmd.Env = spec.Env
	cmd.Dir = spec.Dir
	if spec.Group {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	p := &Proc{
		spec:   spec,
		cmd:    cmd,
		stdout: newLineLog(spec, "stdout", spec.StdoutTail),
		stderr: newLineLog(spec, "stderr", spec.StderrTail),
		exited: make(chan struct{}),
	}
	p.stdout.gate = spec.StdoutGate
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", spec.Bin, err)
	}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); p.stdout.consume(stdout) }()
	go func() { defer readers.Done(); p.stderr.consume(stderr) }()
	go func() {
		readers.Wait()
		p.waitErr = cmd.Wait()
		close(p.exited)
	}()
	return p, nil
}

// Pid is the process's id, and with Spec.Group its process group's id.
func (p *Proc) Pid() int { return p.cmd.Process.Pid }

// Exited is closed once the process has exited and been reaped.
func (p *Proc) Exited() <-chan struct{} { return p.exited }

// Signal sends sig to the process, or with Spec.Group to its whole group. A
// process that has already exited is not an error.
func (p *Proc) Signal(sig syscall.Signal) error {
	select {
	case <-p.exited:
		return nil
	default:
	}
	var err error
	if p.spec.Group {
		err = syscall.Kill(-p.Pid(), sig)
		if errors.Is(err, syscall.ESRCH) {
			err = nil
		}
	} else {
		err = p.cmd.Process.Signal(sig)
		if errors.Is(err, os.ErrProcessDone) {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("%s pid %d: %w", sig, p.Pid(), err)
	}
	return nil
}

// ExitError is the error for a process that exited before the awaited fact.
// It wraps the wait error and carries the kept last lines, where the cause
// is. Read it only once Exited has closed.
func (p *Proc) ExitError() error {
	msg := fmt.Sprintf("%v; last stderr: %s", p.waitErr, p.stderr.tail())
	if p.spec.StdoutTail > 0 {
		msg += "; last stdout: " + p.stdout.tail()
	}
	return &ExitedError{Err: p.waitErr, msg: msg}
}

// ExitedError is a process that exited first. Err is cmd.Wait's result.
type ExitedError struct {
	Err error
	msg string
}

func (e *ExitedError) Error() string { return e.msg }
func (e *ExitedError) Unwrap() error { return e.Err }

// Stop ends the process and proves it: it returns an error unless the process
// has been reaped and, with Spec.Group, its group is empty.
//
// It sends SIGTERM and waits for the exit. Only if ctx ends first is SIGKILL
// sent, with one WARN "<Name> ignored SIGTERM; killed", so a caller that wants
// a clean stop passes a ctx that does not end. A process that has already
// exited is not signalled. Either way one INFO "<Name> stopped" is logged.
func (p *Proc) Stop(ctx context.Context) error {
	var errs []error
	pid := p.Pid()
	select {
	case <-p.exited:
	default:
		if err := p.Signal(syscall.SIGTERM); err != nil {
			errs = append(errs, err)
		}
		select {
		case <-p.exited:
		case <-ctx.Done():
			if err := p.Signal(syscall.SIGKILL); err != nil {
				errs = append(errs, err)
			}
			p.spec.Logger.Warn(p.spec.Name+" ignored SIGTERM; killed", "pid", pid)
			<-p.exited
		}
	}
	if p.spec.Group {
		// The leader is gone; a member that outlived it (a forked server, a
		// helper) is killed and named, so a leak is an error, never silent.
		if err := syscall.Kill(-pid, 0); err == nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			errs = append(errs, fmt.Errorf("process group %d still had members after its leader exited; killed", pid))
		}
	}
	if p.cmd.ProcessState == nil {
		errs = append(errs, fmt.Errorf("teardown left pid %d unreaped", pid))
	} else {
		p.spec.Logger.Info(p.spec.Name+" stopped", "pid", pid, "exit", p.cmd.ProcessState.String())
	}
	return errors.Join(errs...)
}

// Check asks once whether the awaited fact holds. status describes the
// answer for the log and for the error if ctx ends; err is a request that
// got no answer.
type Check func(ctx context.Context) (ok bool, status string, err error)

// NotReadyError is ctx ending before the fact held. Last is the last answer
// the check gave.
type NotReadyError struct {
	Last string
	Err  error
}

func (e *NotReadyError) Error() string {
	return fmt.Sprintf("not ready when ctx ended (last answer: %s): %v", e.Last, e.Err)
}
func (e *NotReadyError) Unwrap() error { return e.Err }

// Final wraps a check error that ends Await at once: the fact can no longer
// become true (a container that is not running will never be ready).
type Final struct{ Err error }

func (f *Final) Error() string { return f.Err.Error() }
func (f *Final) Unwrap() error { return f.Err }

// Await returns nil once check answers true. It returns p.ExitError() as soon
// as the process exits, a check's *Final error at once, and a *NotReadyError
// naming the last answer if ctx ends first. noted, when set, is called each
// time the answer changes. A nil p is a wait on something that is not a local
// process (a container), so only the check and ctx can end it.
//
// No check carries a timeout of its own: each runs under a ctx that ends when
// the caller's ctx does or when the process exits, which are the two facts
// that can make an answer never come. The watcher goroutine is joined before
// Await returns.
func Await(ctx context.Context, p *Proc, check Check, noted func(last string)) error {
	var exited <-chan struct{} // nil: never closes
	if p != nil {
		exited = p.Exited()
	}
	reqCtx, cancel := context.WithCancel(ctx)
	watched := make(chan struct{})
	defer func() {
		cancel()
		<-watched
	}()
	go func() {
		defer close(watched)
		select {
		case <-exited:
			cancel()
		case <-reqCtx.Done():
		}
	}()

	last := "no answer yet"
	ticker := time.NewTicker(recheckInterval)
	defer ticker.Stop()
	for {
		ok, status, err := check(reqCtx)
		if ok {
			return nil
		}
		var final *Final
		if errors.As(err, &final) {
			return final.Err
		}
		// A request cut short because the process exited or ctx ended says
		// nothing about the process; keep the answer before it.
		if reqCtx.Err() == nil {
			now := status
			if err != nil {
				now = err.Error()
			}
			if now != last {
				last = now
				if noted != nil {
					noted(last)
				}
			}
		}
		select {
		case <-exited:
			return p.ExitError()
		default:
		}
		select {
		case <-exited:
			return p.ExitError()
		case <-ctx.Done():
			return &NotReadyError{Last: last, Err: ctx.Err()}
		case <-ticker.C:
		}
	}
}

// FreePort asks the kernel for a free loopback port and releases it for a
// child to bind. Another process can take it in between; the child then
// exits with "address already in use", which its harness reports. It is
// never retried. A child that can bind port 0 and report what it bound needs
// none of this.
func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("free port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return 0, fmt.Errorf("free port: %w", err)
	}
	return port, nil
}

// lineLog reads one stream: each line goes to the logger at DEBUG and to the
// watcher, and the last keep lines are kept for an error. It is deliberately
// not an io.Writer: one reader goroutine owns each stream, and tail is read
// after the process exits.
type lineLog struct {
	log    *slog.Logger
	name   string
	source string
	stream string
	keep   int
	watch  func(string)
	// gate, when set, is waited on before each line is read.
	gate Gate

	mu    sync.Mutex
	lines []string
}

func newLineLog(spec Spec, stream string, keep int) *lineLog {
	return &lineLog{log: spec.Logger, name: spec.Name, source: spec.Source, stream: stream, keep: keep, watch: spec.Watch}
}

// consume reads r to EOF, a line at a time, however long a line is. A last
// line with no newline is still a line.
func (l *lineLog) consume(r io.Reader) {
	br := bufio.NewReader(r)
	for {
		if l.gate != nil {
			l.gate.Wait()
		}
		line, err := br.ReadString('\n')
		if line != "" {
			l.emit(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				// The rest of this stream is lost: the DEBUG lines stop and
				// the tail an exit error carries is cut short. Say so.
				l.log.Warn(l.name+" output read failed", "source", l.source, "stream", l.stream, "err", err)
			}
			return
		}
	}
}

func (l *lineLog) emit(line string) {
	l.log.Debug(l.name+" output", "source", l.source, "stream", l.stream, "line", line)
	if l.watch != nil {
		l.watch(line)
	}
	if l.keep == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
	if len(l.lines) > l.keep {
		l.lines = l.lines[len(l.lines)-l.keep:]
	}
}

// tail is the kept lines joined with " | ".
func (l *lineLog) tail() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) == 0 {
		return "(none)"
	}
	return strings.Join(l.lines, " | ")
}
