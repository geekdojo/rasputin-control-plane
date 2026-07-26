package bmc

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// Serial-over-LAN for the BitScope backend (design doc §2c/§3, D-5).
//
// The manager has ONE serial line multiplexing all 24 targets, so SoL
// concurrency is bus-wide single-session — deliberately stricter than
// the parent contract's per-target single-writer rule:
//
//   - A new OpenSOL on ANY target takes over the existing session, even
//     one bridged to a different node. The old session gets a notice
//     frame and closes; take-over (vs refuse) wins because a dead
//     browser tab must never lock the console.
//   - Power verbs interrupt an open console at command boundaries: the
//     bridge is suspended (console-exit escape), the verb runs, and the
//     console reopens. The operator sees a brief scrollback gap — the
//     contract already accepts drops under backpressure.
//
// The §3 "bus owner" is realized as the existing command mutex plus a
// pausable reader goroutine: exactly one party touches the serial line
// at any time (the reader between commands, the mutex holder during
// them), which is the invariant the design names.
//
// Console mechanics (control-plane manual "Console Port", corrected on
// the bench 2026-07-26 — the original ESC-exit assumption was wrong and
// wedged the bus):
//
//   - Open = pipe first, then '~' THROUGH the pipe with the baud code
//     in vmInput — the manual's exact form: "[7e]|[03]~". "[<addr>]|"
//     attaches the slave, "[00]~" tells the slave's BIOS to open its
//     console at 115,200 (00 115k · 01 9k6 · 02 19k2 · 03 56k7). The
//     bracketed entry matters: '[' commences data entry and CLEARS
//     vmInput — bare digits after the pipe demonstrably did not load
//     the slave's baud register on the bench (silent console), while
//     the bracketed open bridged bidirectionally at full fidelity.
//   - Exit = ^G, the one byte the master interprets while a pipe is
//     open: it closes the pipe, and "the console is closed when the
//     pipe (on the master) is closed."
//
// §9 STILL PENDING: the mute-mode reopen for a flooding target is not
// yet wired (open-mute = same open with a hold-off count specifier —
// the manual's "gone rogue" recovery), and cycle settle is untuned.

const bitscopeVerbConsole = '~'

// bitscopeConsoleBaud115k is the vmInput baud code forwarded with '~':
// 115,200, matching the target images' serial getty.
const bitscopeConsoleBaud115k = "00"

// bitscopeConsoleExit closes the command pipe (^G), which closes the
// slave's console with it. Documented in the control-plane manual and
// validated live 2026-07-26 (recovered a wedged bus).
var bitscopeConsoleExit = []byte{bitscopePipeClose}

// bitscopeSOL is the one live console session on the bus.
type bitscopeSOL struct {
	b      *BitScopeBackend
	id     string
	target string
	addr   byte
	out    chan []byte
	closed chan struct{}

	closeOnce sync.Once
}

func (s *bitscopeSOL) SessionID() string  { return s.id }
func (s *bitscopeSOL) Out() <-chan []byte { return s.out }

// Write sends operator bytes toward the bridged target. It serializes
// against power verbs via the bus mutex, so keystrokes queue behind an
// in-flight verb rather than interleaving into the BIOS.
func (s *bitscopeSOL) Write(p []byte) error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	if s.b.sol != s {
		return fmt.Errorf("bitscope: console session closed")
	}
	if _, err := s.b.port.Write(p); err != nil {
		return fmt.Errorf("bitscope: console write: %w", err)
	}
	return nil
}

func (s *bitscopeSOL) Close() error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	if s.b.sol == s {
		s.b.teardownSOLLocked(s, "")
	}
	return nil
}

// finish emits an optional final notice and closes the out channel —
// exactly once, whichever of Close/take-over/backend-Close gets there
// first.
func (s *bitscopeSOL) finish(notice string) {
	s.closeOnce.Do(func() {
		if notice != "" {
			select {
			case s.out <- []byte("\r\n*** " + notice + "\r\n"):
			default:
			}
		}
		close(s.closed)
		close(s.out)
	})
}

// OpenSOL bridges the target's serial console (address pipe + '~').
// Bus-wide single-session: an existing console — on any target — is
// taken over with a notice frame (D-5).
func (b *BitScopeBackend) OpenSOL(_ context.Context, target, sessionID string) (SOL, error) {
	t, ok := b.targets[target]
	if !ok {
		return nil, fmt.Errorf("bitscope: node %q not in the address map", target)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sol != nil {
		b.teardownSOLLocked(b.sol, "console taken over: session opened on "+target)
	}

	if err := b.port.DrainInput(); err != nil {
		return nil, fmt.Errorf("bitscope: console drain: %w", err)
	}
	if _, err := b.port.Write([]byte(bitscopeConsoleOpen(t.addr))); err != nil {
		return nil, fmt.Errorf("bitscope: console open: %w", err)
	}

	s := &bitscopeSOL{
		b:      b,
		id:     sessionID,
		target: target,
		addr:   t.addr,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	b.sol = s
	b.reader = startSOLReader(b.port, s)
	return s, nil
}

// teardownSOLLocked stops the reader, exits console mode, and finishes
// the session. Caller holds b.mu.
func (b *BitScopeBackend) teardownSOLLocked(s *bitscopeSOL, notice string) {
	if b.reader != nil {
		b.reader.stopAndWait()
		b.reader = nil
	}
	_, _ = b.port.Write(bitscopeConsoleExit)
	_ = b.port.DrainInput()
	b.sol = nil
	s.finish(notice)
}

// suspendConsoleLocked pauses the bridge around a power verb and
// returns the resume func (reopen the console on its target). No-op
// when no console is open. Caller holds b.mu for the whole span.
func (b *BitScopeBackend) suspendConsoleLocked() func() {
	if b.sol == nil {
		return func() {}
	}
	sol := b.sol
	b.reader.pause()
	_, _ = b.port.Write(bitscopeConsoleExit)
	_ = b.port.DrainInput()
	return func() {
		if b.sol != sol {
			return
		}
		_, _ = b.port.Write([]byte(bitscopeConsoleOpen(sol.addr)))
		b.reader.resume()
	}
}

// bitscopeConsoleOpen is the full console-open write for one target:
// attach the slave's pipe, then the baud code + '~' forwarded to its
// BIOS ("[02]|[00]~" = console on node 02 at 115,200 — bench-validated
// bidirectionally 2026-07-26).
func bitscopeConsoleOpen(addr byte) string {
	return fmt.Sprintf("[%02x]|[%s]%c", addr, bitscopeConsoleBaud115k, bitscopeVerbConsole)
}

// solReader owns the serial line between commands, pumping console
// bytes into the session. Power verbs pause it at a read boundary
// (reads block at most the VTIME quiet window, so pause latency is
// bounded); teardown stops it.
type solReader struct {
	pauseReq  chan struct{}
	pausedAck chan struct{}
	resumeCh  chan struct{}
	stop      chan struct{}
	done      chan struct{}
}

func startSOLReader(port busPort, s *bitscopeSOL) *solReader {
	r := &solReader{
		pauseReq:  make(chan struct{}),
		pausedAck: make(chan struct{}),
		resumeCh:  make(chan struct{}),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go func() {
		defer close(r.done)
		buf := make([]byte, 512)
		for {
			select {
			case <-r.stop:
				return
			case <-r.pauseReq:
				r.pausedAck <- struct{}{}
				select {
				case <-r.resumeCh:
				case <-r.stop:
					return
				}
			default:
			}
			n, err := port.Read(buf)
			if n > 0 {
				data := append([]byte(nil), buf[:n]...)
				select {
				case s.out <- data:
				default:
					// Backpressure: a noisy console must not block the
					// bus — drop, same policy as the api's WS relay.
				}
			}
			if err != nil {
				if err == io.EOF {
					continue // VTIME quiet window — keep listening
				}
				return // port error: the session goes quiet; operator reopens
			}
		}
	}()
	return r
}

// pause parks the reader at its next read boundary and returns once it
// has yielded the port. Pair with resume; callers hold b.mu, so pause
// cycles never overlap.
func (r *solReader) pause() {
	r.pauseReq <- struct{}{}
	<-r.pausedAck
}

func (r *solReader) resume() {
	r.resumeCh <- struct{}{}
}

func (r *solReader) stopAndWait() {
	close(r.stop)
	<-r.done
}
