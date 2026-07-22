package bmc

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// pipePort is a busPort double with realistic read timing: Read blocks
// for data up to a quiet window, then returns io.EOF — the same shape
// as the real VTIME behavior, so the SoL reader loop behaves as it
// does on hardware instead of hot-spinning.
type pipePort struct {
	mu       sync.Mutex
	wrote    bytes.Buffer
	in       chan []byte
	leftover []byte
	quiet    time.Duration
}

func newPipePort() *pipePort {
	return &pipePort{in: make(chan []byte, 16), quiet: 200 * time.Millisecond}
}

func (p *pipePort) Read(b []byte) (int, error) {
	p.mu.Lock()
	if len(p.leftover) > 0 {
		n := copy(b, p.leftover)
		p.leftover = p.leftover[n:]
		p.mu.Unlock()
		return n, nil
	}
	p.mu.Unlock()
	select {
	case d := <-p.in:
		n := copy(b, d)
		if n < len(d) {
			p.mu.Lock()
			p.leftover = append(p.leftover, d[n:]...)
			p.mu.Unlock()
		}
		return n, nil
	case <-time.After(p.quiet):
		return 0, io.EOF
	}
}

func (p *pipePort) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wrote.Write(b)
}

func (p *pipePort) Close() error { return nil }

func (p *pipePort) DrainInput() error {
	p.mu.Lock()
	p.leftover = nil
	p.mu.Unlock()
	for {
		select {
		case <-p.in:
		default:
			return nil
		}
	}
}

func (p *pipePort) written() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wrote.String()
}

// awaitWrite waits until the port has seen substr (beyond offset) and
// returns the new total length — lets tests order feeds against writes.
func awaitWrite(t *testing.T, p *pipePort, offset int, substr string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		w := p.written()
		if idx := strings.Index(w[offset:], substr); idx >= 0 {
			return offset + idx + len(substr)
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("port never saw %q after offset %d; wrote: %q", substr, offset, p.written())
	return 0
}

func awaitOut(t *testing.T, s SOL, want string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	var got []byte
	for {
		select {
		case b, ok := <-s.Out():
			if !ok {
				t.Fatalf("Out closed while waiting for %q (got %q)", want, got)
			}
			got = append(got, b...)
			if strings.Contains(string(got), want) {
				return
			}
		case <-deadline:
			t.Fatalf("no %q on Out within budget (got %q)", want, got)
		}
	}
}

func newSOLBackend(t *testing.T) (*BitScopeBackend, *pipePort) {
	t.Helper()
	port := newPipePort()
	targets := map[string]bitscopeTarget{
		"node-a1": {pos: "A-1", addr: 0x01},
		"node-f3": {pos: "F-3", addr: 0x17},
	}
	b := newBitScope(port, targets, bitscopeDefaultUnlock)
	b.settle = 0
	t.Cleanup(func() { _ = b.Close() })
	return b, port
}

func TestBitScopeSOL_BridgesBothDirections(t *testing.T) {
	b, port := newSOLBackend(t)
	s, err := b.OpenSOL(context.Background(), "node-a1", "sess-1")
	if err != nil {
		t.Fatalf("OpenSOL: %v", err)
	}
	off := awaitWrite(t, port, 0, "01|~")

	// target → operator
	port.in <- []byte("login: ")
	awaitOut(t, s, "login: ")

	// operator → target
	if err := s.Write([]byte("root\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	awaitWrite(t, port, off, "root\n")

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	awaitWrite(t, port, off, string(bitscopeConsoleExit))
	if _, ok := <-s.Out(); ok {
		// drain until closed
		for range s.Out() {
		}
	}
	if err := s.Write([]byte("x")); err == nil {
		t.Error("Write after Close must error")
	}
}

func TestBitScopeSOL_BusWideTakeover(t *testing.T) {
	// D-5: one session per BUS — opening a console on a different
	// target closes the existing one with a notice frame.
	b, port := newSOLBackend(t)
	s1, err := b.OpenSOL(context.Background(), "node-a1", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	off := awaitWrite(t, port, 0, "01|~")

	s2, err := b.OpenSOL(context.Background(), "node-f3", "sess-2")
	if err != nil {
		t.Fatalf("takeover open: %v", err)
	}
	awaitWrite(t, port, off, "17|~")

	// s1 gets the notice, then closes.
	awaitOut(t, s1, "taken over")
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-s1.Out():
			if !ok {
				goto s1closed
			}
		case <-deadline:
			t.Fatal("s1.Out never closed after takeover")
		}
	}
s1closed:
	if err := s1.Write([]byte("x")); err == nil {
		t.Error("old session Write must error after takeover")
	}
	// Old session's Close is a harmless no-op now.
	if err := s1.Close(); err != nil {
		t.Errorf("stale Close: %v", err)
	}

	// s2 is live.
	port.in <- []byte("f3 console")
	awaitOut(t, s2, "f3 console")
}

func TestBitScopeSOL_PowerVerbInterruptsAndResumes(t *testing.T) {
	// Design doc §3: a verb suspends the bridge (console exit), runs,
	// and the console reopens — even for a verb on a different target.
	b, port := newSOLBackend(t)
	s, err := b.OpenSOL(context.Background(), "node-a1", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	off := awaitWrite(t, port, 0, "01|~")

	type res struct {
		state proto.BMCPowerState
		err   error
	}
	done := make(chan res, 1)
	go func() {
		st, _, perr := b.Power(context.Background(), "node-f3", proto.BMCPowerOff)
		done <- res{st, perr}
	}()

	// Suspend: console exit escape, then the verb on the other target.
	off = awaitWrite(t, port, off, string(bitscopeConsoleExit))
	off = awaitWrite(t, port, off, `17|\`)
	// Status re-read: feed the reply inside the quiet window.
	off = awaitWrite(t, port, off, "17|=")
	port.in <- []byte("OFF")

	r := <-done
	if r.err != nil {
		t.Fatalf("Power during console: %v", r.err)
	}
	if r.state != proto.BMCStateOff {
		t.Errorf("state: %q, want off", r.state)
	}

	// Resume: console reopened on its original target...
	off = awaitWrite(t, port, off, "01|~")
	// ...and still bridging.
	port.in <- []byte("still here")
	awaitOut(t, s, "still here")
	_ = off
}

func TestBitScopeSOL_BackendCloseFinishesSession(t *testing.T) {
	b, _ := newSOLBackend(t)
	s, err := b.OpenSOL(context.Background(), "node-a1", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("backend Close: %v", err)
	}
	awaitOut(t, s, "shutting down")
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-s.Out():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("Out never closed after backend Close")
		}
	}
}
