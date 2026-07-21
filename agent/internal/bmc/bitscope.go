package bmc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// BitScopeBackend ("bitscope") drives the BitScope CB04B blade BMCs over
// the ER24A rack's RS-485 control bus, reached through the BMC-host
// (manager) Pi's serial port — the Pi's primary UART is internally wired
// to its BMC, and the rack busses all six blades so one manager reaches
// all 24 nodes. Design: design/control-plane/bmc-bitscope.md.
//
// Protocol (BitScope "I/O System" BIOS — proprietary single-character
// verbs at 115,200 8N1, no flow control): power on '/', power off '\'
// (hard cut — there is no reset line, so cycle and reset are both
// off→settle→on per decision D-1), status '=' (reports OFF / ENABLED /
// DISABLED, decoded per D-2), addressing by geographic bus id
// (busID = 4·row + slot, hex 00–17) via the "<addr>|" pipe, bus locked
// until the unlock sequence is sent.
//
// Byte-level framing (addressing pipe syntax, unlock handshake, status
// reply strings, cycle settle time) is asserted from BitScope's docs and
// NOT yet hardware-validated — the bench checklist is design doc §9.
// The decode is deliberately substring-based so framing details can't
// break the state mapping.
//
// Concurrency: a mutex serializes every bus command (the bus is one
// shared serial line). When SoL lands this grows into the design doc §3
// bus-owner goroutine so power verbs can interrupt an open console.
type BitScopeBackend struct {
	mu      sync.Mutex
	port    busPort
	targets map[string]bitscopeTarget
	unlock  []byte
	// settle is the off→on delay inside cycle/reset. Bench-tune.
	settle time.Duration
	// readBudget caps one command's reply collection even if a noisy
	// bus never goes quiet.
	readBudget time.Duration
}

// bitscopeTarget is one row of the address map, resolved.
type bitscopeTarget struct {
	pos  string
	addr byte
	// serial is the Pi serial recorded for the slot. Unused until the
	// bmc-targets advertisement lands (inventory cross-check, §2d).
	serial string
}

// busPort is the serial transport under the driver: Linux termios in
// production (bitscope_port_linux.go), a scripted fake in tests. Read
// must return io.EOF when the line has gone quiet (VTIME timeout).
type busPort interface {
	io.ReadWriteCloser
	// DrainInput discards stale unread bytes ahead of a fresh command.
	DrainInput() error
}

const (
	bitscopeDefaultDev    = "/dev/serial0"
	bitscopeDefaultUnlock = "UnLockMe"
	bitscopeDefaultMap    = "bitscope-map.json"
	bitscopeSettle        = 2 * time.Second
	bitscopeReadBudget    = 2 * time.Second

	bitscopeVerbOn     = '/'
	bitscopeVerbOff    = '\\'
	bitscopeVerbStatus = '='
)

// NewBitScopeBackend loads the address map, opens the serial bus, and
// unlocks it. Zero-value Config fields select the documented defaults
// (dev /dev/serial0, the EEPROM-default unlock sequence per D-4, map at
// <StateDir>/bitscope-map.json).
func NewBitScopeBackend(cfg Config) (*BitScopeBackend, error) {
	dev := cfg.BitScopeDev
	if dev == "" {
		dev = bitscopeDefaultDev
	}
	unlock := cfg.BitScopeUnlock
	if unlock == "" {
		unlock = bitscopeDefaultUnlock
	}
	mapPath := cfg.BitScopeMap
	if mapPath == "" {
		mapPath = filepath.Join(cfg.StateDir, bitscopeDefaultMap)
	}
	targets, err := loadBitScopeMap(mapPath)
	if err != nil {
		return nil, err
	}
	port, err := openBitScopePort(dev)
	if err != nil {
		return nil, fmt.Errorf("bitscope: open %s: %w", dev, err)
	}
	b := newBitScope(port, targets, unlock)
	if err := b.unlockBus(); err != nil {
		_ = port.Close()
		return nil, err
	}
	return b, nil
}

// newBitScope wires a backend onto an already-open port without
// touching the bus. Tests inject a fake port here.
func newBitScope(port busPort, targets map[string]bitscopeTarget, unlock string) *BitScopeBackend {
	return &BitScopeBackend{
		port:       port,
		targets:    targets,
		unlock:     []byte(unlock),
		settle:     bitscopeSettle,
		readBudget: bitscopeReadBudget,
	}
}

func (b *BitScopeBackend) Name() string { return "bitscope" }

// unlockBus sends the unlock sequence and drains whatever the bus says
// back. The bus powers up locked; one unlock per open session.
func (b *BitScopeBackend) unlockBus() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.port.DrainInput(); err != nil {
		return fmt.Errorf("bitscope: unlock drain: %w", err)
	}
	if _, err := b.port.Write(b.unlock); err != nil {
		return fmt.Errorf("bitscope: unlock write: %w", err)
	}
	_, err := b.readReply(context.Background())
	if err != nil {
		return fmt.Errorf("bitscope: unlock reply: %w", err)
	}
	return nil
}

func (b *BitScopeBackend) Power(ctx context.Context, target string, verb proto.BMCPowerVerb) (proto.BMCPowerState, string, error) {
	t, ok := b.targets[target]
	if !ok {
		return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: node %q not in the address map", target)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var detail string
	switch verb {
	case proto.BMCPowerOn:
		if _, err := b.command(ctx, t.addr, bitscopeVerbOn); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "powered on"
	case proto.BMCPowerOff:
		if _, err := b.command(ctx, t.addr, bitscopeVerbOff); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "powered off (hard cut)"
	case proto.BMCPowerCycle, proto.BMCPowerReset:
		if _, err := b.command(ctx, t.addr, bitscopeVerbOff); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		select {
		case <-time.After(b.settle):
		case <-ctx.Done():
			return proto.BMCStateUnknown, "", ctx.Err()
		}
		if _, err := b.command(ctx, t.addr, bitscopeVerbOn); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		if verb == proto.BMCPowerReset {
			// D-1: reset maps to a hard power-cycle; say so.
			detail = "hard power-cycle (CB04B has no reset line)"
		} else {
			detail = "hard power-cycled"
		}
	case proto.BMCPowerQuery:
		detail = "queried"
	default:
		return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: unsupported verb %q", verb)
	}

	// The ack reports post-op reality, not the verb's intent: re-read
	// status and decode (design doc §2b).
	reply, err := b.command(ctx, t.addr, bitscopeVerbStatus)
	if err != nil {
		return proto.BMCStateUnknown, "", err
	}
	state, stateDetail, err := decodeBitScopeState(reply)
	if err != nil {
		return proto.BMCStateUnknown, "", err
	}
	if stateDetail != "" {
		detail += "; " + stateDetail
	}
	return state, detail, nil
}

// OpenSOL is the next backlog item (design doc §2c) — the console
// bridge needs the §3 bus-owner goroutine first.
func (b *BitScopeBackend) OpenSOL(_ context.Context, target, _ string) (SOL, error) {
	return nil, fmt.Errorf("bitscope: SoL for %s not implemented yet (bmc-bitscope backlog)", target)
}

// Close releases the serial port.
func (b *BitScopeBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.port.Close()
}

// command addresses one target and issues one BIOS verb: drain stale
// bytes, write "<addr>|<verb>", collect the reply until the line goes
// quiet. Caller holds b.mu.
func (b *BitScopeBackend) command(ctx context.Context, addr byte, verb byte) (string, error) {
	if err := b.port.DrainInput(); err != nil {
		return "", fmt.Errorf("bitscope: drain: %w", err)
	}
	cmd := fmt.Sprintf("%02x|%c", addr, verb)
	if _, err := b.port.Write([]byte(cmd)); err != nil {
		return "", fmt.Errorf("bitscope: write %q: %w", cmd, err)
	}
	return b.readReply(ctx)
}

// readReply collects bytes until the port reports quiet (io.EOF from
// the VTIME timeout), the read budget expires, or ctx is done.
func (b *BitScopeBackend) readReply(ctx context.Context) (string, error) {
	var out []byte
	buf := make([]byte, 256)
	deadline := time.Now().Add(b.readBudget)
	for {
		if err := ctx.Err(); err != nil {
			return string(out), err
		}
		if time.Now().After(deadline) {
			return string(out), nil
		}
		n, err := b.port.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if err == io.EOF {
				return string(out), nil
			}
			return string(out), fmt.Errorf("bitscope: read: %w", err)
		}
	}
}

// decodeBitScopeState maps a status reply onto the proto power states.
// Substring-based on purpose: exact reply framing is a bench-validation
// item, the state words are not. Per D-2, DISABLED decodes to off with
// the raw fact disclosed in the detail; unknown is reserved for a reply
// that names no state at all.
func decodeBitScopeState(reply string) (proto.BMCPowerState, string, error) {
	up := strings.ToUpper(reply)
	switch {
	case strings.Contains(up, "DISABLED"):
		return proto.BMCStateOff, "disabled", nil
	case strings.Contains(up, "ENABLED"):
		return proto.BMCStateOn, "", nil
	case strings.Contains(up, "OFF"):
		return proto.BMCStateOff, "", nil
	}
	return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: unparseable status reply %q", strings.TrimSpace(reply))
}

// bitscopeMapFile is the on-disk address map (design doc §2d): pos is
// authoritative, the bus address is derived so it can't drift from the
// rack's geographic reality.
type bitscopeMapFile struct {
	Targets []struct {
		Pos    string `json:"pos"`
		NodeID string `json:"node_id"`
		Serial string `json:"serial,omitempty"`
	} `json:"targets"`
}

func loadBitScopeMap(path string) (map[string]bitscopeTarget, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bitscope: address map: %w", err)
	}
	var mf bitscopeMapFile
	if err := json.Unmarshal(buf, &mf); err != nil {
		return nil, fmt.Errorf("bitscope: address map %s: %w", path, err)
	}
	if len(mf.Targets) == 0 {
		return nil, fmt.Errorf("bitscope: address map %s: no targets", path)
	}
	targets := make(map[string]bitscopeTarget, len(mf.Targets))
	seenPos := make(map[byte]string, len(mf.Targets))
	for _, t := range mf.Targets {
		if t.NodeID == "" {
			return nil, fmt.Errorf("bitscope: address map %s: entry %q missing node_id", path, t.Pos)
		}
		addr, err := parseBitScopePos(t.Pos)
		if err != nil {
			return nil, fmt.Errorf("bitscope: address map %s: %w", path, err)
		}
		if other, dup := seenPos[addr]; dup {
			return nil, fmt.Errorf("bitscope: address map %s: pos %s duplicates %s", path, t.Pos, other)
		}
		seenPos[addr] = t.Pos
		if _, dup := targets[t.NodeID]; dup {
			return nil, fmt.Errorf("bitscope: address map %s: duplicate node_id %q", path, t.NodeID)
		}
		targets[t.NodeID] = bitscopeTarget{pos: t.Pos, addr: addr, serial: t.Serial}
	}
	return targets, nil
}

// parseBitScopePos turns a rack position ("A-0" … "F-3", case-
// insensitive) into its geographic bus address: busID = 4·row + slot.
func parseBitScopePos(pos string) (byte, error) {
	p := strings.ToUpper(strings.TrimSpace(pos))
	if len(p) != 3 || p[1] != '-' {
		return 0, fmt.Errorf("bad pos %q (want ROW-SLOT, e.g. A-0)", pos)
	}
	row, slot := p[0], p[2]
	if row < 'A' || row > 'F' {
		return 0, fmt.Errorf("bad pos %q: row %c outside A-F", pos, row)
	}
	if slot < '0' || slot > '3' {
		return 0, fmt.Errorf("bad pos %q: slot %c outside 0-3", pos, slot)
	}
	return 4*(row-'A') + (slot - '0'), nil
}
