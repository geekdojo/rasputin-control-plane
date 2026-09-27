package bmc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
// off→settle→on per decision D-1), status '=' (five-field reply, see
// decodeBitScopeState; state tokens mapped per D-2), addressing by
// geographic bus id (busID = 4·row + slot, hex 00–17) via the
// "<addr>|" pipe, bus locked until the unlock sequence is sent.
//
// PIPE DISCIPLINE (control-plane manual "Command Pipe", learned the
// hard way on the bench 2026-07-26): "<addr>|" ATTACHES the slave —
// after that, every byte except ^G is forwarded to it, including the
// next command's "<addr>|" prefix. A pipe left open therefore wedges
// the whole bus: verbs stop being interpreted by the master and vanish
// into the attached slave. Every command must end by closing its pipe
// with ^G, and unlock defensively closes any pipe a previous holder
// left behind.
//
// HARDWARE-VALIDATED 2026-07-22 (first live rack contact, c02→c05 on
// the ER24A): unlock handshake, addressing-pipe syntax, command-echo
// framing, and the `=` reply format all confirmed. 2026-07-26: ^G
// pipe-close/recovery confirmed live (wedged bus answered `=` again
// right after ^G). Remaining §9 items: cycle settle time, mute-mode
// reopen.
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

	// sol is the one live console session on the bus (D-5: bus-wide
	// single-session); reader pumps its bytes between commands. Both
	// guarded by mu. See bitscope_sol.go.
	sol    *bitscopeSOL
	reader *solReader
}

// bitscopeTarget is one row of the address map, resolved.
type bitscopeTarget struct {
	pos  string
	addr byte
	// nodeID is the map key this row was looked up by. Set by Power, for
	// logs and errors; empty on a row still sitting in the map.
	nodeID string
	// serial is the Pi serial recorded for the slot. It is stored and NOT
	// checked: nothing this driver reads from the bus can be compared with
	// it. The BMC identifies itself by its own UUID (the `#` verb), which
	// is not the Pi's serial, and no reply format for `#` has been captured.
	// So "is the node at this address the node named" is not something the
	// driver can answer. What answers it is the control plane: a reset or
	// cycle is accepted only when the NAMED node comes back on a new boot
	// (api/internal/bmc), which a wrong row in this map cannot satisfy.
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
	// bitscopeDefaultDev is the Pi's 40-pin-header UART AS RASPUTIN OS
	// NAMES IT. It was /dev/serial0 until 2026-07-29 — the Raspberry Pi
	// OS alias BitScope's own documentation uses, inherited from the
	// vendor's docs before this driver had ever run on the appliance
	// image. The appliance is Buildroot and ships no udev rules at all,
	// so that alias does not exist on any node Rasputin builds: the
	// default could never open a bus, on any cluster, ever. The bench
	// hid it by typing the right value into the Settings form.
	//
	// If the header UART is later moved to the PL011 (the open
	// disable-bt decision on the os side), this becomes ttyAMA0 and the
	// same reasoning applies: the default names the device the shipped
	// image actually has.
	bitscopeDefaultDev    = "/dev/ttyS0"
	bitscopeDefaultUnlock = "UnLockMe"
	bitscopeDefaultMap    = "bitscope-map.json"
	bitscopeSettle        = 2 * time.Second
	bitscopeReadBudget    = 2 * time.Second

	bitscopeVerbOn     = '/'
	bitscopeVerbOff    = '\\'
	bitscopeVerbStatus = '='

	// bitscopePipeClose (^G, BEL) closes an open command pipe: the
	// attached slave detaches and — if its console is open — the console
	// closes with it. The one byte the master always interprets itself.
	bitscopePipeClose = '\a'
)

// NewBitScopeBackend loads the address map, opens the serial bus, and
// unlocks it. Zero-value Config fields select the documented defaults
// (dev /dev/ttyS0, the EEPROM-default unlock sequence per D-4, map at
// <StateDir>/bitscope-map.json).
func NewBitScopeBackend(cfg Config) (*BitScopeBackend, error) {
	dev, unlock, mapPath := bitscopeSettings(cfg)
	targets, err := loadBitScopeMap(mapPath)
	if err != nil {
		return nil, err
	}
	return newBitScopeOnDevice(dev, unlock, targets)
}

// newBitScopeOnDevice opens and unlocks the bus for an already-resolved
// target map — shared by the env path (file map) and the settings path
// (inline map, selection.go).
func newBitScopeOnDevice(dev, unlock string, targets map[string]bitscopeTarget) (*BitScopeBackend, error) {
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

// bitscopeSettings resolves the driver's Config fields to their
// documented defaults (design doc §2a).
func bitscopeSettings(cfg Config) (dev, unlock, mapPath string) {
	dev = cfg.BitScopeDev
	if dev == "" {
		dev = bitscopeDefaultDev
	}
	unlock = cfg.BitScopeUnlock
	if unlock == "" {
		unlock = bitscopeDefaultUnlock
	}
	mapPath = cfg.BitScopeMap
	if mapPath == "" {
		mapPath = filepath.Join(cfg.StateDir, bitscopeDefaultMap)
	}
	return dev, unlock, mapPath
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

// Targets lists the address map's node-ids, sorted — the authoritative
// bmc-targets advertisement (design doc §2d). The map is immutable after
// construction, so no lock is needed.
func (b *BitScopeBackend) Targets() []proto.BMCTarget {
	ids := make([]string, 0, len(b.targets))
	for id := range b.targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]proto.BMCTarget, 0, len(ids))
	for _, id := range ids {
		// A real serial line: raw bytes both directions, and nothing
		// discards output behind our back. Reset is a synthesized hard
		// power-cycle (D-1) but it is honoured, so it is advertised.
		out = append(out, proto.BMCTarget{
			NodeID:  id,
			Caps:    []string{proto.BMCCapPower, proto.BMCCapReset, proto.BMCCapConsole},
			Console: &proto.BMCConsoleInfo{Mode: proto.BMCConsoleCharacter},
		})
	}
	return out
}

// unlockBus readies the bus for commands: close any pipe a previous
// holder left open (a stale pipe forwards everything to its slave and
// the bus looks dead — the 2026-07-26 bench wedge), send the unlock
// sequence, then prove local command mode with a bare `=` — the master
// must answer its own five-field status. Failing that check here turns
// "backend came up but every verb returns nothing" into a construction
// error the operator actually sees.
func (b *BitScopeBackend) unlockBus() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.port.Write([]byte{bitscopePipeClose}); err != nil {
		return fmt.Errorf("bitscope: pipe-close write: %w", err)
	}
	if err := b.port.DrainInput(); err != nil {
		return fmt.Errorf("bitscope: unlock drain: %w", err)
	}
	if _, err := b.port.Write(b.unlock); err != nil {
		return fmt.Errorf("bitscope: unlock write: %w", err)
	}
	if _, err := b.readReply(context.Background()); err != nil {
		return fmt.Errorf("bitscope: unlock reply: %w", err)
	}
	if _, err := b.port.Write([]byte{bitscopeVerbStatus}); err != nil {
		return fmt.Errorf("bitscope: status probe write: %w", err)
	}
	reply, err := b.readReply(context.Background())
	if err != nil {
		return fmt.Errorf("bitscope: status probe reply: %w", err)
	}
	if !bitscopeMasterStatus(reply) {
		return fmt.Errorf("bitscope: bus did not answer the local status probe (reply %q) — still locked, wedged, or not a BMC line", reply)
	}
	return nil
}

// bitscopeMasterStatus reports whether reply carries the master BMC's
// own status line: five fields with the MS field 00 (master). Anything
// else — silence, echo only, a slave's ff — means the bus is not in
// local command mode.
func bitscopeMasterStatus(reply string) bool {
	for _, line := range strings.Split(reply, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 5 && f[1] == "00" {
			return true
		}
	}
	return false
}

// Power performs verb on target and reports the state the BMC read back
// afterwards.
//
// WHAT IT CHECKS, and why it is more than it used to be
// (geekdojo/geekdojo-brain#617). A reset used to be: write off, wait, write
// on, read status — with the replies to off and on thrown away and the status
// checked only for carrying the address it was sent to. That sequence reports
// success whether or not the node lost power, so a reset that reset nothing
// was indistinguishable from one that worked. Now:
//
//   - every command's reply is read. A bus that returns NOTHING after a power
//     verb — not even the echo of the command — is an error, and so is an
//     echo that names a different address;
//   - cycle and reset read the status BETWEEN off and on and require it to say
//     off. "Still on after the off command" is reported as exactly that;
//   - every command is logged, with the node, its position and bus address,
//     what was written and what came back (logCommand).
//
// What it does not and cannot check is whether the node at the address is the
// node named; see bitscopeTarget.serial.
//
// A cycle or reset always runs to its end. Whatever went wrong with the off
// half, the on command is still sent, because the alternative is a driver
// that can leave a node powered off on the strength of its own doubt. The
// failure is reported after the node has been told to power on.
func (b *BitScopeBackend) Power(ctx context.Context, target string, verb proto.BMCPowerVerb) (proto.BMCPowerState, string, error) {
	t, ok := b.targets[target]
	if !ok {
		return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: node %q not in the address map", target)
	}
	t.nodeID = target

	b.mu.Lock()
	defer b.mu.Unlock()

	// An open console shares the one serial line: suspend the bridge
	// for the verb, reopen it after — even when the verb targets the
	// bridged node itself (power-cycling the node you're watching).
	resumeConsole := b.suspendConsoleLocked()
	defer resumeConsole()

	var detail string
	// problems collects what went wrong in a cycle or reset without stopping
	// it: see the doc comment for why the sequence always runs to its end.
	var problems []string
	switch verb {
	case proto.BMCPowerOn:
		if err := b.powerVerb(ctx, t, bitscopeVerbOn); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "powered on"
	case proto.BMCPowerOff:
		if err := b.powerVerb(ctx, t, bitscopeVerbOff); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "powered off (hard cut)"
	case proto.BMCPowerCycle, proto.BMCPowerReset:
		if err := b.powerVerb(ctx, t, bitscopeVerbOff); err != nil {
			problems = append(problems, err.Error())
		}
		// Did it actually lose power? The cut is immediate and the status
		// says so at once (bench 2026-07-23), so this needs no wait.
		mid, _, err := b.status(ctx, t)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("could not read its power state after the off command: %v", err))
		case mid != proto.BMCStateOff:
			problems = append(problems, fmt.Sprintf(
				"%s did NOT power off: its BMC reports %q after the off command", t, mid))
		}
		// The dwell with power removed. It bounds nothing and decides
		// nothing; it is how long the node stays off.
		select {
		case <-time.After(b.settle):
		case <-ctx.Done():
			problems = append(problems, fmt.Sprintf("interrupted before the on command: %v", ctx.Err()))
		}
		// Sent on a context of its own when ctx is already done: a node
		// must not be left off because the caller ran out of time.
		onCtx := ctx
		if ctx.Err() != nil {
			var cancel context.CancelFunc
			onCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), b.readBudget+time.Second)
			defer cancel()
		}
		if err := b.powerVerb(onCtx, t, bitscopeVerbOn); err != nil {
			problems = append(problems, err.Error())
		}
		if verb == proto.BMCPowerReset {
			// D-1: reset maps to a hard power-cycle; say so.
			detail = "hard power-cycle (CB04B has no reset line)"
		} else {
			detail = "hard power-cycled"
		}
		ctx = onCtx
	case proto.BMCPowerQuery:
		detail = "queried"
	default:
		return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: unsupported verb %q", verb)
	}

	// The ack reports post-op reality, not the verb's intent: re-read
	// status and decode (design doc §2b).
	state, stateDetail, err := b.status(ctx, t)
	if err != nil {
		if len(problems) > 0 {
			problems = append(problems, fmt.Sprintf("could not read its power state afterwards: %v", err))
			return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: %s of %s failed: %s", verb, t, strings.Join(problems, "; "))
		}
		return proto.BMCStateUnknown, "", err
	}
	if stateDetail != "" {
		detail += "; " + stateDetail
	}
	if len(problems) > 0 {
		return state, detail, fmt.Errorf("bitscope: %s of %s failed (its BMC now reports %q): %s",
			verb, t, state, strings.Join(problems, "; "))
	}
	return state, detail, nil
}

// String names a target the way an operator needs it named when something
// went to the wrong place: the node, where it sits, and the bus address that
// was actually written.
func (t bitscopeTarget) String() string {
	return fmt.Sprintf("node %q (pos %s, bus address %02x)", t.nodeID, t.pos, t.addr)
}

// powerVerb issues on or off and checks the reply. The reply to a power verb
// used to be discarded.
func (b *BitScopeBackend) powerVerb(ctx context.Context, t bitscopeTarget, verb byte) error {
	reply, err := b.command(ctx, t, verb)
	if err != nil {
		return err
	}
	return checkBitScopeEcho(t, verb, reply)
}

// status issues `=` and decodes the reply.
func (b *BitScopeBackend) status(ctx context.Context, t bitscopeTarget) (proto.BMCPowerState, string, error) {
	reply, err := b.command(ctx, t, bitscopeVerbStatus)
	if err != nil {
		return proto.BMCStateUnknown, "", err
	}
	return decodeBitScopeState(t.addr, reply)
}

// checkBitScopeEcho checks the reply to a power verb.
//
// What is known about that reply, and it is not much: the bus echoes the
// command it was given, as "<addr>|<verb>" (captured for `=` on the rack
// 2026-07-22: "04|=" ahead of the status line). This checks only what follows
// from that and nothing it would have to guess at:
//
//   - NOTHING came back. The bus is not hearing the command, or the bytes were
//     lost; either way the verb cannot be assumed to have taken effect.
//   - an echo came back naming a DIFFERENT address. The command went
//     somewhere other than where it was sent.
//
// Anything else — including a reply with no echo line in it — is accepted
// here and is in the journal (logCommand), because no capture exists of what
// a power verb's full reply looks like and refusing an unfamiliar one would
// be inventing protocol. Whether the verb WORKED is not decided here at all:
// the status read after it decides that.
func checkBitScopeEcho(t bitscopeTarget, verb byte, reply string) error {
	if strings.TrimSpace(reply) == "" {
		return fmt.Errorf("bitscope: the bus returned nothing after the %s command to %s — not even the echo of the command",
			bitscopeVerbName(verb), t)
	}
	for _, raw := range strings.FieldsFunc(reply, func(r rune) bool { return r == '\n' || r == '\r' }) {
		addrField, _, isEcho := strings.Cut(strings.TrimSpace(raw), "|")
		if !isEcho {
			continue
		}
		addrField = strings.Trim(addrField, "[] ")
		id, err := strconv.ParseUint(addrField, 16, 8)
		if err != nil {
			continue
		}
		if byte(id) != t.addr {
			return fmt.Errorf("bitscope: the %s command to %s was echoed for bus address %02x (reply %q)",
				bitscopeVerbName(verb), t, byte(id), strings.TrimSpace(reply))
		}
	}
	return nil
}

// bitscopeVerbName names a BIOS verb for logs and errors.
func bitscopeVerbName(verb byte) string {
	switch verb {
	case bitscopeVerbOn:
		return "on"
	case bitscopeVerbOff:
		return "off"
	case bitscopeVerbStatus:
		return "status"
	}
	return fmt.Sprintf("%q", verb)
}

// Close tears down any live console session and releases the port.
func (b *BitScopeBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sol != nil {
		b.teardownSOLLocked(b.sol, "console closed: BMC backend shutting down")
	}
	return b.port.Close()
}

// command addresses one target and issues one BIOS verb: drain stale
// bytes, write "[<addr>]|<verb>" (bracketed entry clears vmInput before
// the digits load it — the manual's canonical form), collect the reply
// until the line goes quiet, then CLOSE THE PIPE — "[<addr>]|" attached
// the slave, and a pipe left open swallows every subsequent command
// (pipe discipline, see the type comment). Caller holds b.mu.
//
// Every call writes one line to the journal, whatever the outcome.
func (b *BitScopeBackend) command(ctx context.Context, t bitscopeTarget, verb byte) (reply string, err error) {
	cmd := fmt.Sprintf("[%02x]|%c", t.addr, verb)
	sent := false
	defer func() { logBitScopeCommand(t, verb, cmd, sent, reply, err) }()

	if err := b.port.DrainInput(); err != nil {
		return "", fmt.Errorf("bitscope: drain: %w", err)
	}
	if _, err := b.port.Write([]byte(cmd)); err != nil {
		return "", fmt.Errorf("bitscope: write %q: %w", cmd, err)
	}
	sent = true
	reply, err = b.readReply(ctx)
	if _, cerr := b.port.Write([]byte{bitscopePipeClose}); cerr == nil {
		_ = b.port.DrainInput() // eat the pipe-close echo
	}
	return reply, err
}

// bitscopeLogReplyMax caps how much of a reply one log line carries. A status
// reply is about twenty bytes; this is for the bus that answers with noise.
const bitscopeLogReplyMax = 120

// logBitScopeCommand writes the one journal line a command gets: which node,
// where it sits, the bus address, the verb, exactly what was written and what
// came back. On success as well as on failure — until
// geekdojo/geekdojo-brain#617 the driver logged nothing when a command
// succeeded, so after a reset that reset the wrong thing the BMC host's
// journal could not say what had gone out on the wire.
//
// The unlock sequence is a secret and is never logged. It cannot reach this
// function: unlockBus writes it to the port directly, and the only bytes
// logged here are the address pipe and the verb.
func logBitScopeCommand(t bitscopeTarget, verb byte, wire string, sent bool, reply string, err error) {
	shown := reply
	if len(shown) > bitscopeLogReplyMax {
		shown = shown[:bitscopeLogReplyMax] + "…"
	}
	outcome := "sent"
	if !sent {
		outcome = "NOT sent"
	}
	line := fmt.Sprintf("rasputin-agent: bmc bitscope: %s verb=%s node=%q pos=%s addr=%02x wire=%q reply=%q",
		outcome, bitscopeVerbName(verb), t.nodeID, t.pos, t.addr, wire, shown)
	if err != nil {
		line += fmt.Sprintf(" error=%q", err.Error())
	}
	log.Print(line)
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

// decodeBitScopeState parses a `=` status reply. Wire format validated
// on the rack 2026-07-22 (first live capture: `04|=\n04 ff 1 26 98`)
// and matching the archived BitScope control-plane protocol doc: the
// bus echoes the issued command, then replies one line of five fields
//
//	ID MS XX YY ZZ
//
// ID = node address (hex 00–7f) · MS = 00 master / ff slave · XX =
// power-state token (0 OFF / 1 ENABLED / 2 DISABLED) · YY = current
// draw (U8) · ZZ = fan speed (U8). Token mapping per D-1/D-2:
// 1 → on; 0 → off; 2 → off with the "disabled" fact disclosed. The ID
// field is cross-checked against the addressed target so a mis-routed
// reply can never report another node's state as the target's.
func decodeBitScopeState(addr byte, reply string) (proto.BMCPowerState, string, error) {
	// The reply is the last non-empty, non-echo line (echoes carry the
	// `|` pipe character; status lines never do).
	var status string
	for _, raw := range strings.FieldsFunc(reply, func(r rune) bool { return r == '\n' || r == '\r' }) {
		l := strings.TrimSpace(raw)
		if l != "" && !strings.ContainsRune(l, '|') {
			status = l
		}
	}
	fields := strings.Fields(status)
	if len(fields) < 3 {
		return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: unparseable status reply %q", strings.TrimSpace(reply))
	}
	id, err := strconv.ParseUint(fields[0], 16, 8)
	if err != nil || byte(id) != addr {
		return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: status reply for node %q, expected %02x (reply %q)",
			fields[0], addr, strings.TrimSpace(reply))
	}
	detail := ""
	if len(fields) >= 5 {
		detail = fmt.Sprintf("current=0x%s fan=0x%s", fields[3], fields[4])
	}
	switch fields[2] {
	case "1":
		return proto.BMCStateOn, detail, nil
	case "0":
		return proto.BMCStateOff, detail, nil
	case "2":
		if detail != "" {
			return proto.BMCStateOff, "disabled; " + detail, nil
		}
		return proto.BMCStateOff, "disabled", nil
	}
	return proto.BMCStateUnknown, "", fmt.Errorf("bitscope: unknown power-state token %q in reply %q",
		fields[2], strings.TrimSpace(reply))
}

// bitscopeMapEntry is one address-map row: pos is authoritative, the
// bus address is derived so it can't drift from the rack's geographic
// reality. The same shape serves the on-disk map file (env path) and
// the inline settings selection (bmc-settings.md §3).
type bitscopeMapEntry struct {
	Pos    string `json:"pos"`
	NodeID string `json:"node_id"`
	Serial string `json:"serial,omitempty"`
}

// bitscopeMapFile is the on-disk address map (design doc §2d).
type bitscopeMapFile struct {
	Targets []bitscopeMapEntry `json:"targets"`
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
	return buildBitScopeTargets(path, mf.Targets)
}

// buildBitScopeTargets validates and resolves address-map entries;
// source labels errors (a file path or "settings").
func buildBitScopeTargets(source string, entries []bitscopeMapEntry) (map[string]bitscopeTarget, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("bitscope: address map %s: no targets", source)
	}
	targets := make(map[string]bitscopeTarget, len(entries))
	seenPos := make(map[byte]string, len(entries))
	for _, t := range entries {
		if t.NodeID == "" {
			return nil, fmt.Errorf("bitscope: address map %s: entry %q missing node_id", source, t.Pos)
		}
		addr, err := parseBitScopePos(t.Pos)
		if err != nil {
			return nil, fmt.Errorf("bitscope: address map %s: %w", source, err)
		}
		if other, dup := seenPos[addr]; dup {
			return nil, fmt.Errorf("bitscope: address map %s: pos %s duplicates %s", source, t.Pos, other)
		}
		seenPos[addr] = t.Pos
		if _, dup := targets[t.NodeID]; dup {
			return nil, fmt.Errorf("bitscope: address map %s: duplicate node_id %q", source, t.NodeID)
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
