package openwrt

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Why dnsmasq is RESTARTED, not reloaded, when the conditional-forward changes
// (geekdojo/geekdojo-brain#436).
//
// `/etc/init.d/dnsmasq reload` regenerates /var/etc/dnsmasq.conf.<section> and
// sends SIGHUP. dnsmasq never re-reads its configuration file on SIGHUP — only
// the hosts/ethers/dhcp-hosts/addn-hosts files, and a --servers-file. Both
// options Rasputin manages are configuration-file options read once at start:
//
//   - `server=/<zone>/<ip>` (UCI dhcp.@dnsmasq[0].server), the forward itself;
//   - `rebind-domain-ok=/<zone>/` (UCI dhcp.@dnsmasq[0].rebind_domain), its
//     rebind-protection whitelist.
//
// On top of that, the init script bind-mounts the config into dnsmasq's ujail as
// a single file and replaces it with `mv`, so the jail keeps seeing the old
// inode. A reload therefore reaches these options only if procd decides to
// restart the instance because the generated file changed, and on the e12bench
// firewall it did not (why is not established): the running dnsmasq kept
// forwarding the cluster zone to the control plane's previous address until a
// manual restart. A restart does not depend on that decision.
//
// The reload-safe alternative, a UCI `serversfile` that dnsmasq re-reads on
// SIGHUP, was rejected: it covers only `server=` (rebind-domain-ok still needs a
// restart when the zone changes), the file must exist before dnsmasq first
// starts and must be rewritten in place rather than renamed because the jail
// mounts the inode, and switching an existing box onto it is itself a restart.
// The forward changes only when the control plane's LAN address or cluster zone
// changes, so a restart's roughly one-second DNS gap is paid rarely, and it
// leaves one mechanism that applies both options.

const (
	// dnsmasqRestartTimeout bounds the init script. It runs detached from the
	// caller's cancellation: killing `restart` between its stop and its start
	// would leave the box with no resolver at all, which is worse than the apply
	// overrunning its deadline.
	dnsmasqRestartTimeout = 20 * time.Second
	// dnsmasqLogTimeout bounds each wait on the log stream: for logread's
	// backlog line (the subscription is live), and for the restarted dnsmasq's
	// startup lines.
	dnsmasqLogTimeout = 5 * time.Second
	// dnsmasqProbeTimeout bounds the one DNS query Get sends through the running
	// dnsmasq.
	dnsmasqProbeTimeout = 2 * time.Second
	// dnsmasqListen is where the firewall's own dnsmasq answers; the init script
	// points /tmp/resolv.conf at it.
	dnsmasqListen = "127.0.0.1:53"
)

// dnsmasqObserver reads the RUNNING dnsmasq, as opposed to its UCI
// configuration. UCI says what dnsmasq will use the next time it starts; only
// the process says what it uses now, and #436 was the two disagreeing.
type dnsmasqObserver interface {
	// FollowLog streams the system log as newline-terminated lines. The stream
	// opens with the newest line already in the log buffer and then carries
	// every line logged after it, with no gap between the two. Close stops it.
	FollowLog(ctx context.Context) (io.ReadCloser, error)
	// LookupA sends one A query for name to the local dnsmasq and returns the
	// IPv4 answers. An error means no successful answer arrived.
	LookupA(ctx context.Context, name string) ([]netip.Addr, error)
}

// realDnsmasq is the production dnsmasqObserver: ubox `logread` and a UDP query
// to 127.0.0.1:53.
type realDnsmasq struct {
	server string // host:port of the dnsmasq to query; dnsmasqListen in production
}

// FollowLog runs `logread -f -l 1`. logd answers a streaming read by writing the
// requested backlog (one line) and then adding the client to its stream list,
// inside one handler of a single-threaded daemon, so no line logged after the
// backlog line can be missed.
func (realDnsmasq) FollowLog(ctx context.Context) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "logread", "-f", "-l", "1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("logread stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start logread: %w", err)
	}
	return &followedLog{ReadCloser: out, cancel: cancel, cmd: cmd}, nil
}

// followedLog kills logread on Close and reaps it.
type followedLog struct {
	io.ReadCloser
	cancel func()
	cmd    *exec.Cmd
	once   sync.Once
}

func (f *followedLog) Close() error {
	f.once.Do(func() {
		f.cancel()
		_ = f.cmd.Wait() // killed by cancel; its exit status carries no information
	})
	return nil
}

func (r realDnsmasq) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	return lookupA(ctx, r.server, name)
}

// lookupA sends exactly one A query for name to server over UDP and reads
// exactly one reply, both bounded by ctx's deadline. It does not retry: the
// caller wants to know whether the running resolver answers, not to coax an
// answer out of it.
func lookupA(ctx context.Context, server, name string) ([]netip.Addr, error) {
	fqdn := name
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	qname, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("query name %q: %w", name, err)
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, fmt.Errorf("query id: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	packet, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("send query to %s: %w", server, err)
	}
	buf := make([]byte, 1232)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read reply from %s: %w", server, err)
	}

	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parse reply: %w", err)
	}
	if !h.Response || h.ID != id {
		return nil, fmt.Errorf("reply from %s is not the answer to our query", server)
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("%s answered %s for %s", server, h.RCode, name)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("parse reply questions: %w", err)
	}
	var addrs []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse reply answers: %w", err)
		}
		if ah.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return nil, fmt.Errorf("parse reply answers: %w", err)
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return nil, fmt.Errorf("parse A record: %w", err)
		}
		addrs = append(addrs, netip.AddrFrom4(a.A))
	}
	return addrs, nil
}

// ----- restart + verify --------------------------------------------------------

// splitDNSForward splits a "/<zone>/<ip>" dnsmasq server entry. ok is false for
// anything not in that shape.
func splitDNSForward(entry string) (zone, target string, ok bool) {
	parts := strings.SplitN(entry, "/", 3)
	if len(parts) != 3 || parts[0] != "" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// dnsmasqMessage returns the message of a log line dnsmasq itself wrote
// ("... daemon.info dnsmasq[1]: <message>"), and false for any other line — so
// another program quoting dnsmasq's wording can never satisfy verification.
func dnsmasqMessage(line string) (string, bool) {
	i := strings.Index(line, "dnsmasq[")
	if i < 0 {
		return "", false
	}
	rest := line[i+len("dnsmasq["):]
	j := strings.Index(rest, "]: ")
	if j < 0 {
		return "", false
	}
	return strings.TrimRight(rest[j+len("]: "):], " \t\r"), true
}

// isForwardInUse reports whether msg is dnsmasq's startup announcement that it
// forwards zone to target: "using nameserver <ip>#53 for domain <zone>",
// optionally followed by a space and a qualifier such as "(no DNSSEC)".
func isForwardInUse(msg, zone, target string) bool {
	server := target
	if !strings.Contains(server, "#") {
		server += "#53"
	}
	want := "using nameserver " + server + " for domain " + zone
	return msg == want || strings.HasPrefix(msg, want+" ")
}

// restartDnsmasq restarts dnsmasq and returns nil only once the NEW process has
// announced, in its own log lines, that it started and — when entry is not
// empty — that it forwards entry's zone to entry's address. Every wait is on a
// log line arriving, bounded by one timeout; nothing is re-checked on a clock.
//
// The log stream is opened before the restart and its backlog line awaited, so
// the startup lines cannot be logged before we are listening, and no line that
// predates the restart can be mistaken for one after it.
func (c *UCIRealClient) restartDnsmasq(ctx context.Context, entry string) error {
	zone, target, wantForward := splitDNSForward(entry)
	if entry != "" && !wantForward {
		return fmt.Errorf("dnsmasq: malformed forward %q", entry)
	}

	followCtx, stopFollowing := context.WithCancel(ctx)
	defer stopFollowing()
	lines, followErr := c.followLines(followCtx)
	if followErr == nil {
		followErr = awaitLine(ctx, lines, c.logTimeout, "logread backlog line",
			func(string) (bool, error) { return true, nil })
	}

	// Restart even when the log can't be followed: the committed config is
	// right and the running process is not, so the restart is the fix whether or
	// not it can be observed. The apply still fails below, and a later apply
	// retries the whole restart.
	restartCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsmasqRestartTimeout)
	_, err := c.runner.Run(restartCtx, "/etc/init.d/dnsmasq", "restart")
	cancel()
	if err != nil {
		return fmt.Errorf("dnsmasq restart: %w", err)
	}
	if followErr != nil {
		return fmt.Errorf("dnsmasq restarted but cannot be verified: %w", followErr)
	}

	started := false
	what := "dnsmasq startup"
	if wantForward {
		what = fmt.Sprintf("dnsmasq startup using nameserver %s for domain %s", target, zone)
	}
	return awaitLine(ctx, lines, c.logTimeout, what, func(line string) (bool, error) {
		msg, ok := dnsmasqMessage(line)
		if !ok {
			return false, nil
		}
		switch {
		case strings.HasPrefix(msg, "FAILED to start up"):
			return false, fmt.Errorf("dnsmasq did not restart: %s", msg)
		case strings.HasPrefix(msg, "started, version "):
			started = true
			return !wantForward, nil
		case started && isForwardInUse(msg, zone, target):
			return true, nil
		}
		return false, nil
	})
}

// followLines opens the log stream and turns it into a channel of lines. The
// channel closes when the stream ends; cancelling ctx ends it.
func (c *UCIRealClient) followLines(ctx context.Context) (<-chan string, error) {
	stream, err := c.dnsmasq.FollowLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("follow log: %w", err)
	}
	lines := make(chan string)
	go func() {
		defer close(lines)
		defer func() { _ = stream.Close() }()
		sc := bufio.NewScanner(stream)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		_ = stream.Close() // unblocks a Scan waiting on a quiet log
	}()
	return lines, nil
}

// awaitLine consumes lines until match reports done or an error, the stream
// ends, or timeout elapses — whichever comes first.
func awaitLine(ctx context.Context, lines <-chan string, timeout time.Duration, what string, match func(string) (bool, error)) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case line, open := <-lines:
			if !open {
				return fmt.Errorf("log stream ended before %s", what)
			}
			done, err := match(line)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("no %s logged within %s", what, timeout)
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s: %w", what, ctx.Err())
		}
	}
}

// dnsForwardServing reports whether the RUNNING dnsmasq forwards entry's zone
// to entry's address. It asks the running dnsmasq for the zone apex's A record:
// the control plane's nameserver answers the apex with its own primary LAN
// address, which is exactly the forward's target (both come from the api's
// lanaddr PrimaryIP). A running forward to a dead address times out, one to a
// live wrong address answers with that address or not at all, and a running
// process without the rebind whitelist drops the private answer — each reads
// false. A cached apex answer can only be one an earlier upstream gave, so it
// can hold a stale address and read false, never read true for a stale forward.
func (c *UCIRealClient) dnsForwardServing(ctx context.Context, entry string) bool {
	zone, target, ok := splitDNSForward(entry)
	if !ok {
		return false
	}
	want, err := netip.ParseAddr(target)
	if err != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, c.probeTimeout)
	defer cancel()
	addrs, err := c.dnsmasq.LookupA(probeCtx, zone)
	if err != nil {
		log.Printf("rasputin-agent: firewall.get: running dnsmasq does not resolve %s: %v", zone, err)
		return false
	}
	for _, a := range addrs {
		if a == want {
			return true
		}
	}
	log.Printf("rasputin-agent: firewall.get: running dnsmasq resolves %s to %v, not the forward target %s", zone, addrs, target)
	return false
}
