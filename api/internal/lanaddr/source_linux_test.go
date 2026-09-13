//go:build linux

package lanaddr

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestNetlinkSource_ListUnprivileged runs the real address dump as an ordinary
// user. Every Linux host has 127.0.0.1 on a loopback interface, which is enough
// to prove the dump parses and joins to interfaces.
func TestNetlinkSource_ListUnprivileged(t *testing.T) {
	addrs, err := SystemSource().List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, a := range addrs {
		if a.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			if !a.Loopback || a.Link == "" || a.Index <= 0 {
				t.Fatalf("127.0.0.1 reported as %+v, want a named loopback interface", a)
			}
			if Usable(a) {
				t.Fatal("127.0.0.1 must not be usable")
			}
			return
		}
	}
	t.Fatalf("127.0.0.1 not in the dump: %+v", addrs)
}

// TestNetlinkSource_SubscribeUnprivileged joins the address multicast group as
// an ordinary user and checks the channel closes when ctx ends — the socket is
// released rather than leaked.
func TestNetlinkSource_SubscribeUnprivileged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := SystemSource().Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("subscription channel not closed after ctx ended")
		}
	}
}

const liveChildEnv = "RASPUTIN_LANADDR_LIVE_CHILD"

// TestNetlinkSource_LiveEvents adds and removes real addresses and checks the
// kernel's events reach the Source and the dump reports them, including the
// dynamic flag the primary rule depends on. Changing addresses needs
// CAP_NET_ADMIN, so the test re-executes itself in a fresh network namespace —
// never the host's — inside a user namespace when not root. Where the host
// forbids that (unprivileged user namespaces disabled, or restricted by
// AppArmor as on some Ubuntu runners), it skips and says so.
func TestNetlinkSource_LiveEvents(t *testing.T) {
	if os.Getenv(liveChildEnv) == "1" {
		liveEventsBody(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetlinkSource_LiveEvents$", "-test.v")
	cmd.Env = append(os.Environ(), liveChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if os.Geteuid() != 0 {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Skipf("cannot create a network namespace here (%v); live netlink test not run", err)
		}
		t.Fatalf("live child failed: %v\n%s", err, text)
	}
	if strings.Contains(text, "--- SKIP") {
		t.Skipf("live child skipped:\n%s", text)
	}
	if !strings.Contains(text, "--- PASS: TestNetlinkSource_LiveEvents") {
		t.Fatalf("live child did not report a pass:\n%s", text)
	}
}

func liveEventsBody(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lo: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := SystemSource()
	ch, err := src.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	leaseIP := net.IPv4(192, 0, 2, 10).To4()    // stands in for a DHCP lease
	staticIP := net.IPv4(198, 51, 100, 7).To4() // stands in for the fallback
	if err := addrRequest(syscall.RTM_NEWADDR, lo.Index, leaseIP, 300); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("no CAP_NET_ADMIN in the namespace (%v)", err)
		}
		t.Fatalf("add %s: %v", leaseIP, err)
	}
	waitEvent(t, ch, "add "+leaseIP.String())
	if err := addrRequest(syscall.RTM_NEWADDR, lo.Index, staticIP, 0); err != nil {
		t.Fatalf("add %s: %v", staticIP, err)
	}
	waitEvent(t, ch, "add "+staticIP.String())

	got := find(t, src)
	if a, ok := got[leaseIP.String()]; !ok || !a.Dynamic || a.Link != "lo" || !a.Loopback {
		t.Fatalf("lease-like address = %+v (present %v), want dynamic on lo", a, ok)
	}
	if a, ok := got[staticIP.String()]; !ok || a.Dynamic {
		t.Fatalf("static address = %+v (present %v), want permanent", a, ok)
	}

	if err := addrRequest(syscall.RTM_DELADDR, lo.Index, leaseIP, 0); err != nil {
		t.Fatalf("delete %s: %v", leaseIP, err)
	}
	waitEvent(t, ch, "delete "+leaseIP.String())
	if _, ok := find(t, src)[leaseIP.String()]; ok {
		t.Fatal("deleted address still listed")
	}
}

func find(t *testing.T, src Source) map[string]Addr {
	t.Helper()
	addrs, err := src.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	out := map[string]Addr{}
	for _, a := range addrs {
		out[a.IP.String()] = a
	}
	return out
}

// waitEvent waits for one change notification. The deadline bounds a broken
// test only.
func waitEvent(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatalf("subscription closed waiting for %s", what)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no address event for %s", what)
	}
}

// addrRequest adds or deletes ip/24 on ifindex over rtnetlink and waits for the
// kernel's ACK. validLft > 0 installs the address with a finite lifetime, which
// is what makes the kernel flag it dynamic, as networkd does for a DHCP lease.
func addrRequest(msgType uint16, ifindex int, ip net.IP, validLft uint32) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	ne := binary.NativeEndian
	body := make([]byte, syscall.SizeofIfAddrmsg)
	body[0] = syscall.AF_INET
	body[1] = 24
	ne.PutUint32(body[4:8], uint32(ifindex))
	attr := func(typ uint16, val []byte) {
		l := syscall.SizeofRtAttr + len(val)
		b := make([]byte, (l+3)&^3)
		ne.PutUint16(b[0:2], uint16(l))
		ne.PutUint16(b[2:4], typ)
		copy(b[4:], val)
		body = append(body, b...)
	}
	attr(syscall.IFA_LOCAL, ip)
	attr(syscall.IFA_ADDRESS, ip)
	if validLft > 0 {
		ci := make([]byte, 16) // struct ifa_cacheinfo: prefered, valid, cstamp, tstamp
		ne.PutUint32(ci[0:4], validLft)
		ne.PutUint32(ci[4:8], validLft)
		attr(6 /* IFA_CACHEINFO */, ci)
	}

	flags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK)
	if msgType == syscall.RTM_NEWADDR {
		flags |= syscall.NLM_F_CREATE | syscall.NLM_F_EXCL
	}
	msg := make([]byte, syscall.NLMSG_HDRLEN, syscall.NLMSG_HDRLEN+len(body))
	ne.PutUint32(msg[0:4], uint32(syscall.NLMSG_HDRLEN+len(body)))
	ne.PutUint16(msg[4:6], msgType)
	ne.PutUint16(msg[6:8], flags)
	ne.PutUint32(msg[8:12], 1)
	msg = append(msg, body...)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			if code := int32(ne.Uint32(m.Data[0:4])); code != 0 {
				return syscall.Errno(-code)
			}
			return nil
		}
	}
	return fmt.Errorf("no netlink ack")
}
