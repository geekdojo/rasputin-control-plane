//go:build linux

package lanaddr

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strings"
	"syscall"
)

// Netlink constants the syscall package does not export.
const (
	// rtmgrpIPv4IfAddr is the legacy multicast group bit for IPv4 address
	// changes: 1 << (RTNLGRP_IPV4_IFADDR-1), RTNLGRP_IPV4_IFADDR = 5.
	rtmgrpIPv4IfAddr = 0x10
	// ifaFlags is IFA_FLAGS, the 32-bit flags attribute. The kernel sends it
	// alongside the 8-bit ifa_flags header field when flags do not fit in 8 bits.
	ifaFlags = 8
)

// SystemSource returns the kernel's view of the node's addresses, over a
// NETLINK_ROUTE socket. Both halves are unprivileged: any process may dump
// addresses and join the IPv4 address multicast group.
func SystemSource() Source { return netlinkSource{} }

type netlinkSource struct{}

// Subscribe joins RTMGRP_IPV4_IFADDR and signals on every RTM_NEWADDR or
// RTM_DELADDR. The socket is non-blocking and handed to the runtime poller via
// os.NewFile, so closing it when ctx ends unblocks the reader: no read timeout
// and no polling loop.
func (netlinkSource) Subscribe(ctx context.Context) (<-chan struct{}, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("lanaddr: netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtmgrpIPv4IfAddr}); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("lanaddr: netlink bind: %w", err)
	}
	f := os.NewFile(uintptr(fd), "netlink-route-ipv4-ifaddr")
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lanaddr: netlink conn: %w", err)
	}

	ch := make(chan struct{}, 1)
	notify := func() {
		select {
		case ch <- struct{}{}:
		default: // one is already pending; the receiver re-lists everything
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = f.Close() })

	go func() {
		defer close(ch)
		defer stop()
		defer f.Close()
		buf := make([]byte, 1<<16)
		for {
			var n int
			var rerr error
			err := rc.Read(func(s uintptr) bool {
				n, _, rerr = syscall.Recvfrom(int(s), buf, 0)
				return !errors.Is(rerr, syscall.EAGAIN)
			})
			if err != nil {
				return // the file was closed: ctx ended
			}
			if errors.Is(rerr, syscall.ENOBUFS) {
				// The socket buffer overflowed and events were dropped. That is
				// exactly why the receiver re-lists instead of applying deltas:
				// one more list recovers the true set.
				notify()
				continue
			}
			if rerr != nil {
				log.Printf("lanaddr: netlink receive: %v", rerr)
				return
			}
			msgs, perr := syscall.ParseNetlinkMessage(buf[:n])
			if perr != nil {
				notify() // unparseable, but it was an address-group message
				continue
			}
			for _, m := range msgs {
				if m.Header.Type == syscall.RTM_NEWADDR || m.Header.Type == syscall.RTM_DELADDR {
					notify()
					break
				}
			}
		}
	}()
	return ch, nil
}

// List dumps every IPv4 address (RTM_GETADDR) and joins each to its interface.
func (netlinkSource) List() ([]Addr, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("lanaddr: dump addresses: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, fmt.Errorf("lanaddr: parse address dump: %w", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("lanaddr: interfaces: %w", err)
	}
	byIndex := make(map[int]net.Interface, len(ifaces))
	for _, ifc := range ifaces {
		byIndex[ifc.Index] = ifc
	}
	return parseAddrDump(msgs, byIndex), nil
}

// parseAddrDump turns RTM_NEWADDR messages into Addrs. Split from List so the
// parsing is testable against hand-built messages.
func parseAddrDump(msgs []syscall.NetlinkMessage, byIndex map[int]net.Interface) []Addr {
	var out []Addr
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type == syscall.NLMSG_DONE {
			break
		}
		if m.Header.Type != syscall.RTM_NEWADDR || len(m.Data) < syscall.SizeofIfAddrmsg {
			continue
		}
		// struct ifaddrmsg: family, prefixlen, flags, scope (one byte each), then
		// the interface index as a host-endian u32.
		if m.Data[0] != syscall.AF_INET {
			continue
		}
		flags := uint32(m.Data[2])
		rawIndex := binary.NativeEndian.Uint32(m.Data[4:8])
		if rawIndex > math.MaxInt32 {
			continue
		}
		index := int(rawIndex)

		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		var local, address net.IP
		var label string
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.IFA_LOCAL:
				local = ipv4(a.Value)
			case syscall.IFA_ADDRESS:
				address = ipv4(a.Value)
			case syscall.IFA_LABEL:
				label = strings.TrimRight(string(a.Value), "\x00")
			case ifaFlags:
				if len(a.Value) >= 4 {
					flags = binary.NativeEndian.Uint32(a.Value[:4])
				}
			}
		}
		// For IPv4, IFA_LOCAL is the interface's own address; IFA_ADDRESS is the
		// peer on a point-to-point link and equals IFA_LOCAL everywhere else.
		ip := local
		if ip == nil {
			ip = address
		}
		if ip == nil {
			continue
		}
		a := Addr{IP: ip, Index: index, Dynamic: flags&syscall.IFA_F_PERMANENT == 0}
		if ifc, ok := byIndex[index]; ok {
			a.Link = ifc.Name
			a.Loopback = ifc.Flags&net.FlagLoopback != 0
		} else {
			// The interface went away between the two dumps; the label is the
			// best name left, and the next event re-lists anyway.
			a.Link = label
		}
		out = append(out, a)
	}
	return out
}

func ipv4(b []byte) net.IP {
	if len(b) != net.IPv4len {
		return nil
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).To4()
}
