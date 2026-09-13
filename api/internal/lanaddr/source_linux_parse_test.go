//go:build linux

package lanaddr

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"syscall"
	"testing"
)

// Hand-built rtnetlink bytes, so the parsing and the receive loop's policy are
// tested without a socket — the live netns test cannot run everywhere (it
// skipped in the mutation job), and these must.

type nlAttr struct {
	typ uint16
	val []byte
}

// nlAddrMsg encodes one netlink message carrying a struct ifaddrmsg and attrs.
func nlAddrMsg(msgType uint16, family, ifaFlags byte, index uint32, attrs ...nlAttr) []byte {
	ne := binary.NativeEndian
	body := make([]byte, syscall.SizeofIfAddrmsg)
	body[0] = family
	body[1] = 24 // prefix length
	body[2] = ifaFlags
	ne.PutUint32(body[4:8], index)
	for _, a := range attrs {
		l := syscall.SizeofRtAttr + len(a.val)
		b := make([]byte, (l+3)&^3)
		ne.PutUint16(b[0:2], uint16(l))
		ne.PutUint16(b[2:4], a.typ)
		copy(b[4:], a.val)
		body = append(body, b...)
	}
	msg := make([]byte, syscall.NLMSG_HDRLEN, syscall.NLMSG_HDRLEN+len(body))
	ne.PutUint32(msg[0:4], uint32(syscall.NLMSG_HDRLEN+len(body)))
	ne.PutUint16(msg[4:6], msgType)
	return append(msg, body...)
}

// nlBare encodes a netlink message with no payload, e.g. NLMSG_DONE.
func nlBare(msgType uint16) []byte {
	msg := make([]byte, syscall.NLMSG_HDRLEN+4)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], msgType)
	return msg
}

func local(ip string) nlAttr   { return nlAttr{syscall.IFA_LOCAL, net.ParseIP(ip).To4()} }
func address(ip string) nlAttr { return nlAttr{syscall.IFA_ADDRESS, net.ParseIP(ip).To4()} }
func flags32(v uint32) nlAttr {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return nlAttr{ifaFlags, b}
}

func parse(t *testing.T, datagram ...[]byte) []Addr {
	t.Helper()
	var all []byte
	for _, d := range datagram {
		all = append(all, d...)
	}
	msgs, err := syscall.ParseNetlinkMessage(all)
	if err != nil {
		t.Fatalf("ParseNetlinkMessage: %v", err)
	}
	return parseAddrDump(msgs, map[int]net.Interface{2: {Index: 2, Name: "end0"}})
}

func byIP(addrs []Addr) map[string]Addr {
	out := map[string]Addr{}
	for _, a := range addrs {
		out[a.IP.String()] = a
	}
	return out
}

// The dynamic flag comes from IFA_F_PERMANENT, and it is what makes the DHCP
// address win over rasputin-os's static fallback. networkd installs a lease's
// address with a finite lifetime (IFA_F_PERMANENT clear) and a static Address=
// as permanent.
func TestParseAddrDump_DynamicFromPermanentFlag(t *testing.T) {
	got := parse(t,
		nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, syscall.IFA_F_PERMANENT, 2, local("192.168.1.2")),
		nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, 2, local("192.168.1.226")),
		nlBare(syscall.NLMSG_DONE),
	)
	m := byIP(got)
	if a, ok := m["192.168.1.2"]; !ok || a.Dynamic || a.Link != "end0" {
		t.Fatalf("static fallback = %+v (present %v), want permanent on end0", a, ok)
	}
	if a, ok := m["192.168.1.226"]; !ok || !a.Dynamic {
		t.Fatalf("DHCP address = %+v (present %v), want dynamic", a, ok)
	}
	if p := Select(got).PrimaryIP(); p.String() != "192.168.1.226" {
		t.Fatalf("primary = %v, want the DHCP address over the lower static one", p)
	}
}

// IFA_FLAGS, the 32-bit attribute, is authoritative over the 8-bit header field
// when present and well formed; a short one is ignored.
func TestParseAddrDump_IFAFlagsAttribute(t *testing.T) {
	for _, tc := range []struct {
		name        string
		headerFlags byte
		attr        nlAttr
		wantDynamic bool
	}{
		{"IFA_FLAGS permanent overrides a dynamic header", 0, flags32(syscall.IFA_F_PERMANENT), false},
		{"IFA_FLAGS dynamic overrides a permanent header", syscall.IFA_F_PERMANENT, flags32(0), true},
		{"IFA_FLAGS shorter than 4 bytes is ignored (header permanent)", syscall.IFA_F_PERMANENT, nlAttr{ifaFlags, []byte{0, 0, 0}}, false},
		{"IFA_FLAGS shorter than 4 bytes is ignored (header dynamic)", 0, nlAttr{ifaFlags, []byte{0x80, 0, 0}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parse(t, nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, tc.headerFlags, 2, local("192.168.1.5"), tc.attr))
			if len(got) != 1 {
				t.Fatalf("parsed %d addresses, want 1: %+v", len(got), got)
			}
			if got[0].Dynamic != tc.wantDynamic {
				t.Fatalf("Dynamic = %v, want %v", got[0].Dynamic, tc.wantDynamic)
			}
		})
	}
}

func TestParseAddrDump_AddressSelection(t *testing.T) {
	// No IFA_LOCAL: IFA_ADDRESS is the address.
	got := parse(t, nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, 2, address("10.0.0.9")))
	if len(got) != 1 || got[0].IP.String() != "10.0.0.9" {
		t.Fatalf("IFA_ADDRESS only = %+v, want 10.0.0.9", got)
	}
	// Both: IFA_LOCAL wins (IFA_ADDRESS is the peer on a point-to-point link).
	got = parse(t, nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, 2, address("10.0.0.1"), local("10.0.0.9")))
	if len(got) != 1 || got[0].IP.String() != "10.0.0.9" {
		t.Fatalf("both = %+v, want IFA_LOCAL 10.0.0.9", got)
	}
	// Neither: skipped.
	if got := parse(t, nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, 2)); len(got) != 0 {
		t.Fatalf("no address attrs = %+v, want nothing", got)
	}
}

func TestParseAddrDump_Filtering(t *testing.T) {
	got := parse(t,
		nlAddrMsg(syscall.RTM_DELADDR, syscall.AF_INET, 0, 2, local("10.0.0.1")),  // not a dump entry
		nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET6, 0, 2, local("10.0.0.2")), // wrong family
		nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, 7, local("10.0.0.3")),  // unknown ifindex
		nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, math.MaxInt32, local("10.0.0.4")),
		nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, math.MaxInt32+1, local("10.0.0.5")), // overflows int32
		nlBare(syscall.NLMSG_DONE),
		nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, 2, local("10.0.0.6")), // after DONE
	)
	m := byIP(got)
	for _, gone := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.6"} {
		if _, ok := m[gone]; ok {
			t.Errorf("%s should have been skipped: %+v", gone, got)
		}
	}
	if a, ok := m["10.0.0.3"]; !ok || a.Index != 7 || a.Link != "" {
		t.Errorf("unknown ifindex entry = %+v (present %v), want kept with no link name", a, ok)
	}
	if a, ok := m["10.0.0.4"]; !ok || a.Index != math.MaxInt32 {
		t.Errorf("max int32 ifindex = %+v (present %v), want kept", a, ok)
	}
}

func TestClassifyDatagram(t *testing.T) {
	newAddr := nlAddrMsg(syscall.RTM_NEWADDR, syscall.AF_INET, 0, 2, local("192.168.1.2"))
	delAddr := nlAddrMsg(syscall.RTM_DELADDR, syscall.AF_INET, 0, 2, local("192.168.1.2"))
	link := nlBare(syscall.RTM_NEWLINK)
	truncated := nlBare(syscall.RTM_NEWADDR)
	binary.NativeEndian.PutUint32(truncated[0:4], 200)
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		datagram []byte
		rerr     error
		want     datagramAction
	}{
		{"RTM_NEWADDR", newAddr, nil, datagramNotify},
		{"RTM_DELADDR", delAddr, nil, datagramNotify},
		{"several address messages in one datagram: one notify", cat(newAddr, delAddr, newAddr), nil, datagramNotify},
		{"address message after an unrelated one", cat(link, delAddr), nil, datagramNotify},
		{"unrelated message type", link, nil, datagramIgnore},
		{"empty datagram", nil, nil, datagramIgnore},
		{"unparseable datagram (header claims more than arrived)", truncated, nil, datagramNotify},
		{"runt shorter than a header", []byte{1, 2, 3}, nil, datagramIgnore},
		{"ENOBUFS: events dropped, re-list", nil, syscall.ENOBUFS, datagramNotify},
		{"wrapped ENOBUFS", nil, errors.Join(errors.New("recv"), syscall.ENOBUFS), datagramNotify},
		{"other receive error: stop", nil, syscall.EBADF, datagramStop},
		{"receive error wins over a datagram", newAddr, syscall.EIO, datagramStop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDatagram(tc.datagram, tc.rerr); got != tc.want {
				t.Fatalf("classifyDatagram = %v, want %v", got, tc.want)
			}
		})
	}
}
