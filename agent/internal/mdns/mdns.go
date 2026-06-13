// Package mdns is a minimal, dependency-free multicast-DNS A-record resolver —
// just enough for an agent to find the control plane at rasputin.local on a LAN
// where the OS has no .local resolver (the OpenWrt firewall image). It is NOT a
// general mDNS stack: one-shot A query, first answer wins.
//
// It sets the QU (unicast-response) bit on the question so responders reply
// directly to our socket; that lets us receive the answer on an ephemeral UDP
// port without joining the multicast group.
package mdns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	mdnsAddr4 = "224.0.0.251:5353"
	typeA     = 1
	classIN   = 1
	// quBit is the top bit of the question's QCLASS — "unicast response
	// requested" (RFC 6762 §5.4). Responders then answer us directly.
	quBit = 0x8000
)

// Resolve performs a one-shot mDNS A lookup for name (e.g. "rasputin.local")
// and returns the first IPv4 address found, or an error on timeout / no answer.
func Resolve(name string, timeout time.Duration) (string, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", errors.New("mdns: empty name")
	}

	query, err := buildQuery(name)
	if err != nil {
		return "", err
	}

	dst, err := net.ResolveUDPAddr("udp4", mdnsAddr4)
	if err != nil {
		return "", err
	}
	// Ephemeral local socket; responders unicast back to it (QU bit).
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", fmt.Errorf("mdns: listen: %w", err)
	}
	defer conn.Close()

	if _, err := conn.WriteToUDP(query, dst); err != nil {
		return "", fmt.Errorf("mdns: send: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "", fmt.Errorf("mdns: no A answer for %q: %w", name, err)
		}
		if ip := parseAnswer(buf[:n], name); ip != "" {
			return ip, nil
		}
		// Not our answer (another responder / record type) — keep reading until
		// the deadline.
	}
}

// buildQuery encodes a single-question DNS packet asking for name's A record
// with the unicast-response bit set.
func buildQuery(name string) ([]byte, error) {
	var b []byte
	// Header: id=0, flags=0, qd=1, an=ns=ar=0.
	b = append(b, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	// QNAME.
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("mdns: bad label in %q", name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0) // root label
	// QTYPE=A, QCLASS=IN|QU.
	b = append(b, byte(typeA>>8), byte(typeA))
	q := uint16(classIN | quBit)
	b = append(b, byte(q>>8), byte(q))
	return b, nil
}

// parseAnswer walks a response packet and returns the first A-record IPv4 whose
// owner name matches want (case-insensitive). Returns "" if none.
func parseAnswer(msg []byte, want string) string {
	if len(msg) < 12 {
		return ""
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12

	// Skip questions.
	for i := 0; i < qd; i++ {
		_, o, ok := readName(msg, off)
		if !ok {
			return ""
		}
		off = o + 4 // qtype + qclass
		if off > len(msg) {
			return ""
		}
	}

	// Walk answers.
	for i := 0; i < an; i++ {
		owner, o, ok := readName(msg, off)
		if !ok || o+10 > len(msg) {
			return ""
		}
		rtype := int(msg[o])<<8 | int(msg[o+1])
		rdlen := int(msg[o+8])<<8 | int(msg[o+9])
		rdStart := o + 10
		if rdStart+rdlen > len(msg) {
			return ""
		}
		if rtype == typeA && rdlen == 4 && strings.EqualFold(owner, want) {
			ip := net.IPv4(msg[rdStart], msg[rdStart+1], msg[rdStart+2], msg[rdStart+3])
			return ip.String()
		}
		off = rdStart + rdlen
	}
	return ""
}

// readName decodes a (possibly compressed) DNS name starting at off, returning
// the dotted name, the offset just past the name in the record stream, and ok.
// For names that use a compression pointer, the returned offset is just past the
// pointer (2 bytes) — correct for advancing through the record.
func readName(msg []byte, off int) (string, int, bool) {
	var labels []string
	cur := off
	jumped := false
	afterPtr := 0
	// Bound the loop to guard against pointer cycles.
	for steps := 0; steps < 128; steps++ {
		if cur >= len(msg) {
			return "", 0, false
		}
		b := msg[cur]
		if b == 0 {
			cur++
			if !jumped {
				afterPtr = cur
			}
			return strings.Join(labels, "."), afterPtr, true
		}
		if b&0xc0 == 0xc0 { // compression pointer
			if cur+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(b&0x3f)<<8 | int(msg[cur+1])
			if !jumped {
				afterPtr = cur + 2
			}
			jumped = true
			cur = ptr
			continue
		}
		l := int(b)
		if cur+1+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[cur+1:cur+1+l]))
		cur += 1 + l
	}
	return "", 0, false
}
