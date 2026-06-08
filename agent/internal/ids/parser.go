// Package ids is the agent's snort3 alert tailer and NATS publisher.
// Only registered on firewall-role nodes; on other nodes the package's
// types compile but Run is not called from main.go.
package ids

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// snort3's alert_fast format (output { alert_fast = { ... } } in snort.lua):
//
//	MM/DD-HH:MM:SS.uuuuuu  [**]  [gid:sid:rev]  Message text here  [**]  [Classification: classname]  [Priority: N]  {Protocol}  Src -> Dst
//
// Some snort configurations include the year in the timestamp; the default
// does not. The parser accepts both. Src/Dst forms cover IPv4/IPv6 with or
// without ports (ICMP has no port; ARP has neither IP nor port). When a
// field can't be extracted we leave it zero/empty and rely on Raw for
// fidelity — the controlplane never blocks on a missing field.

var (
	// Outer skeleton: timestamp, gid:sid:rev, message, classification,
	// priority, protocol, addrs. The Message capture (.*?) is non-greedy
	// against the [**] sentinel that closes it.
	alertFastRe = regexp.MustCompile(
		`^(?P<ts>\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}\.\d+) ` +
			`\[\*\*\] \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] ` +
			`"?(?P<msg>.*?)"? \[\*\*\] ` +
			`(?:\[Classification: (?P<class>[^\]]+)\] )?` +
			`(?:\[Priority: (?P<prio>\d+)\] )?` +
			`(?:\{(?P<proto>[^}]+)\} )?` +
			`(?P<src>\S+)(?: -> (?P<dst>\S+))?\s*$`)

	// Address split: handles "1.2.3.4:80", "[fe80::1]:443", "1.2.3.4" (no
	// port for ICMP), "00:11:22:33:44:55" (ARP — we treat the whole thing
	// as the address, no port). The trailing port is optional.
	addrRe = regexp.MustCompile(
		`^(?:` +
			`\[(?P<v6>[^\]]+)\]` + // [v6]
			`|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})` + // v4
			`|(?P<other>[0-9A-Fa-f:.]+?)` + // mac/etc — keep last, lazy
			`)(?::(?P<port>\d+))?$`)
)

// ParseAlertFast parses one snort3 alert_fast log line into an IDSAlertEvt.
// The Raw field always holds the original line. Returns false (without an
// error) for empty lines and lines that don't look like alerts — callers
// should silently skip those. Returns an error for lines that look like
// alerts but have a structurally-wrong shape we can't recover from.
//
// When the line has the alert skeleton but optional fields are missing
// (classification, priority, addresses for ARP, etc.) the corresponding
// fields are left zero/empty.
func ParseAlertFast(nodeID, line string, now func() time.Time) (proto.IDSAlertEvt, bool, error) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return proto.IDSAlertEvt{}, false, nil
	}
	m := alertFastRe.FindStringSubmatch(line)
	if m == nil {
		// Doesn't match the alert_fast skeleton — could be a header line,
		// a continuation, or noise. Not an error.
		return proto.IDSAlertEvt{}, false, nil
	}
	g := map[string]string{}
	for i, name := range alertFastRe.SubexpNames() {
		if name != "" {
			g[name] = m[i]
		}
	}

	ts, err := parseAlertTs(g["ts"], now)
	if err != nil {
		return proto.IDSAlertEvt{}, false, fmt.Errorf("alert ts %q: %w", g["ts"], err)
	}

	gid, _ := strconv.Atoi(g["gid"])
	sid, _ := strconv.Atoi(g["sid"])
	rev, _ := strconv.Atoi(g["rev"])
	prio, _ := strconv.Atoi(g["prio"]) // missing → 0, fine

	srcAddr, srcPort := splitAddrPort(g["src"])
	dstAddr, dstPort := splitAddrPort(g["dst"])

	return proto.IDSAlertEvt{
		NodeID:         nodeID,
		Ts:             ts,
		GID:            gid,
		SID:            sid,
		Rev:            rev,
		Message:        strings.TrimSpace(g["msg"]),
		Classification: strings.TrimSpace(g["class"]),
		Priority:       prio,
		Protocol:       strings.TrimSpace(g["proto"]),
		SrcAddr:        srcAddr,
		SrcPort:        srcPort,
		DstAddr:        dstAddr,
		DstPort:        dstPort,
		Raw:            line,
	}, true, nil
}

// parseAlertTs handles snort's MM/DD-HH:MM:SS.uuuuuu (no year) and
// MM/DD/YYYY-HH:MM:SS.uuuuuu (year-included) formats. For the year-less
// form we use now()'s year; this is good enough for everything except
// a rollover edge case (an alert logged in late Dec 2026 but processed
// in early Jan 2027 would be year-shifted +1). For v1 we accept that.
func parseAlertTs(s string, now func() time.Time) (time.Time, error) {
	// Year-included variants — snort can be configured to emit a 2- or 4-
	// digit year. Try the 4-digit form first.
	for _, layout := range []string{
		"01/02/2006-15:04:05.000000",
		"01/02/06-15:04:05.000000",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	// Year-less form — borrow now's year.
	t, err := time.Parse("01/02-15:04:05.000000", s)
	if err != nil {
		return time.Time{}, err
	}
	return time.Date(now().Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC), nil
}

// splitAddrPort returns the address-and-port split of a snort src/dst
// field. Returns ("", 0) on empty input.
func splitAddrPort(s string) (string, int) {
	if s == "" {
		return "", 0
	}
	m := addrRe.FindStringSubmatch(s)
	if m == nil {
		return s, 0 // unrecognized shape — keep the whole string as the address
	}
	var addr string
	for i, name := range addrRe.SubexpNames() {
		if (name == "v4" || name == "v6" || name == "other") && m[i] != "" {
			addr = m[i]
		}
	}
	port := 0
	for i, name := range addrRe.SubexpNames() {
		if name == "port" && m[i] != "" {
			port, _ = strconv.Atoi(m[i])
		}
	}
	if addr == "" {
		addr = s
	}
	return addr, port
}
