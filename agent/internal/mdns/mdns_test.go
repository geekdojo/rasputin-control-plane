package mdns

import (
	"strings"
	"testing"
)

func TestBuildQuery(t *testing.T) {
	q, err := buildQuery("rasputin.local")
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	// Header: qdcount == 1.
	if q[4] != 0 || q[5] != 1 {
		t.Fatalf("qdcount not 1: % x", q[4:6])
	}
	// QNAME = 8"rasputin" 5"local" 0.
	want := append([]byte{8}, "rasputin"...)
	want = append(want, 5)
	want = append(want, "local"...)
	want = append(want, 0)
	if got := q[12 : 12+len(want)]; string(got) != string(want) {
		t.Fatalf("qname mismatch:\n got % x\nwant % x", got, want)
	}
	// QTYPE=A, QCLASS has the QU bit set.
	tail := q[12+len(want):]
	if tail[0] != 0 || tail[1] != typeA {
		t.Errorf("qtype not A: % x", tail[0:2])
	}
	if tail[2]&0x80 == 0 {
		t.Errorf("QU bit not set in qclass: % x", tail[2:4])
	}
}

// buildResponse crafts an mDNS-style answer: header, the echoed question, then
// an A answer whose owner name is a compression pointer back to the question
// (offset 12) — exactly the shape real responders emit.
func buildResponse(name, ip4 string) []byte {
	var b []byte
	b = append(b, 0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0) // flags=response/AA, qd=1, an=1
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = append(b, 0, typeA, 0, classIN) // question qtype/qclass
	// Answer: name = pointer to offset 12 (0xC00C).
	b = append(b, 0xC0, 0x0C)
	b = append(b, 0, typeA, 0, classIN)
	b = append(b, 0, 0, 0, 120) // ttl
	b = append(b, 0, 4)         // rdlength
	for _, oct := range strings.Split(ip4, ".") {
		var n int
		for _, c := range oct {
			n = n*10 + int(c-'0')
		}
		b = append(b, byte(n))
	}
	return b
}

func TestParseAnswer_CompressionPointer(t *testing.T) {
	msg := buildResponse("rasputin.local", "192.168.1.50")
	if got := parseAnswer(msg, "rasputin.local"); got != "192.168.1.50" {
		t.Fatalf("parseAnswer = %q, want 192.168.1.50", got)
	}
	// Case-insensitive owner match.
	if got := parseAnswer(msg, "Rasputin.Local"); got != "192.168.1.50" {
		t.Errorf("case-insensitive match failed: %q", got)
	}
	// A different name must not match.
	if got := parseAnswer(msg, "other.local"); got != "" {
		t.Errorf("unexpected match for other.local: %q", got)
	}
}

func TestParseAnswer_NoAnswer(t *testing.T) {
	if got := parseAnswer([]byte{0, 0}, "rasputin.local"); got != "" {
		t.Errorf("short packet should yield empty, got %q", got)
	}
	q, _ := buildQuery("rasputin.local") // a query has no answers
	if got := parseAnswer(q, "rasputin.local"); got != "" {
		t.Errorf("query packet has no answers, got %q", got)
	}
}

func TestReadName_RejectsPointerCycle(t *testing.T) {
	// A pointer at offset 12 pointing to itself must not hang.
	msg := make([]byte, 14)
	msg[12] = 0xC0
	msg[13] = 0x0C // points to offset 12 → cycle
	if _, _, ok := readName(msg, 12); ok {
		t.Error("pointer cycle should fail, not loop forever")
	}
}
