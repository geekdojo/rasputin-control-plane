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

// A response whose header declares an=1 but which carries a second, matching A
// record in trailing bytes must NOT be resolved — parseAnswer must stop after
// the declared answer count. Guards the `i < an` loop bound (and its counter
// direction) against reading past the declared answers.
func TestParseAnswer_HonorsAnswerCount(t *testing.T) {
	const typeTXT = 16
	tail := []byte{
		// answer 0 (the only declared answer): a non-matching TXT record.
		0xC0, 0x0C,
		0, typeTXT, 0, classIN,
		0, 0, 0, 120,
		0, 1, // rdlength = 1
		'x',
		// trailing, UNDECLARED answer: a valid A record for the wanted name.
		// Reachable only if the answer loop runs more than an==1 iterations.
		0xC0, 0x0C,
		0, typeA, 0, classIN,
		0, 0, 0, 120,
		0, 4,
		192, 168, 1, 50,
	}
	msg := answerPacket("rasputin.local", 1, tail) // header says one answer
	if got := parseAnswer(msg, "rasputin.local"); got != "" {
		t.Errorf("parseAnswer read past the declared answer count: got %q, want \"\"", got)
	}
}

// readName caps its decode loop at 128 steps to defeat pointer cycles; that cap
// also bounds a pathological chain of uncompressed labels. A name of exactly 128
// one-byte labels must be rejected (the 128th step exhausts the bound before the
// terminator is read), while 127 labels resolves. Guards the `steps < 128` bound
// against being loosened to `<= 128`.
func TestReadName_LabelCountBound(t *testing.T) {
	build := func(n int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, 1, 'a')
		}
		return append(b, 0) // terminating root label
	}
	if _, _, ok := readName(build(127), 0); !ok {
		t.Error("127 one-byte labels are within the 128-step bound, want ok")
	}
	if _, _, ok := readName(build(128), 0); ok {
		t.Error("128 one-byte labels exhaust the 128-step bound, want failure")
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

// A label of exactly 63 bytes is the longest a DNS label may be (RFC 1035
// §2.3.4); buildQuery must accept it and reject 64. Guards the `> 63` bound
// against being loosened to `>= 63`.
func TestBuildQuery_LabelLengthBoundary(t *testing.T) {
	if _, err := buildQuery(strings.Repeat("a", 63) + ".local"); err != nil {
		t.Errorf("63-byte label is valid, got error: %v", err)
	}
	if _, err := buildQuery(strings.Repeat("a", 64) + ".local"); err == nil {
		t.Error("64-byte label exceeds the DNS limit, want error")
	}
}

// A name whose labels consume the entire buffer with no terminating zero must
// fail rather than read past the end. Guards the `cur >= len(msg)` bound.
func TestReadName_UnterminatedRunsToEnd(t *testing.T) {
	msg := []byte{3, 'a', 'b', 'c'} // label "abc" ends exactly at len, no root 0
	if _, _, ok := readName(msg, 0); ok {
		t.Error("name with no terminating zero should fail")
	}
}

// A compression pointer is two bytes; a lone 0xC0 at the buffer's end must fail
// rather than read its missing second byte. Guards the `cur+1 >= len(msg)` bound.
func TestReadName_TruncatedPointer(t *testing.T) {
	msg := []byte{0xC0} // pointer high byte with no low byte following
	if _, _, ok := readName(msg, 0); ok {
		t.Error("truncated compression pointer should fail")
	}
}

// A label byte claiming more bytes than remain must fail rather than slice past
// the end. Guards the `cur+1+l > len(msg)` bound.
func TestReadName_TruncatedLabel(t *testing.T) {
	msg := []byte{3, 'a', 'b'} // length byte says 3, only 2 chars follow
	if _, _, ok := readName(msg, 0); ok {
		t.Error("label overrunning the buffer should fail")
	}
}

// answerPacket builds header + question + the given answer-record tail, so tests
// can craft truncated/multi-answer responses. anCount is written into the
// header; the answer owner is a compression pointer back to the question (0xC00C).
func answerPacket(name string, anCount byte, answerTail []byte) []byte {
	var b []byte
	b = append(b, 0, 0, 0x84, 0, 0, 1, 0, anCount, 0, 0, 0, 0) // response/AA, qd=1
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = append(b, 0, typeA, 0, classIN) // question qtype/qclass
	return append(b, answerTail...)
}

// A response whose answer owner name is present but which then ends before the
// 10-byte fixed answer fields (type/class/ttl/rdlength) must yield "" rather
// than read out of bounds. Guards the `o+10 > len(msg)` check.
func TestParseAnswer_TruncatedAnswerHeader(t *testing.T) {
	// Answer tail: just the owner pointer, nothing after it.
	msg := answerPacket("rasputin.local", 1, []byte{0xC0, 0x0C})
	if got := parseAnswer(msg, "rasputin.local"); got != "" {
		t.Errorf("truncated answer header should yield empty, got %q", got)
	}
}

// A matching A record that declares rdlength=4 but is truncated before its 4
// address bytes must yield "" rather than read out of bounds. Guards the
// `rdStart+rdlen > len(msg)` check.
func TestParseAnswer_TruncatedRData(t *testing.T) {
	tail := []byte{
		0xC0, 0x0C, // owner = pointer to question
		0, typeA, 0, classIN, // type A, class IN
		0, 0, 0, 120, // ttl
		0, 4, // rdlength = 4
		192, 168, // only 2 of the 4 promised address bytes
	}
	msg := answerPacket("rasputin.local", 1, tail)
	if got := parseAnswer(msg, "rasputin.local"); got != "" {
		t.Errorf("truncated rdata should yield empty, got %q", got)
	}
}

// With two answers where the first is a non-A record, parseAnswer must advance
// past the first (off = rdStart + rdlen) to find the matching A answer.
// Guards the record-advance arithmetic against being flipped to subtraction.
func TestParseAnswer_SkipsFirstAnswerToMatch(t *testing.T) {
	const typeTXT = 16
	tail := []byte{
		// answer 1: TXT (non-A) for the same owner — must be skipped.
		0xC0, 0x0C,
		0, typeTXT, 0, classIN,
		0, 0, 0, 120,
		0, 1, // rdlength = 1
		'x', // rdata
		// answer 2: the A record we want.
		0xC0, 0x0C,
		0, typeA, 0, classIN,
		0, 0, 0, 120,
		0, 4,
		192, 168, 1, 50,
	}
	msg := answerPacket("rasputin.local", 2, tail)
	if got := parseAnswer(msg, "rasputin.local"); got != "192.168.1.50" {
		t.Errorf("parseAnswer = %q, want 192.168.1.50 (must skip first answer)", got)
	}
}
