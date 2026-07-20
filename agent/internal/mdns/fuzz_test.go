package mdns

import "testing"

// Fuzz harnesses for the mDNS response parser. These packets come straight
// off the network — any host on the LAN can send crafted mDNS responses —
// so the parser must never panic, hang, or read out of bounds on ANY input.
// Go native fuzzing (`go test -fuzz`) explores the malformed-input space far
// beyond the hand-written truncation tests; a crash writes the reproducing
// input to testdata/fuzz/ as a permanent regression seed.
//
// Step 5 of the AI-quality rollout: OSS-Fuzz-Gen (the researched tool) targets
// C/C++ and Rasputin owns no first-party C, so the applicable move is
// Go-native fuzzing of the untrusted-input parsers — starting here, the most
// network-exposed one.

func FuzzParseAnswer(f *testing.F) {
	// Seeds: empty, header-only, and a well-formed A-record answer.
	f.Add([]byte{}, "x.local")
	f.Add(make([]byte, 12), "x.local")
	f.Add([]byte{
		0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, // header: 1 answer
		0x03, 'f', 'o', 'o', 0x05, 'l', 'o', 'c', 'a', 'l', 0, // owner foo.local
		0, 1, 0, 1, 0, 0, 0, 0, 0, 4, // type A, class IN, ttl, rdlen 4
		192, 168, 1, 1, // rdata
	}, "foo.local")
	// A compression pointer pointing back into the header — exercises readName's
	// jump path.
	f.Add([]byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4}, "x")

	f.Fuzz(func(t *testing.T, msg []byte, want string) {
		// No assertion on the result — the contract under test is "never
		// panics / OOB / hangs", which the fuzzer enforces automatically.
		_ = parseAnswer(msg, want)
	})
}

func FuzzReadName(f *testing.F) {
	f.Add([]byte{0x03, 'f', 'o', 'o', 0}, 0)
	f.Add([]byte{0xc0, 0x00}, 0)             // pointer to self — cycle guard
	f.Add([]byte{0x3f}, 0)                    // length byte with no label bytes
	f.Fuzz(func(t *testing.T, msg []byte, off int) {
		if len(msg) == 0 {
			return
		}
		// Constrain off to a valid [0,len) index — readName is only ever
		// called with an in-bounds offset in production, so fuzzing negative/
		// past-end offsets would flag impossible inputs.
		off = ((off % len(msg)) + len(msg)) % len(msg)
		_, _, _ = readName(msg, off)
	})
}
