package api

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/s2"

	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
)

// Minimal Loki push encoder for tests — the two messages rewriteLokiPush
// touches, plus an entry so each stream looks like what a collector sends.
//
//	PushRequest   { repeated StreamAdapter streams = 1; }
//	StreamAdapter { string labels = 1; repeated EntryAdapter entries = 2; uint64 hash = 3; }
//	EntryAdapter  { Timestamp timestamp = 1; string line = 2; }

// lokiEntry encodes one EntryAdapter: an empty Timestamp message and the line.
func lokiEntry(line string) []byte {
	return append(pbBytes(1, nil), pbBytes(2, []byte(line))...)
}

// lokiStream encodes a StreamAdapter with the given label string, a hash, and
// one entry per line.
func lokiStream(labels string, lines ...string) []byte {
	out := pbBytes(1, []byte(labels))
	for _, l := range lines {
		out = append(out, pbBytes(2, lokiEntry(l))...)
	}
	// hash = 7 (varint, field 3) — a value the ingress must drop.
	out = append(out, 3<<3)
	return binary.AppendUvarint(out, 7)
}

// lokiPushBody snappy-encodes a PushRequest holding the given streams.
func lokiPushBody(streams ...[]byte) []byte {
	var req []byte
	for _, s := range streams {
		req = append(req, pbBytes(1, s)...)
	}
	return s2.EncodeSnappy(nil, req)
}

// decodedStream is one stream read back out of a rewritten push body.
type decodedStream struct {
	labels  string
	lines   []string
	hashSet bool
	extra   []uint64 // field numbers other than labels/entries/hash
}

// decodeLokiPush reads a snappy push body back into its streams, so a test can
// assert on what the ingress produced rather than on opaque bytes.
func decodeLokiPush(t *testing.T, compressed []byte) []decodedStream {
	t.Helper()
	body, err := s2.Decode(nil, compressed)
	if err != nil {
		t.Fatalf("snappy decode: %v", err)
	}
	top, err := protoFields(body)
	if err != nil {
		t.Fatalf("protoFields: %v", err)
	}
	var out []decodedStream
	for _, f := range top {
		if f.num != lokiStreamsField {
			continue
		}
		fields, err := protoFields(f.payload)
		if err != nil {
			t.Fatalf("protoFields(stream): %v", err)
		}
		var ds decodedStream
		for _, sf := range fields {
			switch sf.num {
			case lokiLabelsField:
				ds.labels = string(sf.payload)
			case 2:
				entry, err := protoFields(sf.payload)
				if err != nil {
					t.Fatalf("protoFields(entry): %v", err)
				}
				for _, ef := range entry {
					if ef.num == 2 {
						ds.lines = append(ds.lines, string(ef.payload))
					}
				}
			case lokiHashField:
				ds.hashSet = true
			default:
				ds.extra = append(ds.extra, sf.num)
			}
		}
		out = append(out, ds)
	}
	return out
}

func TestRewriteLokiPush(t *testing.T) {
	cases := []struct {
		name       string
		body       []byte
		wantLabels []string
		wantLines  [][]string
	}{
		{
			name:       "node_id the collector claimed is overwritten",
			body:       lokiPushBody(lokiStream(`{container="db", node_id="some-other-node"}`, "boom")),
			wantLabels: []string{`{container="db", node_id="c02"}`},
			wantLines:  [][]string{{"boom"}},
		},
		{
			name:       "absent node_id is added",
			body:       lokiPushBody(lokiStream(`{container="db"}`, "line")),
			wantLabels: []string{`{container="db", node_id="c02"}`},
			wantLines:  [][]string{{"line"}},
		},
		{
			name:       "empty label set still gets the stamp",
			body:       lokiPushBody(lokiStream(`{}`, "line")),
			wantLabels: []string{`{node_id="c02"}`},
			wantLines:  [][]string{{"line"}},
		},
		{
			name: "every stream in a batch is stamped",
			body: lokiPushBody(
				lokiStream(`{container="a", node_id="c02"}`, "one"),
				lokiStream(`{container="b", node_id="fw-1"}`, "two", "three"),
			),
			wantLabels: []string{`{container="a", node_id="c02"}`, `{container="b", node_id="c02"}`},
			wantLines:  [][]string{{"one"}, {"two", "three"}},
		},
		{
			name:       "a value carrying a quote cannot break out",
			body:       lokiPushBody(lokiStream(`{container="he said \"hi\"", node_id="x"}`, "l")),
			wantLabels: []string{`{container="he said \"hi\"", node_id="c02"}`},
			wantLines:  [][]string{{"l"}},
		},
		{
			name:       "an unreserved job label is left alone",
			body:       lokiPushBody(lokiStream(`{job="varlogs", node_id="x"}`, "l")),
			wantLabels: []string{`{job="varlogs", node_id="c02"}`},
			wantLines:  [][]string{{"l"}},
		},
		{
			name:       "empty request",
			body:       lokiPushBody(),
			wantLabels: nil,
			wantLines:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, refused, err := rewriteLokiPush(tc.body, "c02", obs.IsReservedLogJob)
			if err != nil {
				t.Fatalf("rewriteLokiPush: %v", err)
			}
			if refused != "" {
				t.Fatalf("refused %q, want none", refused)
			}
			got := decodeLokiPush(t, out)
			if len(got) != len(tc.wantLabels) {
				t.Fatalf("got %d streams, want %d", len(got), len(tc.wantLabels))
			}
			for i, s := range got {
				if s.labels != tc.wantLabels[i] {
					t.Errorf("stream %d labels: got %s, want %s", i, s.labels, tc.wantLabels[i])
				}
				if strings.Join(s.lines, "\x00") != strings.Join(tc.wantLines[i], "\x00") {
					t.Errorf("stream %d lines: got %q, want %q", i, s.lines, tc.wantLines[i])
				}
				if s.hashSet {
					t.Errorf("stream %d still carries the stale label hash", i)
				}
			}
		})
	}
}

// A job label reserved for the controlplane is refused — the whole push, not
// just the offending stream — and nothing is returned to forward.
func TestRewriteLokiPush_RefusesReservedJobs(t *testing.T) {
	for _, job := range []string{obs.IDSLogJob, "rasputin-anything"} {
		body := lokiPushBody(
			lokiStream(`{container="db", node_id="c02"}`, "ordinary"),
			lokiStream(`{job="`+job+`", node_id="fw-1"}`, `{"nodeId":"fw-1","sid":1}`),
		)
		out, refused, err := rewriteLokiPush(body, "c02", obs.IsReservedLogJob)
		if err != nil {
			t.Fatalf("%s: %v", job, err)
		}
		if refused != job {
			t.Errorf("%s: refused = %q, want %q", job, refused, job)
		}
		if out != nil {
			t.Errorf("%s: a refused push must return no body", job)
		}
	}
}

// Fields the ingress does not know — a newer Alloy's additions, at either
// level — survive the round trip untouched.
func TestRewriteLokiPush_PreservesUnknownFields(t *testing.T) {
	stream := lokiStream(`{container="db"}`, "line")
	stream = append(stream, pbBytes(9, []byte("structured-metadata"))...)
	body := lokiPushBody(stream)
	// A top-level field that is not `streams`.
	raw, err := s2.Decode(nil, body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw = append(raw, pbBytes(4, []byte("tenant"))...)
	body = s2.EncodeSnappy(nil, raw)

	out, refused, err := rewriteLokiPush(body, "c02", obs.IsReservedLogJob)
	if err != nil || refused != "" {
		t.Fatalf("rewriteLokiPush: err=%v refused=%q", err, refused)
	}
	decoded, err := s2.Decode(nil, out)
	if err != nil {
		t.Fatalf("decode rewritten: %v", err)
	}
	if !bytes.Contains(decoded, []byte("tenant")) {
		t.Error("the unknown top-level field was dropped")
	}
	if !bytes.Contains(decoded, []byte("structured-metadata")) {
		t.Error("the unknown stream field was dropped")
	}
	streams := decodeLokiPush(t, out)
	if len(streams) != 1 || len(streams[0].extra) != 1 || streams[0].extra[0] != 9 {
		t.Errorf("stream fields: got %+v, want the unknown field 9 kept", streams)
	}
}

func TestRewriteLokiPush_RefusesUnparseable(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"not snappy", []byte("garbage")},
		{"not protobuf", s2.EncodeSnappy(nil, []byte{0xff, 0xff, 0xff})},
		{"truncated stream", s2.EncodeSnappy(nil, []byte{1<<3 | 2, 9, 'a'})},
		{"labels are not brace-delimited", lokiPushBody(lokiStream(`container="db"`, "l"))},
		{"labels value is unquoted", lokiPushBody(lokiStream(`{container=db}`, "l"))},
		{"labels value is unterminated", lokiPushBody(lokiStream(`{container="db}`, "l"))},
		{"duplicate label", lokiPushBody(lokiStream(`{node_id="a", node_id="b"}`, "l"))},
		{"invalid label name", lokiPushBody(lokiStream(`{1container="db"}`, "l"))},
		{"trailing comma", lokiPushBody(lokiStream(`{container="db",}`, "l"))},
		{"group wire type", s2.EncodeSnappy(nil, []byte{1<<3 | 3})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, refused, err := rewriteLokiPush(tc.body, "c02", obs.IsReservedLogJob)
			if !errors.Is(err, errLokiPushFormat) {
				t.Fatalf("err = %v, want errLokiPushFormat", err)
			}
			if out != nil || refused != "" {
				t.Errorf("out=%v refused=%q, want neither", out, refused)
			}
		})
	}
	// A body that claims to decompress to more than the cap is refused before
	// it is decompressed.
	huge := binary.AppendUvarint(nil, uint64(maxLokiPushBytes+1))
	huge = append(huge, 0x00, 0x00, 0x00)
	if _, _, err := rewriteLokiPush(huge, "c02", obs.IsReservedLogJob); !errors.Is(err, errLokiPushFormat) {
		t.Errorf("oversized decompressed length: err = %v, want errLokiPushFormat", err)
	}
}

func TestLokiPushV1(t *testing.T) {
	cases := []struct {
		ct, enc string
		ok      bool
	}{
		{"application/x-protobuf", "snappy", true},
		{"", "", true},
		{"application/x-protobuf", "", true},
		{"application/json", "", false},
		{"application/x-protobuf", "gzip", false},
		{"not/a/media/type;;", "", false},
	}
	for _, tc := range cases {
		err := lokiPushV1(tc.ct, tc.enc)
		if (err == nil) != tc.ok {
			t.Errorf("lokiPushV1(%q, %q) = %v, want ok=%v", tc.ct, tc.enc, err, tc.ok)
		}
	}
}

// End to end through the ingress handler: what reaches Loki carries the
// caller's authenticated node id, and a push claiming a reserved job never
// reaches it at all.
func TestHandleObsLogsIngest_StampsNodeID(t *testing.T) {
	var lokiCalls atomic.Int32
	var gotBody []byte
	stubLoki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lokiCalls.Add(1)
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stubLoki.Close()
	s := newIngestServer(t, obs.NewStatus(fakeVMSup{lokiBase: stubLoki.URL}, nil, nil), "c02")

	push := func(body []byte, ct, enc string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", bytes.NewReader(body))
		req.TLS = certState("c02")
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Content-Encoding", enc)
		rec := httptest.NewRecorder()
		s.handleObsLogsIngest(rec, req)
		return rec
	}

	// A collector claiming another node's logs: accepted, but relabelled.
	rec := push(lokiPushBody(lokiStream(`{container="db", node_id="fw-1"}`, "line")),
		"application/x-protobuf", "snappy")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ordinary push: got %d %q, want 204", rec.Code, rec.Body.String())
	}
	streams := decodeLokiPush(t, gotBody)
	if len(streams) != 1 || streams[0].labels != `{container="db", node_id="c02"}` {
		t.Fatalf("Loki received %+v, want node_id rewritten to the authenticated node", streams)
	}
	if len(streams[0].lines) != 1 || streams[0].lines[0] != "line" {
		t.Errorf("log lines: got %q, want them forwarded unchanged", streams[0].lines)
	}

	before := lokiCalls.Load()
	if rec := push(lokiPushBody(lokiStream(`{job="`+obs.IDSLogJob+`", node_id="fw-1"}`, "forged")),
		"application/x-protobuf", "snappy"); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "reserved") {
		t.Errorf("reserved job: got %d %q, want 400 naming the reserved job", rec.Code, rec.Body.String())
	}
	if rec := push(lokiPushBody(lokiStream(`{container="db"}`, "l")), "application/json", ""); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("json push: got %d, want 415", rec.Code)
	}
	if rec := push([]byte("garbage"), "application/x-protobuf", "snappy"); rec.Code != http.StatusBadRequest {
		t.Errorf("garbage body: got %d, want 400", rec.Code)
	}
	if rec := push(make([]byte, maxLokiPushBytes+1), "application/x-protobuf", "snappy"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: got %d, want 413", rec.Code)
	}
	if n := lokiCalls.Load(); n != before {
		t.Fatalf("Loki received %d refused pushes, want 0", n-before)
	}
}

// The reserved-job rule and the controlplane's own IDS pipe must not drift
// apart: the job label the CP's Alloy writes is exactly the one the ingress
// refuses from a node.
func TestIDSLogJobIsReserved(t *testing.T) {
	if !obs.IsReservedLogJob(obs.IDSLogJob) {
		t.Fatalf("IsReservedLogJob(%q) = false", obs.IDSLogJob)
	}
	for _, job := range []string{"varlogs", "syslog", "", "rasputin"} {
		if obs.IsReservedLogJob(job) {
			t.Errorf("IsReservedLogJob(%q) = true, want false", job)
		}
	}
}

// FuzzRewriteLokiPush drives the ingress's log-push rewriter with arbitrary
// bytes: they arrive over mTLS from a node's collector, so they are
// authenticated but not trusted. The invariants are that it never panics, and
// that anything it hands on to Loki carries the caller's node id on every
// stream — checked by re-parsing the output and by re-running the rewrite,
// which must be a fixed point.
func FuzzRewriteLokiPush(f *testing.F) {
	f.Add(lokiPushBody(lokiStream(`{container="db", node_id="fw-1"}`, "line")))
	f.Add(lokiPushBody(lokiStream(`{}`)))
	f.Add(lokiPushBody(lokiStream(`{job="rasputin-ids"}`, "x")))
	f.Add(lokiPushBody(lokiStream(`{a="é", b="\\"}`, "x"), lokiStream(`{c="d"}`)))
	f.Add(lokiPushBody())
	f.Add([]byte("garbage"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		out, refused, err := rewriteLokiPush(body, "c02", obs.IsReservedLogJob)
		if err != nil {
			if !errors.Is(err, errLokiPushFormat) {
				t.Fatalf("error not classified as a format error: %v", err)
			}
			return
		}
		if refused != "" {
			if out != nil {
				t.Fatalf("refused %q but still returned %d bytes", refused, len(out))
			}
			return
		}
		decoded, derr := s2.Decode(nil, out)
		if derr != nil {
			t.Fatalf("output is not snappy: %v", derr)
		}
		fields, ferr := protoFields(decoded)
		if ferr != nil {
			t.Fatalf("output is not protobuf: %v", ferr)
		}
		for _, sf := range fields {
			if sf.num != lokiStreamsField || sf.payload == nil {
				continue
			}
			stream, serr := protoFields(sf.payload)
			if serr != nil {
				t.Fatalf("output stream is not protobuf: %v", serr)
			}
			labels := ""
			for _, lf := range stream {
				if lf.num == lokiLabelsField && lf.payload != nil {
					labels = string(lf.payload)
				}
				if lf.num == lokiHashField {
					t.Fatalf("output stream kept the stale label hash")
				}
			}
			pairs, perr := parseLokiLabels(labels)
			if perr != nil {
				t.Fatalf("output labels %q do not re-parse: %v", labels, perr)
			}
			stamped := false
			for _, p := range pairs {
				if p.name == lokiNodeIDLabel {
					if p.value != "c02" {
						t.Fatalf("output labels %q carry node_id=%q", labels, p.value)
					}
					stamped = true
				}
			}
			if !stamped {
				t.Fatalf("output labels %q carry no node_id", labels)
			}
		}
		// Re-running the rewrite over its own output must change nothing.
		again, refusedAgain, aerr := rewriteLokiPush(out, "c02", obs.IsReservedLogJob)
		if aerr != nil || refusedAgain != "" {
			t.Fatalf("rewrite is not idempotent: err=%v refused=%q", aerr, refusedAgain)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("rewrite is not a fixed point")
		}
	})
}
