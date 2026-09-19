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

// Minimal remote-write 1.0 encoder for tests: the same three messages
// reservedSeriesName walks, plus a sample so each series looks like what a
// collector sends.

func pbBytes(field uint64, b []byte) []byte {
	out := binary.AppendUvarint(nil, field<<3|2)
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}

func pbLabel(name, value string) []byte {
	return append(pbBytes(1, []byte(name)), pbBytes(2, []byte(value))...)
}

// series encodes a TimeSeries whose labels are __name__=name then the given
// key/value pairs, followed by one sample (value fixed64, timestamp varint).
func series(name string, kv ...string) []byte {
	var ts []byte
	ts = append(ts, pbBytes(1, pbLabel("__name__", name))...)
	for i := 0; i+1 < len(kv); i += 2 {
		ts = append(ts, pbBytes(1, pbLabel(kv[i], kv[i+1]))...)
	}
	sample := append([]byte{1<<3 | 1}, make([]byte, 8)...) // value = 0 (fixed64)
	sample = append(sample, 2<<3)                          // timestamp: field 2, wire type 0 (varint)
	sample = binary.AppendUvarint(sample, 1789836786000)
	return append(ts, pbBytes(2, sample)...)
}

// remoteWriteBody snappy-encodes a WriteRequest holding the given series.
func remoteWriteBody(ss ...[]byte) []byte {
	var req []byte
	for _, s := range ss {
		req = append(req, pbBytes(1, s)...)
	}
	return s2.EncodeSnappy(nil, req)
}

func TestReservedSeriesName(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"ordinary series", remoteWriteBody(series("container_memory_working_set_bytes", "name", "db")), ""},
		{"empty request", remoteWriteBody(), ""},
		{"host metric name", remoteWriteBody(series("rasputin_cpu_percent", "nodeId", "other-node")), "rasputin_cpu_percent"},
		{"vmalert state", remoteWriteBody(series("ALERTS", "alertname", "HighCPU", "alertstate", "firing")), "ALERTS"},
		{"vmalert activation", remoteWriteBody(series("ALERTS_FOR_STATE", "alertname", "HighCPU")), "ALERTS_FOR_STATE"},
		{"reserved series after an ordinary one", remoteWriteBody(
			series("container_cpu_usage_seconds_total"), series("rasputin_disk_used_bytes")), "rasputin_disk_used_bytes"},
		{"reserved value on a non-name label is fine", remoteWriteBody(series("up", "job", "ALERTS")), ""},
	}
	// Fields of every scalar wire type are skipped by their exact width, so
	// a reserved name after them is still found.
	var scalars []byte
	scalars = append(scalars, 5<<3, 0x96, 0x01)               // varint
	scalars = append(scalars, 6<<3|1, 1, 2, 3, 4, 5, 6, 7, 8) // fixed64
	scalars = append(scalars, 7<<3|5, 1, 2, 3, 4)             // fixed32
	scalars = append(scalars, pbBytes(1, series("ALERTS_FOR_STATE"))...)
	cases = append(cases, struct {
		name string
		body []byte
		want string
	}{"after scalar fields", s2.EncodeSnappy(nil, scalars), "ALERTS_FOR_STATE"})
	// A fixed-width field that ends the message exactly is complete, not
	// truncated.
	for _, tail := range [][]byte{
		{6<<3 | 1, 1, 2, 3, 4, 5, 6, 7, 8}, // fixed64
		{7<<3 | 5, 1, 2, 3, 4},             // fixed32
	} {
		body := append(pbBytes(1, series("ALERTS")), tail...)
		cases = append(cases, struct {
			name string
			body []byte
			want string
		}{"ends on a fixed-width field", s2.EncodeSnappy(nil, body), "ALERTS"})
	}
	// A series whose __name__ label is not first is still found.
	var late []byte
	late = append(late, pbBytes(1, pbLabel("nodeId", "x"))...)
	late = append(late, pbBytes(1, pbLabel("__name__", "ALERTS"))...)
	cases = append(cases, struct {
		name string
		body []byte
		want string
	}{"name label not first", s2.EncodeSnappy(nil, pbBytes(1, late)), "ALERTS"})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := reservedSeriesName(tc.body, obs.IsReservedMetricName)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReservedSeriesName_RefusesWhatItCannotRead(t *testing.T) {
	raw := pbBytes(1, series("up"))
	for name, body := range map[string][]byte{
		"not snappy":          []byte("snappy-remote-write-bytes"),
		"truncated protobuf":  s2.EncodeSnappy(nil, raw[:len(raw)-3]),
		"group wire type":     s2.EncodeSnappy(nil, []byte{1<<3 | 3}),
		"length past the end": s2.EncodeSnappy(nil, []byte{1<<3 | 2, 0x7f}),
		"truncated key":       s2.EncodeSnappy(nil, []byte{0x80}),
		"truncated varint":    s2.EncodeSnappy(nil, []byte{3 << 3, 0x80}),
		"truncated fixed64":   s2.EncodeSnappy(nil, []byte{3<<3 | 1, 1, 2, 3}),
		"truncated fixed32":   s2.EncodeSnappy(nil, []byte{3<<3 | 5, 1, 2}),
		// A malformed Label inside an otherwise well-formed TimeSeries.
		"malformed label": s2.EncodeSnappy(nil, pbBytes(1, pbBytes(1, []byte{1<<3 | 2, 0x7f}))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := reservedSeriesName(body, obs.IsReservedMetricName); !errors.Is(err, errRemoteWriteFormat) {
				t.Fatalf("err = %v, want errRemoteWriteFormat", err)
			}
		})
	}
}

func TestRemoteWriteV1Headers(t *testing.T) {
	for _, tc := range []struct {
		ct, enc string
		ok      bool
	}{
		{"application/x-protobuf", "snappy", true},
		{"", "", true},
		{"application/x-protobuf;proto=prometheus.WriteRequest", "snappy", true},
		{"application/x-protobuf;proto=io.prometheus.write.v2.Request", "snappy", false},
		{"application/x-protobuf", "zstd", false},
		{"application/json", "snappy", false},
		{"not a media type;;", "snappy", false},
	} {
		err := remoteWriteV1(tc.ct, tc.enc)
		if (err == nil) != tc.ok {
			t.Errorf("remoteWriteV1(%q, %q) = %v, want ok=%v", tc.ct, tc.enc, err, tc.ok)
		}
	}
}

// End to end through the ingress handler: a push carrying a reserved name is
// refused and never reaches VictoriaMetrics.
func TestHandleObsIngest_RefusesReservedMetricNames(t *testing.T) {
	var vmCalls atomic.Int32
	stubVM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vmCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stubVM.Close()
	s := newIngestServer(t, obs.NewStatus(fakeVMSup{vmBase: stubVM.URL}, nil, nil), "c02")

	push := func(body []byte, ct, enc string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/obs/ingest", bytes.NewReader(body))
		req.TLS = certState("c02")
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Content-Encoding", enc)
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, req)
		return rec
	}
	for _, name := range []string{"rasputin_cpu_percent", "ALERTS", "ALERTS_FOR_STATE"} {
		rec := push(remoteWriteBody(series("container_cpu_usage_seconds_total"), series(name, "nodeId", "c01")),
			"application/x-protobuf", "snappy")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reserved") {
			t.Errorf("%s: got %d %q, want 400 naming the reserved metric", name, rec.Code, rec.Body.String())
		}
	}
	if rec := push(remoteWriteBody(series("up")), "application/x-protobuf;proto=io.prometheus.write.v2.Request", "snappy"); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("remote-write 2.0: got %d, want 415", rec.Code)
	}
	if rec := push([]byte("garbage"), "application/x-protobuf", "snappy"); rec.Code != http.StatusBadRequest {
		t.Errorf("garbage body: got %d, want 400", rec.Code)
	}
	if rec := push(make([]byte, maxRemoteWriteBytes+1), "application/x-protobuf", "snappy"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: got %d, want 413", rec.Code)
	}
	if n := vmCalls.Load(); n != 0 {
		t.Fatalf("VM received %d refused pushes, want 0", n)
	}
	if rec := push(remoteWriteBody(series("container_cpu_usage_seconds_total")), "application/x-protobuf", "snappy"); rec.Code != http.StatusNoContent {
		t.Fatalf("ordinary push: got %d %q, want 204", rec.Code, rec.Body.String())
	}
	if n := vmCalls.Load(); n != 1 {
		t.Fatalf("VM calls = %d, want 1", n)
	}
}
