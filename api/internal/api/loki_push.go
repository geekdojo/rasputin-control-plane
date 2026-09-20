package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"strconv"
	"strings"

	"github.com/klauspost/compress/s2"
)

// The logs half of the ingress identity rule (§5.2 "attribution"): the
// authenticated channel decides who a write belongs to, and one label —
// node_id — is stamped by the SERVER on every write path.
//
// The metrics half gets that for free: VictoriaMetrics' extra_label overrides
// whatever the payload carried, so handleObsIngest forwards the body unread
// apart from the reserved-name check. Loki has no extra_label equivalent, so
// the logs half is done here instead: each stream's label set is parsed,
// node_id is replaced with the verified client leaf's CommonName, and the
// request is re-encoded. A reserved job label is refused outright rather than
// rewritten, because there is no node it could correctly belong to — those
// streams come from the controlplane's own Alloy, which writes straight to
// Loki over the compose network and never passes through this ingress.

// maxLokiPushBytes caps a collector's log push, compressed and decompressed
// alike. It exists because the ingress holds the whole request in memory to
// rewrite it (see rewriteLokiPush) before forwarding. It matches
// maxRemoteWriteBytes so the two ingress routes have one number, and it is far
// above what a per-node Alloy batches (loki.write flushes at 1MB by default).
const maxLokiPushBytes = 32 << 20

// errLokiPushFormat marks a body the ingress cannot parse as a Loki push
// request. It is refused rather than forwarded unrewritten: an unparseable
// body is one whose node_id the server could not stamp.
var errLokiPushFormat = errors.New("not a snappy-compressed Loki push request")

// Protobuf field numbers from Loki's logproto.PushRequest, fixed by the wire
// format Alloy's loki.write speaks:
//
//	PushRequest   { repeated StreamAdapter streams = 1; }
//	StreamAdapter { string labels = 1; repeated EntryAdapter entries = 2; uint64 hash = 3; }
//
// Only `labels` is read or written. Entries — the log lines themselves — are
// copied byte for byte and never parsed.
const (
	lokiStreamsField = 1
	lokiLabelsField  = 1
	lokiHashField    = 3
)

// Stream labels the ingress is opinionated about.
const (
	// lokiNodeIDLabel is the one label the server owns on this path.
	lokiNodeIDLabel = "node_id"
	// lokiJobLabel names the log stream's producer. The controlplane reserves
	// a prefix of it (obs.IsReservedLogJob).
	lokiJobLabel = "job"
)

// lokiPushV1 checks the request headers name the one format the ingress can
// rewrite: Loki's protobuf push, snappy-compressed. Per-node Alloy sends
// exactly that. Loki itself also accepts JSON, but no collector the
// controlplane renders emits it, and a format the ingress cannot rewrite is a
// format whose node_id it cannot stamp — so it is refused rather than passed
// through.
func lokiPushV1(contentType, contentEncoding string) error {
	if enc := strings.TrimSpace(contentEncoding); enc != "" && !strings.EqualFold(enc, "snappy") {
		return fmt.Errorf("content-encoding %q: %w", enc, errLokiPushFormat)
	}
	if contentType == "" {
		return nil
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("content-type %q: %w", contentType, errLokiPushFormat)
	}
	if mt != "application/x-protobuf" {
		return fmt.Errorf("content-type %q: %w", contentType, errLokiPushFormat)
	}
	return nil
}

// rewriteLokiPush returns a snappy-compressed Loki push body in which EVERY
// stream carries node_id=nodeID, whatever the caller sent. When a stream's job
// label is reserved for the controlplane it returns that job name instead, and
// no body: the whole request is refused, because a push is one collector's
// batch and a batch containing a forged stream is not partially trustworthy.
//
// Hand-decoded rather than via generated protobuf types, for the same reason
// reservedSeriesName is: the api module has no protobuf dependency and the two
// messages touched here are fixed by Loki's push format. Fields other than
// `labels` are copied verbatim — including ones this code does not know — so a
// newer Alloy's additions survive the round trip unread.
//
// The stream `hash` field is dropped on every stream. It is a cache of the
// label set's hash, and the label set has just changed; Loki derives it from
// the labels string itself, so omitting it is the same as never having sent it.
func rewriteLokiPush(compressed []byte, nodeID string, reservedJob func(string) bool) (out []byte, refusedJob string, err error) {
	n, err := s2.DecodedLen(compressed)
	if err != nil {
		return nil, "", fmt.Errorf("snappy: %v: %w", err, errLokiPushFormat)
	}
	if n > maxLokiPushBytes {
		return nil, "", fmt.Errorf("decompressed size %d exceeds %d bytes: %w", n, maxLokiPushBytes, errLokiPushFormat)
	}
	body, err := s2.Decode(nil, compressed)
	if err != nil {
		return nil, "", fmt.Errorf("snappy: %v: %w", err, errLokiPushFormat)
	}
	top, err := protoFields(body)
	if err != nil {
		return nil, "", fmt.Errorf("protobuf: %v: %w", err, errLokiPushFormat)
	}
	rewritten := make([]byte, 0, len(body))
	for _, f := range top {
		if f.num != lokiStreamsField || f.payload == nil {
			rewritten = append(rewritten, f.raw...)
			continue
		}
		stream, refused, err := rewriteLokiStream(f.payload, nodeID, reservedJob)
		if err != nil {
			return nil, "", fmt.Errorf("protobuf: %v: %w", err, errLokiPushFormat)
		}
		if refused != "" {
			return nil, refused, nil
		}
		rewritten = appendLenDelim(rewritten, lokiStreamsField, stream)
	}
	return s2.EncodeSnappy(nil, rewritten), "", nil
}

// rewriteLokiStream rebuilds one StreamAdapter with node_id stamped, or
// reports the reserved job label that makes the stream inadmissible.
func rewriteLokiStream(stream []byte, nodeID string, reservedJob func(string) bool) (out []byte, refusedJob string, err error) {
	fields, err := protoFields(stream)
	if err != nil {
		return nil, "", err
	}
	// Last wins, as protobuf says for a repeated scalar read as singular.
	// Absent is the empty label set, which the stamp then fills in.
	labels := ""
	for _, f := range fields {
		if f.num == lokiLabelsField && f.payload != nil {
			labels = string(f.payload)
		}
	}
	pairs, err := parseLokiLabels(labels)
	if err != nil {
		return nil, "", err
	}
	for _, p := range pairs {
		if p.name == lokiJobLabel && reservedJob != nil && reservedJob(p.value) {
			return nil, p.value, nil
		}
	}
	pairs = setLokiLabel(pairs, lokiNodeIDLabel, nodeID)
	out = appendLenDelim(out, lokiLabelsField, []byte(formatLokiLabels(pairs)))
	for _, f := range fields {
		// The labels field is replaced above; the hash is a stale cache of
		// the label set that just changed.
		if f.num == lokiLabelsField || f.num == lokiHashField {
			continue
		}
		out = append(out, f.raw...)
	}
	return out, "", nil
}

// ----- label strings ------------------------------------------------------

// A Loki stream carries its labels as one Prometheus-style string —
// `{container="db", node_id="c02"}` — not as protobuf fields, so stamping
// node_id means parsing and re-rendering that string.

type lokiLabel struct{ name, value string }

// parseLokiLabels parses a stream's label string into its pairs, in order.
// Strict by design: anything that is not the exact shape Prometheus'
// labels.Labels.String() emits — which is what Alloy sends — is an error, and
// the request is then refused rather than stamped on a guess. A duplicate
// label name is an error for the same reason: which of two node_id or job
// values the ingress was meant to judge is not answerable.
func parseLokiLabels(s string) ([]lokiLabel, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, errors.New("label set is not brace-delimited")
	}
	rest := strings.TrimSpace(s[1 : len(s)-1])
	var out []lokiLabel
	seen := map[string]bool{}
	for rest != "" {
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return nil, errors.New("label without a value")
		}
		name := strings.TrimSpace(rest[:eq])
		if !validLabelName(name) {
			return nil, fmt.Errorf("invalid label name %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate label %q", name)
		}
		seen[name] = true
		rest = strings.TrimSpace(rest[eq+1:])
		quoted, n := scanQuoted(rest)
		if n == 0 {
			return nil, fmt.Errorf("label %q has no quoted value", name)
		}
		value, err := strconv.Unquote(quoted)
		if err != nil {
			return nil, fmt.Errorf("label %q: %v", name, err)
		}
		out = append(out, lokiLabel{name: name, value: value})
		rest = strings.TrimSpace(rest[n:])
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return nil, errors.New("labels are not comma-separated")
		}
		rest = strings.TrimSpace(rest[1:])
		if rest == "" {
			return nil, errors.New("trailing comma in label set")
		}
	}
	return out, nil
}

// scanQuoted returns the leading Go-quoted string of s (including both quotes)
// and how many bytes it spans, or n=0 when s does not start with a complete
// quoted string.
func scanQuoted(s string) (quoted string, n int) {
	if s == "" || s[0] != '"' {
		return "", 0
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip the escaped byte, whatever it is
		case '"':
			return s[:i+1], i + 1
		}
	}
	return "", 0
}

// validLabelName reports whether name is a Prometheus/Loki label name:
// [a-zA-Z_][a-zA-Z0-9_]*.
func validLabelName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// setLokiLabel replaces name's value in place, or appends the pair when the
// label was absent. In place so a rewritten stream keeps the caller's label
// order and the diff against what it sent is exactly the one value.
func setLokiLabel(pairs []lokiLabel, name, value string) []lokiLabel {
	for i := range pairs {
		if pairs[i].name == name {
			pairs[i].value = value
			return pairs
		}
	}
	return append(pairs, lokiLabel{name: name, value: value})
}

// formatLokiLabels renders pairs back into the stream label string Loki parses.
// Values go through strconv.Quote, so a node id or a container name carrying a
// quote, a backslash or a newline cannot break out of its value.
func formatLokiLabels(pairs []lokiLabel) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.name)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(p.value))
	}
	b.WriteByte('}')
	return b.String()
}

// ----- protobuf ------------------------------------------------------------

// protoField is one field of a protobuf message: its number, the raw bytes of
// the whole field (key included, so it can be copied verbatim), and — for
// length-delimited fields only — the payload those bytes carry.
type protoField struct {
	num     uint64
	raw     []byte
	payload []byte
}

// protoFields splits a protobuf message into its top-level fields without
// interpreting any of them. Unlike walkFields (remote_write.go), which only
// needs to look inside length-delimited fields, this keeps every field's raw
// bytes so a message can be rebuilt with one field replaced and the rest
// untouched. Groups (deprecated, never used by Loki) and truncated input are
// errors.
func protoFields(b []byte) ([]protoField, error) {
	var out []protoField
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad field key")
		}
		field, wire := key>>3, key&7
		rest := b[n:]
		var size int
		var payload []byte
		switch wire {
		case 0: // varint
			_, vn := binary.Uvarint(rest)
			if vn <= 0 {
				return nil, errors.New("bad varint")
			}
			size = vn
		case 1: // fixed64
			if len(rest) < 8 {
				return nil, errors.New("truncated fixed64")
			}
			size = 8
		case 2: // length-delimited
			l, ln := binary.Uvarint(rest)
			// No field can be longer than the whole decoded request, which
			// is capped; bounding l by that constant first keeps the int
			// conversion exact.
			if ln <= 0 || l > maxLokiPushBytes {
				return nil, errors.New("bad length")
			}
			size = ln + int(l)
			if size > len(rest) {
				return nil, errors.New("bad length")
			}
			payload = rest[ln:size]
		case 5: // fixed32
			if len(rest) < 4 {
				return nil, errors.New("truncated fixed32")
			}
			size = 4
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wire)
		}
		out = append(out, protoField{num: field, raw: b[:n+size], payload: payload})
		b = b[n+size:]
	}
	return out, nil
}

// appendLenDelim appends a length-delimited field to dst.
func appendLenDelim(dst []byte, field uint64, payload []byte) []byte {
	dst = binary.AppendUvarint(dst, field<<3|2)
	dst = binary.AppendUvarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}
