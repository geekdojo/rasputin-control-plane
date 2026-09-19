package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"strings"

	"github.com/klauspost/compress/s2"
)

// maxRemoteWriteBytes caps a collector's remote-write request, compressed and
// decompressed alike. It is VictoriaMetrics' own default -maxInsertRequestSize,
// so nothing VM itself would have accepted is refused here; it exists because
// the ingress now holds the whole request in memory to check it (see
// reservedSeriesName) before forwarding it.
const maxRemoteWriteBytes = 32 << 20

// errRemoteWriteFormat marks a body the ingress cannot parse as a Prometheus
// remote-write 1.0 request. It is refused rather than forwarded unchecked.
var errRemoteWriteFormat = errors.New("not a snappy-compressed remote-write 1.0 request")

// remoteWriteV1 checks the request headers name the one format the ingress
// can inspect: Prometheus remote-write 1.0 (prometheus.WriteRequest),
// snappy-compressed. Per-node Alloy sends exactly that. Anything else —
// remote-write 2.0, another compression — is refused rather than passed
// through unread.
func remoteWriteV1(contentType, contentEncoding string) error {
	if enc := strings.TrimSpace(contentEncoding); enc != "" && !strings.EqualFold(enc, "snappy") {
		return fmt.Errorf("content-encoding %q: %w", enc, errRemoteWriteFormat)
	}
	if contentType == "" {
		return nil
	}
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("content-type %q: %w", contentType, errRemoteWriteFormat)
	}
	if mt != "application/x-protobuf" {
		return fmt.Errorf("content-type %q: %w", contentType, errRemoteWriteFormat)
	}
	if p, ok := params["proto"]; ok && p != "prometheus.WriteRequest" {
		return fmt.Errorf("content-type %q: %w", contentType, errRemoteWriteFormat)
	}
	return nil
}

// reservedSeriesName returns the first metric name in a snappy-compressed
// remote-write 1.0 body for which reserved reports true, or "" when there is
// none. It reads only each series' __name__ label; samples, exemplars,
// histograms and metadata are skipped unread.
//
// Hand-decoded rather than via generated protobuf types: the api module has
// no protobuf dependency, and the three messages walked here are fixed by the
// remote-write 1.0 spec —
//
//	WriteRequest { repeated TimeSeries timeseries = 1; ... }
//	TimeSeries   { repeated Label labels = 1; ... }
//	Label        { string name = 1; string value = 2; }
func reservedSeriesName(compressed []byte, reserved func(string) bool) (string, error) {
	n, err := s2.DecodedLen(compressed)
	if err != nil {
		return "", fmt.Errorf("snappy: %v: %w", err, errRemoteWriteFormat)
	}
	if n > maxRemoteWriteBytes {
		return "", fmt.Errorf("decompressed size %d exceeds %d bytes: %w", n, maxRemoteWriteBytes, errRemoteWriteFormat)
	}
	body, err := s2.Decode(nil, compressed)
	if err != nil {
		return "", fmt.Errorf("snappy: %v: %w", err, errRemoteWriteFormat)
	}
	var found string
	err = walkFields(body, func(field uint64, series []byte) error {
		if field != 1 || found != "" {
			return nil
		}
		return walkFields(series, func(field uint64, label []byte) error {
			if field != 1 || found != "" {
				return nil
			}
			var name, value string
			if err := walkFields(label, func(field uint64, b []byte) error {
				switch field {
				case 1:
					name = string(b)
				case 2:
					value = string(b)
				}
				return nil
			}); err != nil {
				return err
			}
			if name == "__name__" && reserved(value) {
				found = value
			}
			return nil
		})
	})
	if err != nil {
		return "", fmt.Errorf("protobuf: %v: %w", err, errRemoteWriteFormat)
	}
	return found, nil
}

// walkFields calls fn with the field number and payload of every
// length-delimited field in the protobuf message b, and skips fields of every
// other wire type. Groups (deprecated, never used by remote-write) and
// truncated input are errors.
func walkFields(b []byte, fn func(field uint64, payload []byte) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return errors.New("bad field key")
		}
		b = b[n:]
		field, wire := key>>3, key&7
		switch wire {
		case 0: // varint
			_, n := binary.Uvarint(b)
			if n <= 0 {
				return errors.New("bad varint")
			}
			b = b[n:]
		case 1: // fixed64
			if len(b) < 8 {
				return errors.New("truncated fixed64")
			}
			b = b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			// No field can be longer than the whole decoded request, which
			// is capped; bounding l by that constant first keeps the int
			// conversion exact.
			if n <= 0 || l > maxRemoteWriteBytes {
				return errors.New("bad length")
			}
			end := n + int(l)
			if end > len(b) {
				return errors.New("bad length")
			}
			payload := b[n:end]
			b = b[end:]
			if err := fn(field, payload); err != nil {
				return err
			}
		case 5: // fixed32
			if len(b) < 4 {
				return errors.New("truncated fixed32")
			}
			b = b[4:]
		default:
			return fmt.Errorf("unsupported wire type %d", wire)
		}
	}
	return nil
}
