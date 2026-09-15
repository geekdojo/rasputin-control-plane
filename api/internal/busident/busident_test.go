package busident

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestNodeIDFromSubject(t *testing.T) {
	cases := []struct {
		subject string
		wantID  string
		wantOK  bool
	}{
		{"rasputin.node.cp-1.heartbeat", "cp-1", true},
		{"rasputin.node.fw-x.evt.registered", "fw-x", true},
		{"rasputin.node.x.cmd.something.deep", "x", true},
		{"rasputin.node.alpha.metrics", "alpha", true},
		// Negative cases:
		{"", "", false},
		{"rasputin.node", "", false},
		{"rasputin.node.x", "", false}, // only 3 tokens — needs at least 4.
		{"rasputin.node.x.", "", false},
		{"rasputin.node..heartbeat", "", false},
		{"other.node.x.heartbeat", "", false},
		{"rasputin.other.x.heartbeat", "", false},
		{"rasputin.node.*.heartbeat", "", false},
		{"rasputin.node.>.heartbeat", "", false},
		{"rasputin.node.Alpha.heartbeat", "", false},
		{"rasputin.node.-alpha.heartbeat", "", false},
		{"rasputin.node.al pha.heartbeat", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			id, ok := NodeIDFromSubject(tc.subject)
			if ok != tc.wantOK || id != tc.wantID {
				t.Errorf("NodeIDFromSubject(%q) = (%q, %v), want (%q, %v)",
					tc.subject, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

// decodeCase is shared by the three decoder tables: payloadID is the nodeId
// written into the JSON payload, and wantErr is nil when the decode should
// succeed with NodeID == wantID.
type decodeCase struct {
	name      string
	subject   string
	payloadID string
	raw       []byte // when set, used instead of a marshalled payload
	wantID    string
	wantErr   error
}

func commonCases(subjectFor func(id string) string) []decodeCase {
	return []decodeCase{
		{name: "matching id", subject: subjectFor("alpha"), payloadID: "alpha", wantID: "alpha"},
		{name: "empty id takes subject", subject: subjectFor("alpha"), payloadID: "", wantID: "alpha"},
		{name: "mismatched id", subject: subjectFor("alpha"), payloadID: "beta", wantErr: ErrNodeIDMismatch},
		{name: "mismatched case", subject: subjectFor("alpha"), payloadID: "Alpha", wantErr: ErrNodeIDMismatch},
		{name: "mismatched whitespace", subject: subjectFor("alpha"), payloadID: "alpha ", wantErr: ErrNodeIDMismatch},
		{name: "malformed subject", subject: "rasputin.node", payloadID: "alpha", wantErr: ErrBadSubject},
		{name: "wrong root", subject: "other.node.alpha.metrics", payloadID: "alpha", wantErr: ErrBadSubject},
		{name: "wildcard node token", subject: subjectFor("*"), payloadID: "", wantErr: ErrBadSubject},
		{name: "invalid node token", subject: subjectFor("Alpha"), payloadID: "Alpha", wantErr: ErrBadSubject},
		{name: "extra tokens before the event", subject: "rasputin.node.alpha.beta." + subjectFor("x")[len("rasputin.node.x."):], payloadID: "", wantErr: ErrBadSubject},
		{name: "bad json", subject: subjectFor("alpha"), raw: []byte("{"), wantErr: errAnyDecode},
	}
}

// errAnyDecode marks a case that must fail with a JSON decode error (which is
// neither sentinel).
var errAnyDecode = errors.New("any decode error")

func checkDecode(t *testing.T, tc decodeCase, gotID string, err error) {
	t.Helper()
	switch {
	case tc.wantErr == nil:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotID != tc.wantID {
			t.Fatalf("NodeID = %q, want %q", gotID, tc.wantID)
		}
	case tc.wantErr == errAnyDecode:
		if err == nil || errors.Is(err, ErrBadSubject) || errors.Is(err, ErrNodeIDMismatch) {
			t.Fatalf("err = %v, want a decode error", err)
		}
	default:
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("err = %v, want %v", err, tc.wantErr)
		}
		if gotID != "" {
			t.Fatalf("NodeID = %q on error, want empty", gotID)
		}
	}
}

func TestDecodeRegistered(t *testing.T) {
	cases := append(commonCases(proto.NodeRegisteredSubject),
		decodeCase{name: "trailing token", subject: proto.NodeRegisteredSubject("alpha") + ".x", payloadID: "alpha", wantErr: ErrBadSubject},
		decodeCase{name: "other event kind", subject: proto.NodeHeartbeatSubject("alpha"), payloadID: "alpha", wantErr: ErrBadSubject},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.raw
			if data == nil {
				data, _ = json.Marshal(proto.NodeRegisteredEvt{NodeID: tc.payloadID, Role: proto.RoleCompute, Hostname: "h"})
			}
			ev, err := DecodeRegistered(tc.subject, data)
			checkDecode(t, tc, ev.NodeID, err)
			if err == nil && (ev.Role != proto.RoleCompute || ev.Hostname != "h") {
				t.Fatalf("payload fields not decoded: %+v", ev)
			}
		})
	}
}

func TestDecodeIDSAlert(t *testing.T) {
	cases := append(commonCases(proto.IDSAlertSubject),
		decodeCase{name: "other ids event", subject: proto.NodeEvtSubject("alpha", "ids.summary"), payloadID: "alpha", wantID: "alpha"},
		decodeCase{name: "ids with no event token", subject: proto.NodeEvtSubject("alpha", "ids."), payloadID: "alpha", wantErr: ErrBadSubject},
		decodeCase{name: "not an ids event", subject: proto.NodeRegisteredSubject("alpha"), payloadID: "alpha", wantErr: ErrBadSubject},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.raw
			if data == nil {
				data, _ = json.Marshal(proto.IDSAlertEvt{NodeID: tc.payloadID, SID: 7})
			}
			ev, err := DecodeIDSAlert(tc.subject, data)
			checkDecode(t, tc, ev.NodeID, err)
			if err == nil && ev.SID != 7 {
				t.Fatalf("payload fields not decoded: %+v", ev)
			}
		})
	}
}

func TestDecodeMetrics(t *testing.T) {
	cases := append(commonCases(proto.NodeMetricsSubject),
		decodeCase{name: "trailing token", subject: proto.NodeMetricsSubject("alpha") + ".x", payloadID: "alpha", wantErr: ErrBadSubject},
		decodeCase{name: "other event kind", subject: proto.NodeHeartbeatSubject("alpha"), payloadID: "alpha", wantErr: ErrBadSubject},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.raw
			if data == nil {
				data, _ = json.Marshal(proto.MetricsEvt{NodeID: tc.payloadID, Metrics: map[string]float64{"m": 1}})
			}
			ev, err := DecodeMetrics(tc.subject, data)
			checkDecode(t, tc, ev.NodeID, err)
			if err == nil && ev.Metrics["m"] != 1 {
				t.Fatalf("payload fields not decoded: %+v", ev)
			}
		})
	}
}
