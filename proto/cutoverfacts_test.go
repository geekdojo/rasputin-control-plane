package proto

import (
	"encoding/json"
	"testing"
)

// The decoders answer (value, reported), and the distinction is the whole
// point: a cutover reads "did not report" as "not satisfied", never as a
// value.
func TestTokenSourceOf(t *testing.T) {
	cases := []struct {
		name         string
		meta         map[string]any
		want         string
		wantReported bool
	}{
		{"file", map[string]any{MetadataTokenSource: "file"}, TokenSourceFile, true},
		{"env", map[string]any{MetadataTokenSource: "env"}, TokenSourceEnv, true},
		{"none is a report", map[string]any{MetadataTokenSource: "none"}, TokenSourceNone, true},
		{"surrounding space is trimmed", map[string]any{MetadataTokenSource: " file "}, TokenSourceFile, true},
		{"absent", map[string]any{MetadataBusTLS: true}, "", false},
		{"nil metadata", nil, "", false},
		// An unknown value is not a report. Counting it would mean gating a
		// cutover on a string this api does not understand.
		{"unknown value", map[string]any{MetadataTokenSource: "somewhere-else"}, "", false},
		{"empty value", map[string]any{MetadataTokenSource: ""}, "", false},
		{"wrong type", map[string]any{MetadataTokenSource: 7}, "", false},
		{"bool where a string belongs", map[string]any{MetadataTokenSource: true}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reported := TokenSourceOf(tc.meta)
			if got != tc.want || reported != tc.wantReported {
				t.Errorf("TokenSourceOf = (%q, %v), want (%q, %v)", got, reported, tc.want, tc.wantReported)
			}
		})
	}
}

func TestHTTPSPinnedOf(t *testing.T) {
	cases := []struct {
		name               string
		meta               map[string]any
		want, wantReported bool
	}{
		{"true", map[string]any{MetadataHTTPSPinned: true}, true, true},
		// false is a REPORT, and the node that made it is one still to
		// migrate — not one that said nothing.
		{"false", map[string]any{MetadataHTTPSPinned: false}, false, true},
		{"absent", map[string]any{MetadataBusTLS: true}, false, false},
		{"nil metadata", nil, false, false},
		{"a string is not a report", map[string]any{MetadataHTTPSPinned: "true"}, false, false},
		{"a number is not a report", map[string]any{MetadataHTTPSPinned: 1}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reported := HTTPSPinnedOf(tc.meta)
			if got != tc.want || reported != tc.wantReported {
				t.Errorf("HTTPSPinnedOf = (%v, %v), want (%v, %v)", got, reported, tc.want, tc.wantReported)
			}
		})
	}
}

// Metadata crosses the bus as JSON and is stored as JSON on the node row, so
// the decoders have to read what comes back through a round trip — where a
// Go bool is still a bool but nothing else is guaranteed to keep its type.
func TestCutoverFactsSurviveAJSONRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tokenSource string
		pinned      bool
	}{
		{"a migrated node", TokenSourceFile, true},
		{"a node still on the variable", TokenSourceEnv, false},
		{"a node with no token", TokenSourceNone, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent := map[string]any{MetadataTokenSource: tc.tokenSource, MetadataHTTPSPinned: tc.pinned}
			b, err := json.Marshal(NodeRegisteredEvt{NodeID: "n1", Metadata: sent})
			if err != nil {
				t.Fatal(err)
			}
			var got NodeRegisteredEvt
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			src, reported := TokenSourceOf(got.Metadata)
			if !reported || src != tc.tokenSource {
				t.Errorf("after a round trip TokenSourceOf = (%q, %v), want (%q, true)", src, reported, tc.tokenSource)
			}
			pinned, reported := HTTPSPinnedOf(got.Metadata)
			if !reported || pinned != tc.pinned {
				t.Errorf("after a round trip HTTPSPinnedOf = (%v, %v), want (%v, true)", pinned, reported, tc.pinned)
			}
		})
	}
}
