package nodetrust

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

var trustOriginalCA = []byte("-----BEGIN CERTIFICATE-----\nORIGINAL\n-----END CERTIFICATE-----\n")

func TestStateFor(t *testing.T) {
	want := proto.TrustFingerprint(trustOriginalCA)
	cases := []struct {
		name     string
		want     string
		node     *proto.Node
		state    NodeTrustState
		predates bool
	}{
		{"current", want, &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataTrustFingerprint: want}}, TrustCurrent, false},
		{"stale", want, &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataTrustFingerprint: "other"}}, TrustStale, false},
		{"reload-pending is stale", want, &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataTrustFingerprint: proto.TrustFingerprintReloadPending}}, TrustStale, false},
		{"none is stale", want, &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataTrustFingerprint: proto.TrustFingerprintNone}}, TrustStale, false},
		{"unreported, new agent", want, &proto.Node{ID: "a", AgentVersion: "2026.09.1-dev.150"}, TrustUnreported, false},
		{"unreported, agent predates the field", want, &proto.Node{ID: "a", AgentVersion: "2026.08.4-dev.130"}, TrustUnreported, true},
		{"unreported, unparseable version", want, &proto.Node{ID: "a", AgentVersion: "dev"}, TrustUnreported, false},
		{"no CA shipped", "", &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataTrustFingerprint: "other"}}, TrustCurrent, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := StateFor(tc.want, tc.node)
			if got.State != tc.state || got.AgentPredatesField != tc.predates {
				t.Errorf("got %+v, want state=%s predates=%v", got, tc.state, tc.predates)
			}
		})
	}
}
