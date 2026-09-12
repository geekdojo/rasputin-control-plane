package apps

import (
	"encoding/json"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// fakeVolumeCheckAgent answers docker.volumes.check on node n, reporting
// dropped as the volumes the compose it was sent would drop, and hands every
// command it received to the test.
func fakeVolumeCheckAgent(t *testing.T, nc *nats.Conn, dropped ...proto.AppDroppedVolume) <-chan proto.AppVolumesCheckCmd {
	t.Helper()
	got := make(chan proto.AppVolumesCheckCmd, 8)
	if dropped == nil {
		dropped = []proto.AppDroppedVolume{}
	}
	sub, err := nc.Subscribe(proto.AppVolumesCheckSubject("n"), func(m *nats.Msg) {
		var cmd proto.AppVolumesCheckCmd
		_ = json.Unmarshal(m.Data, &cmd)
		select {
		case got <- cmd:
		default:
		}
		b, _ := json.Marshal(proto.AppVolumesCheckAck{OK: true, Declared: []string{}, Dropped: dropped})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got
}
