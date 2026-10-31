package obs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// runTeardown runs collector teardown for node "n1" against a fake agent that
// answers ack, and returns the stop command the agent received, the step's
// error and its log lines.
func runTeardown(t *testing.T, ack proto.AppStopAck) (proto.AppStopCmd, error, []string) {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	got := make(chan proto.AppStopCmd, 1)
	sub, err := nc.Subscribe(proto.AppStopSubject("n1"), func(m *nats.Msg) {
		var cmd proto.AppStopCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		b, _ := json.Marshal(ack)
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	spec, _ := json.Marshal(CollectorNodeSpec{NodeID: "n1"})
	var logs []string
	_, stepErr := collectorTeardown()(&jobs.StepCtx{
		Ctx: context.Background(), JobID: "j", Spec: spec, NATS: nc,
		Log: func(_, msg string) { logs = append(logs, msg) },
	})
	var cmd proto.AppStopCmd
	select {
	case cmd = <-got:
	default:
		t.Fatal("the agent received no stop command")
	}
	return cmd, stepErr, logs
}

// TC-783-18: collector teardown asks the agent to remove the collector's
// compose file.
func TestCollectorTeardown_TC783_18_AsksForComposeRemoval(t *testing.T) {
	cmd, err, logs := runTeardown(t, proto.AppStopAck{OK: true, Status: proto.AppStatusStopped})
	if err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if cmd.AppID != collectorAppID || !cmd.RemoveCompose || cmd.DeleteVolumes {
		t.Errorf("stop command = %+v; want appId %s, removeCompose true, deleteVolumes false", cmd, collectorAppID)
	}
	if !contains(logs, "observability collector stopped on n1") {
		t.Errorf("logs = %q; want the stopped line", logs)
	}
}

// TC-783-19: a stopped collector whose compose file the agent could not
// remove fails the teardown with the agent's detail, and the job never says
// the collector stopped.
func TestCollectorTeardown_TC783_19_FailsWhenComposeNotRemoved(t *testing.T) {
	const detail = "Stopped, but the app's compose file could not be removed: permission denied."
	_, err, logs := runTeardown(t, proto.AppStopAck{OK: false, Status: proto.AppStatusStopped, Detail: detail})
	if err == nil || err.Error() != detail {
		t.Fatalf("teardown err = %v; want %q", err, detail)
	}
	for _, l := range logs {
		if strings.Contains(l, "observability collector stopped") {
			t.Errorf("teardown logged %q after a failed removal", l)
		}
	}
}
