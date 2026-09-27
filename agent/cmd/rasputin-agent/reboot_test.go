package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The agent's one Rebooter simulates only when the dev mock was asked for by
// name AND the image is a dev build. Nothing else — least of all a choice the
// agent could not make sense of — may produce a node that fakes its reboots
// (geekdojo/geekdojo-brain#616). That no autodetect ever answers "mock" is
// TestNoAutodetectEverYieldsMock's.
func TestNewRebooter_SimulatesOnlyForTheExplicitMockOnADevImage(t *testing.T) {
	for _, tc := range []struct {
		choice, image string
		want          bool
	}{
		{"mock", "", true},
		{"mock", "2026.09.4-dev.7", true},
		{"mock", "2026.09.4", false},
		{"rauc", "", false},
		{"rauc", "2026.09.4", false},
		{"openwrt-ab", "2026.09.4-dev.7", false},
		{backendUnavailable, "", false},
		{"", "", false},
		{"Mock", "", false},
		{"mock ", "", false},
		{"simulate", "", false},
	} {
		rb := newRebooter("n", nil, tc.choice, tc.image, nil)
		if got := rb.Simulated(); got != tc.want {
			t.Errorf("choice=%q image=%q: simulated=%v, want %v", tc.choice, tc.image, got, tc.want)
		}
	}
}

// diag.ping reports which boot is answering: it is how the control plane
// verifies a reboot on a node whatever its role or update backend.
func TestHandlePing_ReportsTheBootIdentity(t *testing.T) {
	t.Setenv("RASPUTIN_BOOT_ID", "boot-under-test")
	nc := testBus(t)
	subj := proto.NodeCmdSubject("n", "diag.ping")
	sub, err := nc.Subscribe(subj, func(m *nats.Msg) { handlePing("n", m) })
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	cmd, _ := json.Marshal(proto.DiagPingCmd{JobID: "j"})
	msg, err := nc.Request(subj, cmd, 5*time.Second)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	var pong proto.DiagPongEvt
	if err := json.Unmarshal(msg.Data, &pong); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pong.BootID != "boot-under-test" {
		t.Errorf("bootId = %q, want boot-under-test", pong.BootID)
	}
}
