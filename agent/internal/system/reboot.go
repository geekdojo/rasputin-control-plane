// Package system implements system-level agent operations (reboot, shutdown,
// time set, etc.). In v0 these are simulated — the agent doesn't actually
// restart its process. In production the equivalent commands are dispatched
// to the BMC for the adjacent slot.
package system

import (
	"encoding/json"
	"log"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

const (
	rebootDefaultDelay = 3
	rebootMaxDelay     = 30
)

// muted is the agent's simulated-offline flag. While true, the heartbeat
// loop in main.go skips publishing. The reboot handler sets it for the
// duration of the simulated downtime.
var muted atomic.Bool

// IsMuted reports whether the agent is currently simulating offline state.
// Read by the heartbeat loop.
func IsMuted() bool { return muted.Load() }

// RegisterRebootHandler subscribes to rasputin.node.<nodeID>.cmd.system.reboot.
// On a reboot command it:
//  1. Replies synchronously so the saga can advance.
//  2. Publishes a `rebooting` event.
//  3. Mutes heartbeats for DelaySeconds.
//  4. Calls reregister so the api sees a fresh NodeRegisteredEvt.
func RegisterRebootHandler(nc *nats.Conn, nodeID string, reregister func(*nats.Conn)) (*nats.Subscription, error) {
	subj := proto.NodeCmdSubject(nodeID, "system.reboot")
	return nc.Subscribe(subj, func(m *nats.Msg) {
		var cmd proto.SystemRebootCmd
		_ = json.Unmarshal(m.Data, &cmd)
		delay := cmd.DelaySeconds
		if delay <= 0 || delay > rebootMaxDelay {
			delay = rebootDefaultDelay
		}
		ack, _ := json.Marshal(proto.SystemRebootAck{OK: true, DelaySeconds: delay})
		if err := m.Respond(ack); err != nil {
			log.Printf("rasputin-agent: system.reboot: respond: %v", err)
			return
		}
		go simulateReboot(nc, nodeID, delay, reregister)
	})
}

func simulateReboot(nc *nats.Conn, nodeID string, delay int, reregister func(*nats.Conn)) {
	log.Printf("rasputin-agent: simulating reboot (delay=%ds)", delay)

	ev, _ := json.Marshal(proto.SystemRebootingEvt{
		NodeID:       nodeID,
		DelaySeconds: delay,
		Ts:           time.Now().UTC(),
	})
	if err := nc.Publish(proto.NodeEvtSubject(nodeID, "rebooting"), ev); err != nil {
		log.Printf("rasputin-agent: system.reboot: publish rebooting: %v", err)
	}

	muted.Store(true)
	time.Sleep(time.Duration(delay) * time.Second)
	muted.Store(false)

	log.Printf("rasputin-agent: simulated reboot complete; re-registering")
	if reregister != nil {
		reregister(nc)
	}
}
