package tailscale

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers subscribes to mesh.enroll, mesh.leave, mesh.status for
// nodeID and dispatches to the supplied Backend. Returns the subscriptions
// so the caller can Unsubscribe them on shutdown.
//
// onEnrolled hooks run after every enroll that succeeded, once the ack has
// gone back. main passes its re-register closure: the registration event is
// what carries the CA fingerprint this node trusts (proto
// MetadataMeshCAFingerprint), and it otherwise fires only on a NATS
// (re)connect — so without this the api would keep seeing the OLD
// fingerprint after a re-delivery, until the next reconnect, and keep
// re-delivering to a node that had already converged.
func RegisterHandlers(nc *nats.Conn, nodeID string, backend Backend, onEnrolled ...func()) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 3)

	enrollSub, err := nc.Subscribe(proto.MeshEnrollSubject(nodeID), func(m *nats.Msg) {
		if handleEnroll(backend, m) {
			for _, fn := range onEnrolled {
				if fn != nil {
					fn()
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	subs = append(subs, enrollSub)
	log.Printf("rasputin-agent: subscribed to %s", proto.MeshEnrollSubject(nodeID))

	leaveSub, err := nc.Subscribe(proto.MeshLeaveSubject(nodeID), func(m *nats.Msg) {
		handleLeave(backend, m)
	})
	if err != nil {
		return subs, err
	}
	subs = append(subs, leaveSub)
	log.Printf("rasputin-agent: subscribed to %s", proto.MeshLeaveSubject(nodeID))

	statusSub, err := nc.Subscribe(proto.MeshStatusSubject(nodeID), func(m *nats.Msg) {
		handleStatus(backend, m)
	})
	if err != nil {
		return subs, err
	}
	subs = append(subs, statusSub)
	log.Printf("rasputin-agent: subscribed to %s", proto.MeshStatusSubject(nodeID))

	return subs, nil
}

// enrollBudget is how long one mesh.enroll may run before the agent answers:
// the mesh CA install, the tailscaled restart and `tailscale up` together.
// A NATS request carries no deadline of its own, so this is the ONLY clock
// on the agent side — the one that killed `tailscale up` on e3bench-compute1
// when it was a hand-typed 30 s (geekdojo/geekdojo-brain#402). A var only so
// the deadline path can be driven in tests without waiting the budget out.
var enrollBudget = proto.MeshEnrollWork

// handleEnroll answers one mesh.enroll and reports whether the enroll
// succeeded (so the caller can fire its post-enroll hooks).
func handleEnroll(backend Backend, m *nats.Msg) bool {
	var cmd proto.MeshEnrollCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		bus.Respond(m, proto.MeshEnrollAck{OK: false, Detail: "bad cmd: " + err.Error()})
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), enrollBudget)
	defer cancel()
	st, err := backend.Enroll(ctx, EnrollInput{
		LoginServer:     cmd.LoginServer,
		AuthKey:         cmd.AuthKey,
		Hostname:        cmd.Hostname,
		AdvertiseRoutes: cmd.AdvertiseRoutes,
		AcceptDNS:       cmd.AcceptDNS,
		AcceptRoutes:    cmd.AcceptRoutes,
		MeshCAPEM:       cmd.MeshCAPEM,
	})
	if err != nil {
		bus.Respond(m, proto.MeshEnrollAck{OK: false, Backend: backend.Name(), Detail: err.Error()})
		log.Printf("rasputin-agent: mesh.enroll: %v", err)
		return false
	}
	bus.Respond(m, proto.MeshEnrollAck{
		OK:               true,
		TailnetID:        st.TailnetID,
		TailnetIP:        st.TailnetIP,
		Hostname:         st.Hostname,
		Routes:           st.Routes,
		Backend:          backend.Name(),
		TrustFingerprint: backend.TrustFingerprint(),
	})
	return true
}

func handleLeave(backend Backend, m *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := backend.Leave(ctx); err != nil {
		bus.Respond(m, proto.MeshLeaveAck{OK: false, Detail: err.Error()})
		log.Printf("rasputin-agent: mesh.leave: %v", err)
		return
	}
	bus.Respond(m, proto.MeshLeaveAck{OK: true})
}

func handleStatus(backend Backend, m *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := backend.Status(ctx)
	if err != nil {
		bus.Respond(m, proto.MeshStatusAck{OK: false, Backend: backend.Name(), Detail: err.Error()})
		return
	}
	bus.Respond(m, proto.MeshStatusAck{
		OK:        true,
		Enrolled:  st.Enrolled,
		TailnetID: st.TailnetID,
		TailnetIP: st.TailnetIP,
		Hostname:  st.Hostname,
		Routes:    st.Routes,
		PeerCount: st.PeerCount,
		Backend:   backend.Name(),
	})
}
