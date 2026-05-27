package tailscale

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers subscribes to mesh.enroll, mesh.leave, mesh.status for
// nodeID and dispatches to the supplied Backend. Returns the subscriptions
// so the caller can Unsubscribe them on shutdown.
func RegisterHandlers(nc *nats.Conn, nodeID string, backend Backend) ([]*nats.Subscription, error) {
	subs := make([]*nats.Subscription, 0, 3)

	enrollSub, err := nc.Subscribe(proto.MeshEnrollSubject(nodeID), func(m *nats.Msg) {
		handleEnroll(backend, m)
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

func handleEnroll(backend Backend, m *nats.Msg) {
	var cmd proto.MeshEnrollCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.MeshEnrollAck{OK: false, Detail: "bad cmd: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := backend.Enroll(ctx, EnrollInput{
		LoginServer:     cmd.LoginServer,
		AuthKey:         cmd.AuthKey,
		Hostname:        cmd.Hostname,
		AdvertiseRoutes: cmd.AdvertiseRoutes,
		AcceptDNS:       cmd.AcceptDNS,
		AcceptRoutes:    cmd.AcceptRoutes,
	})
	if err != nil {
		respond(m, proto.MeshEnrollAck{OK: false, Backend: backend.Name(), Detail: err.Error()})
		log.Printf("rasputin-agent: mesh.enroll: %v", err)
		return
	}
	respond(m, proto.MeshEnrollAck{
		OK:        true,
		TailnetID: st.TailnetID,
		TailnetIP: st.TailnetIP,
		Hostname:  st.Hostname,
		Routes:    st.Routes,
		Backend:   backend.Name(),
	})
}

func handleLeave(backend Backend, m *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := backend.Leave(ctx); err != nil {
		respond(m, proto.MeshLeaveAck{OK: false, Detail: err.Error()})
		log.Printf("rasputin-agent: mesh.leave: %v", err)
		return
	}
	respond(m, proto.MeshLeaveAck{OK: true})
}

func handleStatus(backend Backend, m *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := backend.Status(ctx)
	if err != nil {
		respond(m, proto.MeshStatusAck{OK: false, Backend: backend.Name(), Detail: err.Error()})
		return
	}
	respond(m, proto.MeshStatusAck{
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

func respond(m *nats.Msg, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		log.Printf("rasputin-agent: marshal response: %v", err)
		return
	}
	if err := m.Respond(payload); err != nil {
		log.Printf("rasputin-agent: respond: %v", err)
	}
}
